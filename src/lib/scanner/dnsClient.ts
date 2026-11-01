import { Resolver } from "node:dns/promises";
import { randomInt } from "node:crypto";
import dgram from "node:dgram";
import net from "node:net";

/**
 * Small DNS abstraction used by the email and DNS checks.
 * It's an interface so tests can inject a fake resolver - no real DNS needed.
 */
export interface DnsClient {
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<{ exchange: string; priority: number }[]>;
  caa(name: string): Promise<{ tag: string; value: string; critical: number }[]>;
  /**
   * true = signed (DS record at the parent), false = not signed,
   * "broken" = signed but fails validation, null = couldn't determine.
   */
  dnssec(name: string): Promise<boolean | "broken" | null>;
}

const NOT_FOUND = new Set(["ENODATA", "ENOTFOUND", "ENOTIMP", "EREFUSED", "ESERVFAIL", "ECONNREFUSED", "ETIMEOUT", "ECANCELLED"]);

/** Turn "no such record" errors into an empty answer; rethrow anything unexpected. */
async function orEmpty<T>(p: Promise<T[]>): Promise<T[]> {
  try {
    return await p;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? "";
    if (NOT_FOUND.has(code)) return [];
    throw err;
  }
}

export function createDnsClient(): DnsClient {
  const resolver = new Resolver({ timeout: 3000, tries: 2 });

  return {
    txt: async (name) => (await orEmpty(resolver.resolveTxt(name))).map((chunks) => chunks.join("")),
    mx: (name) => orEmpty(resolver.resolveMx(name)),
    caa: async (name) =>
      (await orEmpty(resolver.resolveCaa(name))).map((r) => {
        const rec = r as unknown as Record<string, string | number>;
        const tag = ["issue", "issuewild", "iodef"].find((t) => t in rec) ?? "unknown";
        return { tag, value: String(rec[tag] ?? ""), critical: Number(rec.critical ?? 0) };
      }),
    // Node's resolver has no DS type, so this sends a raw query to the same system resolver
    // (no third-party DNS-over-HTTPS service involved).
    dnssec: (name) => dnssecStatus(name, resolver.getServers()),
  };
}

/**
 * Signed zones publish a DS record at their parent. When the zone's own signatures are wrong, a
 * validating resolver answers SERVFAIL for names inside it but succeeds with Checking Disabled.
 * (A non-validating resolver never shows that difference, so "broken" is only reported when seen.)
 */
export async function dnssecStatus(
  name: string,
  servers: string[],
  query: (server: string, packet: Buffer) => Promise<Buffer> = udpQuery,
): Promise<boolean | "broken" | null> {
  const server = servers.map(stripPort).find((s) => net.isIP(s));
  if (!server) return null;
  const ask = async (type: number, checkingDisabled = false) =>
    parseDnsResponse(await query(server, encodeDnsQuery(name, type, { checkingDisabled })));
  /** SERVFAIL that goes away with Checking Disabled = a validation failure. */
  const failsValidation = async (type: number) => (await ask(type, true)).rcode === 0;
  try {
    const ds = await ask(DS);
    if (ds.rcode === RCODE_SERVFAIL) return (await failsValidation(DS)) ? "broken" : null;
    if (ds.rcode !== 0) return null;
    if (!ds.answerTypes.includes(DS)) return false;
    const soa = await ask(SOA);
    if (soa.rcode === RCODE_SERVFAIL) return (await failsValidation(SOA)) ? "broken" : true;
    return true;
  } catch {
    return null;
  }
}

const DS = 43;
const SOA = 6;
const RCODE_SERVFAIL = 2;

function stripPort(server: string): string {
  const v6 = server.match(/^\[(.+)\](?::\d+)?$/);
  if (v6) return v6[1];
  return net.isIPv6(server) ? server : server.replace(/:\d+$/, "");
}

/** A standard recursive query with an EDNS0 OPT record asking for DNSSEC data (DO bit). */
export function encodeDnsQuery(name: string, type: number, opts: { checkingDisabled?: boolean; id?: number } = {}): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(opts.id ?? randomInt(0, 0x10000), 0);
  // RD (recursion desired) + AD (ask for the authenticated-data bit) [+ CD]
  header.writeUInt16BE(0x0100 | 0x0020 | (opts.checkingDisabled ? 0x0010 : 0), 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(1, 10); // ARCOUNT (the OPT record)
  const labels = name.replace(/\.$/, "").split(".").filter(Boolean);
  const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "ascii")])), Buffer.from([0])]);
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(1, 2); // IN
  // OPT: root name, type 41, UDP size 1232, extended rcode/version 0, DO flag, no options.
  const opt = Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
  return Buffer.concat([header, qname, question, opt]);
}

export interface DnsResponse {
  id: number;
  rcode: number;
  authenticated: boolean;
  answerTypes: number[];
}

export function parseDnsResponse(buf: Buffer): DnsResponse {
  if (buf.length < 12) throw new Error("DNS response too short");
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let offset = 12;
  const skipName = () => {
    for (;;) {
      const len = buf[offset];
      if (len === undefined) throw new Error("Truncated DNS name");
      if ((len & 0xc0) === 0xc0) { offset += 2; return; } // compression pointer ends the name
      offset += 1;
      if (len === 0) return;
      offset += len;
    }
  };
  for (let i = 0; i < qd; i++) { skipName(); offset += 4; }
  const answerTypes: number[] = [];
  for (let i = 0; i < an; i++) {
    skipName();
    if (offset + 10 > buf.length) throw new Error("Truncated DNS answer");
    answerTypes.push(buf.readUInt16BE(offset));
    offset += 10 + buf.readUInt16BE(offset + 8);
  }
  return { id: buf.readUInt16BE(0), rcode: flags & 0x000f, authenticated: (flags & 0x0020) !== 0, answerTypes };
}

function udpQuery(server: string, packet: Buffer, timeoutMs = 3000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIPv6(server) ? "udp6" : "udp4");
    const id = packet.readUInt16BE(0);
    const timer = setTimeout(() => done(new Error("DNS query timed out")), timeoutMs);
    const done = (err: Error | null, msg?: Buffer) => {
      clearTimeout(timer);
      socket.close();
      if (err) reject(err);
      else resolve(msg!);
    };
    socket.on("error", (err) => done(err));
    // Ignore stray packets: only the answer to this query's id counts.
    socket.on("message", (msg, rinfo) => {
      if (rinfo.address === server && msg.length >= 2 && msg.readUInt16BE(0) === id) done(null, msg);
    });
    socket.send(packet, 53, server);
  });
}

/** Common two-level public suffixes (co.uk, edu.so, com.au…). Not a full Public Suffix List, but covers most cases. */
const SECOND_LEVEL = /^(co|com|net|org|edu|gov|ac|or|ne|go|mil|sch|ltd|plc|nic)\.[a-z]{2}$/;

/** Best-effort "organisational domain": shop.example.co.uk -> example.co.uk */
export function orgDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return SECOND_LEVEL.test(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

/** host and its parents, down to (and including) the organisational domain. */
export function domainChain(host: string): string[] {
  const org = orgDomain(host);
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  const chain: string[] = [];
  for (let i = 0; i < labels.length; i++) {
    const name = labels.slice(i).join(".");
    chain.push(name);
    if (name === org) break;
  }
  return chain;
}
