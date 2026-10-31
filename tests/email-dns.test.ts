import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeSpf, checkDmarc, checkSpf, countSpfLookups, runEmailChecks } from "../src/lib/scanner/checks/email";
import { runDnsChecks } from "../src/lib/scanner/checks/dns";
import { dnssecStatus, domainChain, encodeDnsQuery, orgDomain, parseDnsResponse, type DnsClient } from "../src/lib/scanner/dnsClient";

/** In-memory fake DNS: zone maps record name -> records. */
function fakeDns(zone: {
  txt?: Record<string, string[]>;
  mx?: Record<string, { exchange: string; priority: number }[]>;
  caa?: Record<string, { tag: string; value: string; critical: number }[]>;
  dnssec?: Record<string, boolean | "broken" | null>;
}): DnsClient {
  return {
    txt: async (n) => zone.txt?.[n] ?? [],
    mx: async (n) => zone.mx?.[n] ?? [],
    caa: async (n) => zone.caa?.[n] ?? [],
    dnssec: async (n) => (zone.dnssec && n in zone.dnssec ? zone.dnssec[n] : false),
  };
}

test("orgDomain handles subdomains and two-level suffixes", () => {
  assert.equal(orgDomain("shop.example.com"), "example.com");
  assert.equal(orgDomain("www.nugaaluniversity.edu.so"), "nugaaluniversity.edu.so");
  assert.equal(orgDomain("a.b.example.co.uk"), "example.co.uk");
  assert.deepEqual(domainChain("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"]);
});

test("SPF analysis", () => {
  assert.deepEqual(analyzeSpf("v=spf1 include:_spf.google.com mx -all"), { qualifier: "-", lookups: 2, hasRedirect: false });
  assert.equal(checkSpf("x.com", ["v=spf1 +all"], true).severity, "high");
  assert.equal(checkSpf("x.com", ["v=spf1 include:a.com ?all"], true).status, "warn");
  assert.equal(checkSpf("x.com", ["v=spf1 -all", "v=spf1 ~all"], true).status, "fail", "duplicate SPF = PermError");
  assert.equal(checkSpf("x.com", ["v=spf1 include:_spf.google.com ~all"], true).status, "pass");
  assert.equal(checkSpf("x.com", ["v=spf1 redirect=_spf.x.com"], true).status, "pass");
  assert.equal(checkSpf("x.com", [], true).status, "fail", "missing SPF on a mail domain");
  assert.equal(checkSpf("x.com", [], false).status, "info", "missing SPF on a non-mail domain is advisory");
  const many = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.com`).join(" ") + " -all";
  assert.equal(checkSpf("x.com", [many], true).status, "warn");
});

test("DMARC policies", () => {
  assert.equal(checkDmarc(null, "x.com", true).status, "fail");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=none; rua=mailto:a@x.com" }, "x.com", true).status, "warn");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject" }, "x.com", true).status, "pass");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject; pct=20" }, "x.com", true).status, "warn");
  // Subdomain inherits the parent's sp= policy
  const sub = checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject; sp=none" }, "mail.x.com", true);
  assert.equal(sub.status, "warn");
  assert.match(sub.description, /inherited/);
});

test("email checks end-to-end on a well-configured domain", async () => {
  const dns = fakeDns({
    txt: {
      "example.com": ["v=spf1 include:_spf.google.com -all", "google-site-verification=abc"],
      "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
      "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
      "s1._domainkey.example.com": ["v=DKIM1; p="], // revoked key - must not count
    },
    mx: { "example.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] },
  });
  const findings = await runEmailChecks("www.example.com", dns);
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  assert.equal(byId.spf.status, "pass");
  assert.equal(byId.dmarc.status, "pass");
  assert.equal(byId.dkim.status, "pass");
  assert.match(byId.dkim.description, /google/);
  assert.doesNotMatch(byId.dkim.description, /s1/);
});

test("email checks on an unprotected mail domain", async () => {
  const dns = fakeDns({ mx: { "victim.org": [{ exchange: "mx.victim.org", priority: 10 }] } });
  const ids = (await runEmailChecks("victim.org", dns)).filter((f) => f.status === "fail").map((f) => f.id);
  assert.deepEqual(ids.sort(), ["dmarc", "spf"]);
});

test("CAA is inherited from the parent domain", async () => {
  const dns = fakeDns({ caa: { "example.com": [{ tag: "issue", value: "letsencrypt.org", critical: 0 }] } });
  const [caa] = await runDnsChecks("app.example.com", dns);
  assert.equal(caa.status, "pass");
  assert.match(caa.description, /letsencrypt\.org.*inherited from example\.com/);
  const [none] = await runDnsChecks("nocaa.com", fakeDns({}));
  assert.equal(none.status, "warn");
});

test("DNSSEC: signed, unsigned and unknown", async () => {
  const [, signed] = await runDnsChecks("www.secure.com", fakeDns({ dnssec: { "secure.com": true } }));
  assert.equal(signed.status, "pass");
  const [, unsigned] = await runDnsChecks("plain.com", fakeDns({}));
  assert.equal(unsigned.status, "warn");
  const [, unknown] = await runDnsChecks("x.com", fakeDns({ dnssec: { "x.com": null } }));
  assert.equal(unknown.status, "info");
  const [, broken] = await runDnsChecks("x.com", fakeDns({ dnssec: { "x.com": "broken" } }));
  assert.equal(broken.status, "fail");
  assert.equal(broken.severity, "high");
});

test("CAA with only an iodef record restricts nothing", async () => {
  const [caa] = await runDnsChecks("x.com", fakeDns({ caa: { "x.com": [{ tag: "iodef", value: "mailto:sec@x.com", critical: 0 }] } }));
  assert.equal(caa.status, "warn");
  assert.match(caa.description, /iodef/);
});

test("SPF: lookups inside includes count towards the limit of 10", async () => {
  const dns = fakeDns({ txt: {
    "x.com": ["v=spf1 include:a.com include:b.com -all"],
    "a.com": ["v=spf1 include:c.com mx a ip4:1.2.3.4 -all"],
    "b.com": ["v=spf1 " + Array.from({ length: 6 }, (_, i) => `exists:e${i}.b.com`).join(" ") + " -all"],
    "c.com": ["v=spf1 include:a.com -all"], // loops back to a.com; must not recurse forever
  } });
  const total = await countSpfLookups("v=spf1 include:a.com include:b.com -all", dns);
  assert.ok(total > 10, `counted ${total}`);
  const spf = (await runEmailChecks("x.com", dns)).find((f) => f.id === "spf")!;
  assert.equal(spf.status, "warn");
  assert.match(spf.description, /includes are followed/);
});

test("DMARC: duplicate records, invalid policy and sp=none", () => {
  const dup = checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject", count: 2 }, "x.com", true);
  assert.equal(dup.status, "fail");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=block" }, "x.com", true).status, "fail");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; rua=mailto:a@x.com" }, "x.com", true).status, "fail");
  const sp = checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject; sp=none" }, "x.com", true);
  assert.equal(sp.status, "warn");
  assert.match(sp.description, /subdomain/);
});

/** Answers a query the way a resolver would: same id and question, given rcode, `answers` records of `type`. */
function dnsAnswer(query: Buffer, rcode: number, answerType?: number): Buffer {
  const head = Buffer.from(query.subarray(0, query.length - 11)); // drop the OPT record
  head.writeUInt16BE(0x8180 | rcode, 2);
  head.writeUInt16BE(answerType ? 1 : 0, 6);
  head.writeUInt16BE(0, 10);
  if (!answerType) return head;
  const rr = Buffer.from([0xc0, 0x0c, 0, answerType, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
  return Buffer.concat([head, rr]);
}

test("DNS wire format: query flags and response parsing", () => {
  const q = encodeDnsQuery("example.com", 43, { id: 0x1234, checkingDisabled: true });
  assert.equal(q.readUInt16BE(0), 0x1234);
  assert.equal(q.readUInt16BE(2) & 0x0010, 0x0010, "CD bit set");
  const parsed = parseDnsResponse(dnsAnswer(q, 0, 43));
  assert.deepEqual(parsed, { id: 0x1234, rcode: 0, authenticated: false, answerTypes: [43] });
});

test("DNSSEC status from raw resolver answers", async () => {
  /** A resolver whose answer depends on the record type and the CD bit. */
  const resolver = (answer: (type: number, cd: boolean) => [number, number?]) => async (_server: string, packet: Buffer) => {
    const qnameEnd = packet.indexOf(0, 12);
    const type = packet.readUInt16BE(qnameEnd + 1);
    const cd = (packet.readUInt16BE(2) & 0x0010) !== 0;
    const [rcode, answerType] = answer(type, cd);
    return dnsAnswer(packet, rcode, answerType);
  };
  const servers = ["127.0.0.53"];
  assert.equal(await dnssecStatus("x.com", servers, resolver((t) => [0, t === 43 ? 43 : 6])), true);
  assert.equal(await dnssecStatus("x.com", servers, resolver(() => [0])), false);
  // DS exists but the zone's own signatures fail: SERVFAIL, unless checking is disabled.
  assert.equal(await dnssecStatus("x.com", servers, resolver((t, cd) => (t === 43 ? [0, 43] : cd ? [0, 6] : [2]))), "broken");
  // SERVFAIL either way is an outage, not a DNSSEC verdict.
  assert.equal(await dnssecStatus("x.com", servers, resolver(() => [2])), null);
  assert.equal(await dnssecStatus("x.com", [], resolver(() => [0])), null, "no resolver configured");
});
