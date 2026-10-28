import { Resolver } from "node:dns/promises";

/**
 * Small DNS abstraction used by the email and DNS checks.
 * It's an interface so tests can inject a fake resolver - no real DNS needed.
 */
export interface DnsClient {
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<{ exchange: string; priority: number }[]>;
  caa(name: string): Promise<{ tag: string; value: string; critical: number }[]>;
  /** true = DNSSEC-validated, false = not signed/validated, null = couldn't determine */
  dnssec(name: string): Promise<boolean | null>;
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
    dnssec: async (name) => {
      // Node's resolver can't validate DNSSEC, so ask a validating DNS-over-HTTPS resolver
      // and read the AD ("Authenticated Data") flag. This is a fixed, trusted host - not user input.
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=SOA&do=true`, {
          headers: { Accept: "application/dns-json" },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (!res.ok) return null;
        const data = (await res.json()) as { Status?: number; AD?: boolean };
        if (data.Status !== 0) return null;
        return data.AD === true;
      } catch {
        return null;
      }
    },
  };
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
