import type { Finding } from "../types";
import { domainChain, orgDomain, type DnsClient } from "../dnsClient";

/**
 * CAA: which Certificate Authorities may issue TLS certificates for the domain.
 * Without it, any of ~100 public CAs can issue one, so a mistake or compromise at
 * any of them could produce a valid certificate for your site.
 * CAA is inherited: the closest record walking up the DNS tree applies.
 */
export async function checkCaa(host: string, dns: DnsClient): Promise<Finding> {
  const base = { id: "caa", category: "dns" as const, title: "CAA (certificate authority restriction)" };
  for (const name of domainChain(host)) {
    const records = await dns.caa(name).catch(() => []);
    if (records.length) {
      // The closest record set applies even if it only has iodef, and iodef alone restricts no one.
      if (!records.some((r) => r.tag === "issue" || r.tag === "issuewild")) {
        return { ...base, status: "warn", severity: "low",
          evidence: records.map((r) => `${name} CAA ${r.critical} ${r.tag} "${r.value}"`).join("\n"),
          description: `The CAA record${name !== host ? ` (inherited from ${name})` : ""} only sets a reporting address (iodef) and has no \`issue\` entry, so any certificate authority may still issue certificates.`,
          recommendation: `Add an \`issue\` entry next to it, e.g. \`0 issue "letsencrypt.org"\` (use your actual CA).` };
      }
      const issuers = records.filter((r) => r.tag === "issue" || r.tag === "issuewild").map((r) => r.value.split(";")[0].trim() || "(none)");
      const iodef = records.some((r) => r.tag === "iodef");
      return { ...base, status: "pass", severity: "low",
        evidence: records.map((r) => `${name} CAA ${r.critical} ${r.tag} "${r.value}"`).join("\n"),
        description: `Only ${[...new Set(issuers)].join(", ") || "no CA"} may issue certificates${name !== host ? ` (inherited from ${name})` : ""}.${iodef ? " Violation reports are enabled (iodef)." : ""}` };
    }
  }
  return { ...base, status: "warn", severity: "low",
    description: "No CAA record, so any public certificate authority may issue certificates for this domain.",
    recommendation: `Add a CAA record on ${orgDomain(host)}, e.g. \`0 issue "letsencrypt.org"\` (use your actual CA, e.g. "pki.goog" or "sectigo.com").` };
}

/**
 * DNSSEC signs DNS answers so attackers can't forge them (DNS spoofing / cache poisoning).
 */
export async function checkDnssec(host: string, dns: DnsClient): Promise<Finding> {
  const base = { id: "dnssec", category: "dns" as const, title: "DNSSEC" };
  const zone = orgDomain(host);
  const status = await dns.dnssec(zone).catch(() => null);
  if (status === null) {
    return { ...base, status: "info", severity: "info", description: "DNSSEC status could not be determined (the DNS resolver didn't answer)." };
  }
  if (status === "broken") {
    return { ...base, status: "fail", severity: "high",
      description: `${zone} has DNSSEC enabled at the registrar (a DS record), but its signatures don't validate. Validating resolvers, used by a large share of internet users, cannot resolve the domain at all.`,
      recommendation: "Fix the signing at your DNS provider, or remove the DS record at your registrar until it is fixed. https://dnsviz.net shows where the chain breaks." };
  }
  return status
    ? { ...base, status: "pass", severity: "low", description: `${zone} is DNSSEC-signed (a DS record is published at the parent zone), so validating resolvers can detect forged DNS answers.` }
    : { ...base, status: "warn", severity: "low",
        description: `${zone} is not DNSSEC-signed. Attackers who can spoof DNS responses could redirect visitors or intercept email.`,
        recommendation: "Enable DNSSEC at your DNS provider (often one click in Cloudflare and others), then add the DS record at your registrar." };
}

export async function runDnsChecks(host: string, dns: DnsClient): Promise<Finding[]> {
  return Promise.all([checkCaa(host, dns), checkDnssec(host, dns)]);
}
