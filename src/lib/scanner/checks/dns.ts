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
  const validated = await dns.dnssec(zone).catch(() => null);
  if (validated === null) {
    return { ...base, status: "info", severity: "info", description: "DNSSEC status could not be determined (the validating resolver didn't answer)." };
  }
  return validated
    ? { ...base, status: "pass", severity: "low", description: `${zone} is DNSSEC-signed and validates correctly, so its DNS answers can't be forged.` }
    : { ...base, status: "warn", severity: "low",
        description: `${zone} is not DNSSEC-signed. Attackers who can spoof DNS responses could redirect visitors or intercept email.`,
        recommendation: "Enable DNSSEC at your DNS provider (often one click in Cloudflare and others), then add the DS record at your registrar." };
}

export async function runDnsChecks(host: string, dns: DnsClient): Promise<Finding[]> {
  return Promise.all([checkCaa(host, dns), checkDnssec(host, dns)]);
}
