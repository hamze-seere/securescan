import type { Finding } from "../types";
import { orgDomain, type DnsClient } from "../dnsClient";

/**
 * Email security: can attackers send email that pretends to come from this domain?
 *  - SPF   says which servers may send mail for the domain
 *  - DKIM  cryptographically signs outgoing mail
 *  - DMARC tells receivers what to do when SPF/DKIM fail (and where to send reports)
 * Without these, phishing emails "from" your domain land in inboxes.
 */

/** DKIM selectors used by popular providers. DKIM keys can't be discovered without the selector. */
export const DKIM_SELECTORS = [
  "google", "default", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail",
  "dkim", "smtp", "zoho", "protonmail", "mandrill", "mxvault", "everlytic", "sendgrid", "amazonses", "fm1",
];

const SPF_LOOKUP_MECHANISMS = /^(?:[+\-~?]?)(include:|a\b|a:|a\/|mx\b|mx:|mx\/|ptr|exists:|redirect=)/i;

export function analyzeSpf(record: string) {
  const terms = record.trim().split(/\s+/).slice(1);
  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
  const qualifier = all ? (/^[+\-~?]/.test(all) ? all[0] : "+") : null;
  const lookups = terms.filter((t) => SPF_LOOKUP_MECHANISMS.test(t)).length;
  const hasRedirect = terms.some((t) => /^redirect=/i.test(t));
  return { qualifier, lookups, hasRedirect };
}

export function checkSpf(domain: string, txt: string[], hasMx: boolean): Finding {
  const base = { id: "spf", category: "email" as const, title: "SPF (sender policy)" };
  const records = txt.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));

  if (records.length === 0) {
    return hasMx
      ? { ...base, status: "fail", severity: "medium",
          description: `${domain} receives email but has no SPF record, so anyone can send email claiming to be from it.`,
          recommendation: "Publish a TXT record such as `v=spf1 include:_spf.google.com -all` listing your real mail providers." }
      : { ...base, status: "info", severity: "info",
          description: `${domain} has no SPF record and no mail servers. If it never sends email, lock it down so it can't be spoofed.`,
          recommendation: "Publish `v=spf1 -all` to declare that this domain sends no email." };
  }
  if (records.length > 1) {
    return { ...base, status: "fail", severity: "medium", evidence: records.join("\n"),
      description: "Multiple SPF records were found. This is invalid (SPF PermError), so receivers ignore SPF entirely.",
      recommendation: "Merge them into a single `v=spf1 … -all` record." };
  }

  const record = records[0];
  const { qualifier, lookups, hasRedirect } = analyzeSpf(record);

  if (qualifier === "+") {
    return { ...base, status: "fail", severity: "high", evidence: record,
      description: "SPF ends with `+all`, which authorises every server on the internet to send as this domain. It's worse than having no SPF.",
      recommendation: "Replace `+all` with `-all` (or `~all` while testing)." };
  }
  if (lookups > 10) {
    return { ...base, status: "warn", severity: "medium", evidence: record,
      description: `SPF uses ${lookups} DNS-lookup mechanisms at the top level. More than 10 causes a PermError and SPF stops working.`,
      recommendation: "Remove unused `include:` entries or flatten the record." };
  }
  if (qualifier === "?" || (!qualifier && !hasRedirect)) {
    return { ...base, status: "warn", severity: "medium", evidence: record,
      description: "SPF doesn't say what to do with unauthorised senders (`?all` or no `all`), so spoofed mail isn't rejected.",
      recommendation: "End the record with `-all` (hard fail) or `~all` (soft fail)." };
  }
  return { ...base, status: "pass", severity: "medium", evidence: record,
    description: qualifier === "-"
      ? "SPF is published with a strict `-all` policy."
      : "SPF is published. `~all` (soft fail) is acceptable; `-all` is stricter once you're sure all senders are listed." };
}

export function parseTags(record: string): Map<string, string> {
  return new Map(
    record.split(";").map((p) => p.trim()).filter(Boolean).map((p) => {
      const i = p.indexOf("=");
      return [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim()] as [string, string];
    }),
  );
}

export function checkDmarc(
  found: { name: string; record: string } | null,
  domain: string,
  hasMx: boolean,
): Finding {
  const base = { id: "dmarc", category: "email" as const, title: "DMARC (spoofing policy)" };
  if (!found) {
    return { ...base, status: hasMx ? "fail" : "warn", severity: hasMx ? "medium" : "low",
      description: `No DMARC record at _dmarc.${domain}. Receivers have no instruction to reject email that fails SPF/DKIM, and you get no reports about spoofing attempts.`,
      recommendation: `Add a TXT record at _dmarc.${domain}: \`v=DMARC1; p=quarantine; rua=mailto:dmarc@${orgDomain(domain)}\`, then move to \`p=reject\`.` };
  }

  const tags = parseTags(found.record);
  const inherited = found.name !== `_dmarc.${domain}`;
  // A parent domain's policy applies to subdomains via sp= (falls back to p=).
  const policy = ((inherited ? tags.get("sp") : undefined) ?? tags.get("p") ?? "none").toLowerCase();
  const pct = Number(tags.get("pct") ?? 100);
  const reports = tags.has("rua") ? " Aggregate reports are enabled (rua)." : " No `rua` reporting address is set, so you won't see spoofing attempts.";
  const where = inherited ? ` (inherited from ${found.name})` : "";

  if (policy === "none") {
    return { ...base, status: "warn", severity: "low", evidence: found.record,
      description: `DMARC is in monitoring mode \`p=none\`${where}: spoofed email is still delivered.${reports}`,
      recommendation: "Once reports show legitimate mail passes, move to `p=quarantine`, then `p=reject`." };
  }
  if (pct < 100) {
    return { ...base, status: "warn", severity: "low", evidence: found.record,
      description: `DMARC policy \`${policy}\` applies to only ${pct}% of failing mail${where}.${reports}`,
      recommendation: "Increase to `pct=100` (or remove pct)." };
  }
  return { ...base, status: "pass", severity: "medium", evidence: found.record,
    description: `DMARC enforces \`p=${policy}\`${where}: spoofed email is ${policy === "reject" ? "rejected" : "sent to spam"}.${reports}` };
}

export function checkDkim(domain: string, found: string[]): Finding {
  const base = { id: "dkim", category: "email" as const, title: "DKIM (email signing)" };
  if (found.length) {
    return { ...base, status: "pass", severity: "low", evidence: found.map((s) => `${s}._domainkey.${domain}`).join("\n"),
      description: `DKIM signing keys were found for selector${found.length > 1 ? "s" : ""} ${found.map((s) => `\`${s}\``).join(", ")}.` };
  }
  return { ...base, status: "info", severity: "info",
    description: `No DKIM key was found under ${DKIM_SELECTORS.length} common selectors. DKIM may still be configured under a custom selector name (they can't be listed from DNS).`,
    recommendation: "Enable DKIM signing in your email provider and publish the key it gives you." };
}

export async function runEmailChecks(host: string, dns: DnsClient): Promise<Finding[]> {
  const domain = host.replace(/^www\./i, "").toLowerCase();

  const [txt, mx, dkimHits] = await Promise.all([
    dns.txt(domain).catch(() => []),
    dns.mx(domain).catch(() => []),
    Promise.all(
      DKIM_SELECTORS.map(async (s) => {
        const recs = await dns.txt(`${s}._domainkey.${domain}`).catch(() => []);
        // Must contain a non-empty public key (p=). An empty p= means the key was revoked.
        return recs.some((r) => /(?:^|;)\s*p=\s*[A-Za-z0-9+/]/.test(r)) ? s : null;
      }),
    ),
  ]);
  const hasMx = mx.some((m) => m.exchange && m.exchange !== "."); // "." = null MX (RFC 7505)

  // DMARC: look at the domain first, then fall back to the organisational domain.
  let dmarc: { name: string; record: string } | null = null;
  for (const name of [domain, orgDomain(domain)].filter((v, i, a) => a.indexOf(v) === i)) {
    const rec = (await dns.txt(`_dmarc.${name}`).catch(() => [])).find((r) => /^v=DMARC1/i.test(r.trim()));
    if (rec) { dmarc = { name: `_dmarc.${name}`, record: rec }; break; }
  }

  const mxFinding: Finding = {
    id: "mx", category: "email", title: "Mail servers (MX)", status: "info", severity: "info",
    description: hasMx
      ? `${domain} receives email via ${mx.length} mail server${mx.length > 1 ? "s" : ""}.`
      : `${domain} has no mail servers, so it doesn't receive email.`,
    evidence: hasMx ? mx.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`).join("\n") : undefined,
  };

  return [
    mxFinding,
    checkSpf(domain, txt, hasMx),
    checkDmarc(dmarc, domain, hasMx),
    checkDkim(domain, dkimHits.filter((s): s is string => s !== null)),
  ];
}
