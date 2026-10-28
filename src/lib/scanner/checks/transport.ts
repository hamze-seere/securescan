import type { Finding, TlsInfo } from "../types";

/** Checks whether plain HTTP is upgraded to HTTPS. */
export function checkHttpsRedirect(
  httpResult: { chain: { url: string; status: number }[]; finalUrl: string } | { error: string },
): Finding {
  const base = { id: "https-redirect", category: "transport" as const, title: "HTTP → HTTPS redirect" };
  if ("error" in httpResult) {
    return { ...base, status: "info", severity: "info",
      description: `Plain HTTP (port 80) did not respond (${httpResult.error}). That's fine if the site is HTTPS-only.` };
  }
  if (httpResult.finalUrl.startsWith("https://")) {
    const first = httpResult.chain[0];
    const permanent = first && (first.status === 301 || first.status === 308);
    return { ...base, status: "pass", severity: "high",
      evidence: httpResult.chain.map((h) => `${h.status} ${h.url}`).join("\n"),
      description: permanent
        ? "Visitors on http:// are permanently redirected to HTTPS."
        : "Visitors on http:// are redirected to HTTPS (a temporary redirect; a 301/308 is better for caching and SEO)." };
  }
  return { ...base, status: "fail", severity: "high",
    evidence: httpResult.chain.map((h) => `${h.status} ${h.url}`).join("\n"),
    recommendation: "Redirect all HTTP traffic to HTTPS with a 301, then add HSTS.",
    description: "The site is served over unencrypted HTTP without redirecting to HTTPS. Anyone on the network can read or modify traffic." };
}

export function checkTls(tls: TlsInfo | null, httpsError: string | null): Finding[] {
  if (!tls) {
    return [{
      id: "tls-missing", category: "transport", title: "HTTPS availability",
      status: "fail", severity: "critical",
      description: `The site could not be reached over HTTPS${httpsError ? ` (${httpsError})` : ""}. All traffic is unencrypted.`,
      recommendation: "Enable HTTPS. Let's Encrypt provides free certificates and most hosts enable it in one click.",
    }];
  }

  const findings: Finding[] = [];

  findings.push(
    tls.authorized
      ? { id: "tls-cert", category: "transport", title: "TLS certificate", status: "pass", severity: "critical",
          evidence: `Subject: ${tls.subject ?? "?"}\nIssuer: ${tls.issuer ?? "?"}`,
          description: `Valid certificate issued by ${tls.issuer ?? "a trusted CA"}.` }
      : { id: "tls-cert", category: "transport", title: "TLS certificate", status: "fail", severity: "critical",
          evidence: tls.authorizationError ?? undefined,
          description: `Browsers will show a security warning: ${describeCertError(tls.authorizationError)}.`,
          recommendation: "Install a valid certificate that matches the domain and includes the full intermediate chain." },
  );

  if (tls.daysRemaining !== null) {
    const d = tls.daysRemaining;
    if (d < 0) {
      // Already reported via authorizationError; don't double-penalise.
    } else if (d < 14) {
      findings.push({ id: "tls-expiry", category: "transport", title: "Certificate expiry", status: "warn", severity: "medium",
        evidence: `Expires ${tls.validTo}`, description: `The certificate expires in ${d} day${d === 1 ? "" : "s"}.`,
        recommendation: "Renew now and automate renewals (e.g. certbot timer)." });
    } else {
      findings.push({ id: "tls-expiry", category: "transport", title: "Certificate expiry", status: "pass", severity: "medium",
        evidence: `Expires ${tls.validTo}`, description: `The certificate is valid for another ${d} days.` });
    }
  }

  const proto = tls.protocol ?? "";
  const modern = proto === "TLSv1.3" || proto === "TLSv1.2";
  findings.push({
    id: "tls-protocol", category: "transport", title: "TLS protocol version",
    status: modern ? "pass" : "fail", severity: "high",
    evidence: `${proto || "unknown"}${tls.cipher ? ` / ${tls.cipher}` : ""}`,
    description: modern
      ? `Negotiated ${proto}${proto === "TLSv1.3" ? " (the latest version)" : ""}.`
      : `Negotiated ${proto || "an unknown protocol"}. TLS 1.0/1.1 are deprecated and vulnerable.`,
    recommendation: modern ? undefined : "Disable TLS 1.0/1.1 and enable TLS 1.2 and 1.3.",
  });

  return findings;
}

function describeCertError(code: string | null): string {
  switch (code) {
    case "CERT_HAS_EXPIRED": return "the certificate has expired";
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "SELF_SIGNED_CERT_IN_CHAIN": return "the certificate is self-signed";
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE": return "the certificate chain is incomplete (missing intermediate certificate)";
    case "ERR_TLS_CERT_ALTNAME_INVALID": return "the certificate does not match this domain name";
    default: return code ? `certificate error ${code}` : "the certificate could not be verified";
  }
}
