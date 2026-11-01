import type { Finding } from "../types";
import { getHeader, type Headers } from "./util";

const LEAKY_HEADERS = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache"];
/** A dotted version number such as nginx/1.25.3 or Microsoft-IIS/10.0, but not opaque ids like "ECS (dcb/7F84)". */
const VERSION = /(^|[/\s(])v?\d+\.\d+/;

export function runDisclosureChecks(headers: Headers): Finding[] {
  const findings: Finding[] = [];

  const server = getHeader(headers, "server");
  if (server && VERSION.test(server)) {
    findings.push({
      id: "server-version", category: "disclosure", title: "Server version disclosed",
      status: "warn", severity: "low", evidence: `Server: ${server}`,
      description: "The Server header reveals the exact software version, so attackers can look up known CVEs for it.",
      recommendation: "Hide version numbers (Apache: `ServerTokens Prod`; Nginx: `server_tokens off;`).",
    });
  }

  const leaks = LEAKY_HEADERS.map((h) => [h, getHeader(headers, h)] as const).filter(([, v]) => v);
  if (leaks.length) {
    findings.push({
      id: "tech-headers", category: "disclosure", title: "Technology stack disclosed",
      status: "warn", severity: "low",
      evidence: leaks.map(([k, v]) => `${k}: ${v}`).join("\n"),
      description: "Response headers reveal the framework/language and often its version, which helps attackers fingerprint the site.",
      recommendation: "Remove these headers (PHP: `expose_php = Off`; Express: `app.disable('x-powered-by')`; Next.js: `poweredByHeader: false`).",
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: "disclosure-ok", category: "disclosure", title: "Version disclosure",
      status: "pass", severity: "low",
      description: "No server or framework version numbers were found in the response headers.",
    });
  }
  return findings;
}
