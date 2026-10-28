import type { Finding } from "../types";
import { getHeader, type Headers } from "./util";

/** Active content can rewrite the whole page if tampered with; passive content cannot. */
const ACTIVE = /<(script|iframe|frame|embed|object)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const STYLESHEET = /<link\b(?=[^>]*\brel\s*=\s*["']?stylesheet)[^>]*\bhref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const PASSIVE = /<(img|audio|video|source)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const FORM = /<form\b[^>]*\baction\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;

function collect(re: RegExp, html: string, group: number): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(re)) out.add(m[group]);
  return [...out];
}

export function runContentChecks(html: string, isHttps: boolean, headers: Headers): Finding[] {
  const contentType = getHeader(headers, "content-type") ?? "";
  if (!isHttps || !/html/i.test(contentType)) return [];

  const active = [...collect(ACTIVE, html, 2), ...collect(STYLESHEET, html, 1)];
  const passive = collect(PASSIVE, html, 2);
  const forms = collect(FORM, html, 1);
  const findings: Finding[] = [];

  if (active.length) {
    findings.push({
      id: "mixed-active", category: "content", title: "Active mixed content",
      status: "fail", severity: "high", evidence: active.slice(0, 5).join("\n"),
      description: "Scripts, styles or frames are loaded over plain HTTP on an HTTPS page. Browsers block them, and anyone who can tamper with that HTTP request can take over the page.",
      recommendation: "Load every resource over https:// (or add `upgrade-insecure-requests` to your CSP).",
    });
  }
  if (forms.length) {
    findings.push({
      id: "insecure-form", category: "content", title: "Form submits over HTTP",
      status: "fail", severity: "high", evidence: forms.slice(0, 5).join("\n"),
      description: "A form posts its data to an http:// URL, so whatever users type (possibly passwords) is sent unencrypted.",
      recommendation: "Change form actions to https:// URLs.",
    });
  }
  if (passive.length) {
    findings.push({
      id: "mixed-passive", category: "content", title: "Passive mixed content",
      status: "warn", severity: "low", evidence: passive.slice(0, 5).join("\n"),
      description: "Images or media are loaded over HTTP. They can be swapped or tracked by a network attacker, and browsers show a degraded padlock.",
      recommendation: "Serve all media over https://.",
    });
  }
  if (!findings.length) {
    findings.push({
      id: "mixed-ok", category: "content", title: "Mixed content",
      status: "pass", severity: "high",
      description: "No resources or forms using plain HTTP were found in the page HTML.",
    });
  }
  return findings;
}
