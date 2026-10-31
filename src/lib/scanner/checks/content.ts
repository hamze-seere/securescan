import type { Finding } from "../types";
import { cspPolicies, metaCspPolicies, parseCsp } from "./headers";
import { getHeader, type Headers } from "./util";

/** Active content can rewrite the whole page if tampered with; passive content cannot. */
const ACTIVE = /<(script|iframe|frame|embed|object)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const STYLESHEET = /<link\b(?=[^>]*\brel\s*=\s*["']?stylesheet)[^>]*\bhref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const PASSIVE = /<(img|audio|video|source)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const SRCSET = /<(?:img|source)\b[^>]*\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const FORM = /<form\b[^>]*\baction\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
const SCRIPT_TAG = /<script\b[^>]*>/gi;
const STYLESHEET_TAG = /<link\b(?=[^>]*\brel\s*=\s*["']?stylesheet)[^>]*>/gi;

/**
 * Public CDNs that serve immutable, versioned files. Scripts from these hosts can always carry an
 * `integrity` hash, so a missing one is a real gap. (Tag managers and analytics change their files
 * in place and cannot use SRI, so they are only listed.)
 */
const STATIC_CDNS = /(^|\.)(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|ajax\.googleapis\.com|cdn\.datatables\.net|ajax\.aspnetcdn\.com)$/i;

function collect(re: RegExp, html: string, group: number): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(re)) out.add(m[group]);
  return [...out];
}

function srcsetHttp(html: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(SRCSET)) {
    for (const candidate of (m[1] ?? m[2] ?? "").split(",")) {
      const url = candidate.trim().split(/\s+/)[0];
      if (/^http:\/\//i.test(url)) out.add(url);
    }
  }
  return [...out];
}

const attr = (tag: string, name: string) =>
  tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"))?.slice(1).find((v) => v !== undefined);

/** External scripts/stylesheets from another host that lack an `integrity` attribute. */
export function missingSri(html: string, pageUrl: string): { url: string; staticCdn: boolean }[] {
  const page = new URL(pageUrl);
  const out = new Map<string, boolean>();
  const tags = [
    ...[...html.matchAll(SCRIPT_TAG)].map((m) => [m[0], "src"] as const),
    ...[...html.matchAll(STYLESHEET_TAG)].map((m) => [m[0], "href"] as const),
  ];
  for (const [tag, key] of tags) {
    const ref = attr(tag, key);
    if (!ref || attr(tag, "integrity")) continue;
    let url: URL;
    try { url = new URL(ref, page); } catch { continue; }
    if (url.protocol !== "https:" && url.protocol !== "http:") continue;
    if (url.hostname === page.hostname) continue;
    out.set(url.toString(), STATIC_CDNS.test(url.hostname));
  }
  return [...out].map(([url, staticCdn]) => ({ url, staticCdn }));
}

export function runContentChecks(html: string, isHttps: boolean, headers: Headers, pageUrl?: string): Finding[] {
  const contentType = getHeader(headers, "content-type") ?? "";
  if (!/html/i.test(contentType)) return [];
  // Commented-out markup is never loaded.
  const page = html.replace(/<!--[\s\S]*?-->/g, "");
  const findings: Finding[] = [];

  if (isHttps) findings.push(...mixedContent(page, headers));
  if (pageUrl) {
    const sri = checkSri(page, pageUrl);
    if (sri) findings.push(sri);
  }
  return findings;
}

function mixedContent(page: string, headers: Headers): Finding[] {
  const active = [...collect(ACTIVE, page, 2), ...collect(STYLESHEET, page, 1)];
  const passive = [...collect(PASSIVE, page, 2), ...srcsetHttp(page)];
  const forms = collect(FORM, page, 1);
  // With upgrade-insecure-requests the browser rewrites http:// subresources to https:// before
  // fetching, so they are not actually loaded insecurely.
  const upgraded = [...cspPolicies(headers), ...metaCspPolicies(page)].some((p) => parseCsp(p).has("upgrade-insecure-requests"));
  const findings: Finding[] = [];

  if (active.length || (passive.length && upgraded)) {
    findings.push(upgraded
      ? {
          id: "mixed-active", category: "content", title: "Mixed content (auto-upgraded)",
          status: "info", severity: "info", evidence: [...active, ...passive].slice(0, 5).join("\n"),
          description: "The page references http:// resources, but its CSP sets `upgrade-insecure-requests`, so browsers fetch them over HTTPS instead.",
          recommendation: "Change the URLs to https:// anyway, so the page does not depend on the upgrade.",
        }
      : {
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
  if (passive.length && !upgraded) {
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

function checkSri(page: string, pageUrl: string): Finding | null {
  const base = { id: "sri", category: "content" as const, title: "Subresource Integrity (SRI)" };
  const missing = missingSri(page, pageUrl);
  if (missing.length === 0) return null;
  const cdn = missing.filter((m) => m.staticCdn);
  if (cdn.length) {
    return { ...base, status: "warn", severity: "medium", evidence: cdn.slice(0, 5).map((m) => m.url).join("\n"),
      description: `${cdn.length} script${cdn.length === 1 ? "" : "s"} or stylesheet${cdn.length === 1 ? "" : "s"} from a public CDN load without an \`integrity\` hash. If the CDN is compromised, the attacker's code runs on your page.`,
      recommendation: "Add `integrity=\"sha384-…\"` and `crossorigin=\"anonymous\"` to every CDN `<script>` and stylesheet (cdnjs and jsDelivr show the hash), or self-host the files." };
  }
  return { ...base, status: "info", severity: "info", evidence: missing.slice(0, 5).map((m) => m.url).join("\n"),
    description: `The page loads ${missing.length} third-party script${missing.length === 1 ? "" : "s"} or stylesheet${missing.length === 1 ? "" : "s"} without an \`integrity\` hash. That is normal for tag managers and analytics, which change their files in place, but each one can run any code on your page.`,
    recommendation: "Keep third-party scripts to a minimum, and use SRI for any file with a fixed version." };
}
