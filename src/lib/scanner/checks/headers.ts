import type { Finding } from "../types";
import { getHeader, getHeaderList, truncate, type Headers } from "./util";

const SIX_MONTHS = 15_552_000;

export function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name && !directives.has(name.toLowerCase())) {
      directives.set(name.toLowerCase(), sources.map((s) => s.toLowerCase()));
    }
  }
  return directives;
}

/**
 * Every enforced CSP header policy. Repeated headers arrive as an array (see httpClient), and a
 * single header may also hold several policies separated by commas (RFC 9110 field combining).
 */
export function cspPolicies(headers: Headers, name = "content-security-policy"): string[] {
  return getHeaderList(headers, name)
    .flatMap((v) => v.split(","))
    .map((p) => p.trim())
    .filter(Boolean);
}

/** `<meta http-equiv="Content-Security-Policy" content="…">` policies from the page body. */
export function metaCspPolicies(html: string): string[] {
  const out: string[] = [];
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(tag)) continue;
    const content = tag.match(/content\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    const value = (content?.[1] ?? content?.[2] ?? "").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&").trim();
    if (value) out.push(value);
  }
  return out;
}

const ONE_YEAR = 31_536_000;

export function checkHsts(headers: Headers, isHttps: boolean): Finding {
  const base = { id: "hsts", category: "headers" as const, title: "Strict-Transport-Security (HSTS)" };
  // Browsers only honour the first HSTS header.
  const value = getHeaderList(headers, "strict-transport-security")[0];
  const recommendation =
    "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on HTTPS responses.";

  if (!isHttps) {
    return { ...base, status: "info", severity: "info", description: "HSTS only applies to HTTPS responses; the site was not served over HTTPS." };
  }
  if (!value) {
    return { ...base, status: "fail", severity: "high", recommendation,
      description: "HSTS is missing, so browsers may still connect over plain HTTP, leaving users open to SSL-stripping attacks." };
  }
  const maxAge = Number(value.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
  if (maxAge < SIX_MONTHS) {
    return { ...base, status: "warn", severity: "medium", evidence: value, recommendation,
      description: `HSTS max-age is ${maxAge}s. Use at least 6 months (15552000s) to get real protection.` };
  }
  const subdomains = /includesubdomains/i.test(value);
  const preload = /(^|;)\s*preload\s*(;|$)/i.test(value);
  const extras = [subdomains && "includeSubDomains", preload && "preload"].filter(Boolean);
  const days = Math.round(maxAge / 86400);
  if (preload && (maxAge < ONE_YEAR || !subdomains)) {
    // hstspreload.org rejects the submission, so the `preload` token gives a false sense of safety.
    return { ...base, status: "warn", severity: "low", evidence: value,
      recommendation: "For the preload list use `max-age` of at least 31536000 together with `includeSubDomains` and `preload`.",
      description: `HSTS is enabled for ${days} days, but the \`preload\` directive is set without meeting the preload list's requirements (max-age of at least 1 year and includeSubDomains).` };
  }
  return { ...base, status: "pass", severity: "high", evidence: value,
    description: `HSTS is enabled for ${days} days${extras.length ? ` with ${extras.join(" and ")}` : ""}.${preload ? " The policy meets the HSTS preload list requirements." : ""}` };
}

type CspIssue = { key: string; text: string; major: boolean };

/** Weaknesses of one policy. Keys let us intersect issues across several enforced policies. */
function cspIssues(policy: string): CspIssue[] {
  const csp = parseCsp(policy);
  const scriptSrc = csp.get("script-src") ?? csp.get("default-src");
  const issues: CspIssue[] = [];
  let usesNonceOrHash = false;
  if (!scriptSrc) issues.push({ key: "no-script-src", major: true, text: "no `script-src` or `default-src` directive, so scripts are unrestricted" });
  else {
    usesNonceOrHash = scriptSrc.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"));
    const strictDynamic = scriptSrc.includes("'strict-dynamic'");
    // Browsers ignore 'unsafe-inline' when a nonce or hash is present, so it is only a problem without one.
    if (scriptSrc.includes("'unsafe-inline'") && !usesNonceOrHash) issues.push({ key: "unsafe-inline", major: true, text: "`'unsafe-inline'` allows inline scripts (defeats XSS protection)" });
    if (scriptSrc.includes("'unsafe-eval'")) issues.push({ key: "unsafe-eval", major: false, text: "`'unsafe-eval'` allows eval()" });
    if (!strictDynamic && scriptSrc.some((s) => s === "*" || s === "http:" || s === "https:" || s === "data:")) {
      issues.push({ key: "wildcard", major: true, text: "wildcard or scheme-only script sources let scripts load from almost anywhere" });
    }
  }
  if (!csp.has("object-src") && !(csp.get("default-src") ?? []).includes("'none'")) {
    issues.push({ key: "object-src", major: false, text: "no `object-src 'none'` (plugin content allowed)" });
  }
  // base-uri does not fall back to default-src. Without it an injected <base> tag can
  // redirect relative script URLs, which defeats nonce/hash-based policies.
  if (usesNonceOrHash && !csp.has("base-uri")) {
    issues.push({ key: "base-uri", major: false, text: "no `base-uri` (an injected `<base>` tag could hijack relative script URLs)" });
  }
  return issues;
}

export function checkCsp(headers: Headers, html = ""): Finding {
  const base = { id: "csp", category: "headers" as const, title: "Content-Security-Policy (CSP)" };
  const headerPolicies = cspPolicies(headers);
  const metaPolicies = metaCspPolicies(html);
  const policies = [...headerPolicies, ...metaPolicies];
  const reportOnly = getHeader(headers, "content-security-policy-report-only");
  const recommendation =
    "Deploy a CSP that restricts script sources, e.g. `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.";

  if (policies.length === 0) {
    return { ...base, status: "fail", severity: "high", recommendation,
      evidence: reportOnly ? `Report-only policy found: ${truncate(reportOnly)}` : undefined,
      description: reportOnly
        ? "Only a report-only CSP is set. It reports violations but does not block XSS."
        : "No Content-Security-Policy. CSP is the strongest browser-side defence against cross-site scripting (XSS)." };
  }

  // With several policies, a resource must satisfy all of them, so a weakness only
  // remains if every policy has it.
  const perPolicy = policies.map(cspIssues);
  const issues = perPolicy[0].filter((i) => perPolicy.every((list) => list.some((j) => j.key === i.key)));
  const evidence = truncate(
    [...headerPolicies, ...metaPolicies.map((p) => `<meta> ${p}`)].join(" | "),
    300,
  );
  const source = headerPolicies.length === 0
    ? " (set with a `<meta>` tag; `frame-ancestors` and reporting do not work there)"
    : policies.length > 1 ? ` (${policies.length} policies combined)` : "";

  if (issues.length === 0) {
    return { ...base, status: "pass", severity: "high", evidence,
      description: `A restrictive Content-Security-Policy is in place${source}.` };
  }
  // A policy that still lets injected scripts run gives little XSS protection, so it costs
  // half of a missing CSP. Hardening gaps alone are minor.
  const major = issues.some((i) => i.major);
  return { ...base, status: "warn", severity: major ? "high" : "low", evidence, recommendation,
    description: `CSP is present${source} but weak: ${issues.map((i) => i.text).join("; ")}.` };
}

export function checkFraming(headers: Headers): Finding {
  const base = { id: "clickjacking", category: "headers" as const, title: "Clickjacking protection" };
  const xfo = getHeader(headers, "x-frame-options");
  // frame-ancestors is ignored in <meta> policies, so only headers count. Any restrictive policy wins.
  const frameAncestors = cspPolicies(headers)
    .map((p) => parseCsp(p).get("frame-ancestors"))
    .find((fa) => fa && !fa.includes("*"));

  if (frameAncestors) {
    return { ...base, status: "pass", severity: "medium", evidence: `frame-ancestors ${frameAncestors.join(" ")}`,
      description: "CSP `frame-ancestors` controls who can embed this site." };
  }
  if (xfo && /^(deny|sameorigin)$/i.test(xfo.trim())) {
    return { ...base, status: "pass", severity: "medium", evidence: `X-Frame-Options: ${xfo}`,
      description: "X-Frame-Options prevents other sites from framing this page." };
  }
  return { ...base, status: "fail", severity: "medium",
    recommendation: "Add `X-Frame-Options: DENY` or the CSP directive `frame-ancestors 'none'`.",
    description: "Any website can embed this page in an iframe and trick users into clicking hidden buttons (clickjacking)." };
}

export function checkNoSniff(headers: Headers): Finding {
  const value = getHeader(headers, "x-content-type-options");
  const ok = value?.trim().toLowerCase() === "nosniff";
  return {
    id: "nosniff", category: "headers", title: "X-Content-Type-Options",
    status: ok ? "pass" : "fail", severity: "low", evidence: value,
    description: ok
      ? "MIME-type sniffing is disabled."
      : "Browsers may guess (sniff) content types, which can turn uploaded files into executable scripts.",
    recommendation: ok ? undefined : "Add `X-Content-Type-Options: nosniff`.",
  };
}

const SAFE_REFERRER = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"];

export function checkReferrerPolicy(headers: Headers): Finding {
  const base = { id: "referrer-policy", category: "headers" as const, title: "Referrer-Policy" };
  const value = getHeader(headers, "referrer-policy");
  if (!value) {
    return { ...base, status: "warn", severity: "low",
      recommendation: "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
      description: "No Referrer-Policy. Modern browsers default to a safe policy, but setting it explicitly prevents full URLs (which may contain tokens) leaking to other sites." };
  }
  // The last valid token wins per the spec.
  const effective = value.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean).pop() ?? "";
  if (SAFE_REFERRER.includes(effective)) {
    return { ...base, status: "pass", severity: "low", evidence: value, description: `Referrer-Policy is set to \`${effective}\`.` };
  }
  return { ...base, status: "fail", severity: "low", evidence: value,
    recommendation: "Use `strict-origin-when-cross-origin` or `no-referrer`.",
    description: `\`${effective}\` sends full URLs to other sites, which can leak sensitive query parameters.` };
}

export function checkPermissionsPolicy(headers: Headers): Finding {
  const value = getHeader(headers, "permissions-policy");
  return {
    id: "permissions-policy", category: "headers", title: "Permissions-Policy",
    status: value ? "pass" : "warn", severity: "low", evidence: value ? truncate(value) : undefined,
    description: value
      ? "Browser features (camera, microphone, geolocation…) are restricted."
      : "No Permissions-Policy. Embedded third-party content could request powerful browser features.",
    recommendation: value ? undefined : "Add e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
  };
}

export function checkCoop(headers: Headers): Finding {
  const value = getHeader(headers, "cross-origin-opener-policy");
  const ok = !!value && /same-origin/i.test(value);
  return {
    id: "coop", category: "headers", title: "Cross-Origin-Opener-Policy",
    status: ok ? "pass" : "info", severity: "low", evidence: value,
    description: ok
      ? "The page is isolated from cross-origin windows it opens or is opened by."
      : "No COOP. Optional, but it isolates your window from cross-origin pop-ups (XS-Leaks, Spectre-style attacks).",
    recommendation: ok ? undefined : "Consider `Cross-Origin-Opener-Policy: same-origin`.",
  };
}

export function checkLegacyXss(headers: Headers): Finding | null {
  const value = getHeader(headers, "x-xss-protection");
  if (!value || value.trim().startsWith("0")) return null;
  return {
    id: "x-xss-protection", category: "headers", title: "Deprecated X-XSS-Protection",
    status: "info", severity: "info", evidence: value,
    description: "X-XSS-Protection is deprecated, and the old browser XSS auditor it enables could itself be abused. Rely on CSP instead.",
    recommendation: "Remove the header or set `X-XSS-Protection: 0`.",
  };
}

export function runHeaderChecks(headers: Headers, isHttps: boolean, html = ""): Finding[] {
  return [
    checkHsts(headers, isHttps),
    checkCsp(headers, html),
    checkFraming(headers),
    checkNoSniff(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkCoop(headers),
    checkLegacyXss(headers),
  ].filter((f): f is Finding => f !== null);
}
