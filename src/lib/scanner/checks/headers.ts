import type { Finding } from "../types";
import { getHeader, truncate, type Headers } from "./util";

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

export function checkHsts(headers: Headers, isHttps: boolean): Finding {
  const base = { id: "hsts", category: "headers" as const, title: "Strict-Transport-Security (HSTS)" };
  const value = getHeader(headers, "strict-transport-security");
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
  const extras = [/includesubdomains/i.test(value) && "includeSubDomains", /preload/i.test(value) && "preload"].filter(Boolean);
  return { ...base, status: "pass", severity: "high", evidence: value,
    description: `HSTS is enabled for ${Math.round(maxAge / 86400)} days${extras.length ? ` with ${extras.join(" and ")}` : ""}.` };
}

export function checkCsp(headers: Headers): Finding {
  const base = { id: "csp", category: "headers" as const, title: "Content-Security-Policy (CSP)" };
  const value = getHeader(headers, "content-security-policy");
  const reportOnly = getHeader(headers, "content-security-policy-report-only");
  const recommendation =
    "Deploy a CSP that restricts script sources, e.g. `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.";

  if (!value) {
    return { ...base, status: "fail", severity: "high", recommendation,
      evidence: reportOnly ? `Report-only policy found: ${truncate(reportOnly)}` : undefined,
      description: reportOnly
        ? "Only a report-only CSP is set. It reports violations but does not block XSS."
        : "No Content-Security-Policy. CSP is the strongest browser-side defence against cross-site scripting (XSS)." };
  }

  const csp = parseCsp(value);
  const scriptSrc = csp.get("script-src") ?? csp.get("default-src");
  const issues: string[] = [];
  if (!scriptSrc) issues.push("no `script-src` or `default-src` directive, so scripts are unrestricted");
  else {
    const hasNonceOrHash = scriptSrc.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"));
    const strictDynamic = scriptSrc.includes("'strict-dynamic'");
    if (scriptSrc.includes("'unsafe-inline'") && !hasNonceOrHash) issues.push("`'unsafe-inline'` allows inline scripts (defeats XSS protection)");
    if (scriptSrc.includes("'unsafe-eval'")) issues.push("`'unsafe-eval'` allows eval()");
    if (!strictDynamic && scriptSrc.some((s) => s === "*" || s === "http:" || s === "https:" || s === "data:")) {
      issues.push("wildcard or scheme-only script sources let scripts load from almost anywhere");
    }
  }
  if (!csp.has("object-src") && !(csp.get("default-src") ?? []).includes("'none'")) {
    issues.push("no `object-src 'none'` (plugin content allowed)");
  }

  if (issues.length === 0) {
    return { ...base, status: "pass", severity: "high", evidence: truncate(value, 300),
      description: "A restrictive Content-Security-Policy is in place." };
  }
  return { ...base, status: "warn", severity: issues.length > 1 ? "medium" : "low", evidence: truncate(value, 300), recommendation,
    description: `CSP is present but weak: ${issues.join("; ")}.` };
}

export function checkFraming(headers: Headers): Finding {
  const base = { id: "clickjacking", category: "headers" as const, title: "Clickjacking protection" };
  const xfo = getHeader(headers, "x-frame-options");
  const csp = getHeader(headers, "content-security-policy");
  const frameAncestors = csp ? parseCsp(csp).get("frame-ancestors") : undefined;

  if (frameAncestors && !frameAncestors.includes("*")) {
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

export function runHeaderChecks(headers: Headers, isHttps: boolean): Finding[] {
  return [
    checkHsts(headers, isHttps),
    checkCsp(headers),
    checkFraming(headers),
    checkNoSniff(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkCoop(headers),
    checkLegacyXss(headers),
  ].filter((f): f is Finding => f !== null);
}
