import type { Finding, HttpResponseData } from "../types";
import { getHeader } from "./util";

/**
 * Two cheap probes that only report when they find something: a public JavaScript source map,
 * and an open redirect through a common query parameter on the home page. Each costs one GET.
 * A clean result proves little (other scripts or parameters may still leak), so neither adds a "pass".
 */

/** A host that can never resolve (RFC 2606), so following the redirect would go nowhere. */
export const REDIRECT_CANARY = "https://securescan.invalid/";
const REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return", "returnTo", "continue", "dest"];

/** Path + query that asks the home page to redirect to the canary through every common parameter at once. */
export function openRedirectPath(): string {
  const q = new URLSearchParams(REDIRECT_PARAMS.map((p) => [p, REDIRECT_CANARY]));
  return `/?${q}`;
}

/** `res` is the un-followed response to `openRedirectPath()`. */
export function checkOpenRedirect(res: HttpResponseData | null): Finding | null {
  if (!res || res.status < 300 || res.status >= 400) return null;
  const location = getHeader(res.headers, "location");
  if (!location) return null;
  let target: URL;
  try { target = new URL(location, res.url); } catch { return null; }
  if (target.hostname !== new URL(REDIRECT_CANARY).hostname) return null;
  return {
    id: "open-redirect", category: "exposure", title: "Open redirect",
    status: "fail", severity: "medium",
    evidence: `GET ${openRedirectPath()} → ${res.status} Location: ${location}`,
    description: "The site redirects to any URL passed in a query parameter. Phishing links can use your domain to send people to an attacker's page, and it can leak OAuth tokens.",
    recommendation: "Only redirect to relative paths or to an allowlist of your own hosts; reject anything else.",
  };
}

const SCRIPT_SRC = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;

/** URL of the first same-origin script's `.map` file, or null when the page has no such script. */
export function sourceMapUrl(html: string, pageUrl: string): string | null {
  const page = new URL(pageUrl);
  for (const m of html.replace(/<!--[\s\S]*?-->/g, "").matchAll(SCRIPT_SRC)) {
    let src: URL;
    try { src = new URL(m[1] ?? m[2] ?? m[3], page); } catch { continue; }
    if (src.origin !== page.origin || !/\.m?js$/i.test(src.pathname)) continue;
    src.search = "";
    src.hash = "";
    return `${src}.map`;
  }
  return null;
}

/** `res` is the response to `sourceMapUrl()`. */
export function checkSourceMap(res: HttpResponseData | null, mapUrl: string): Finding | null {
  if (!res || res.status !== 200) return null;
  if (!/"mappings"\s*:/.test(res.body) || !/"sources"\s*:/.test(res.body)) return null;
  const path = new URL(mapUrl).pathname;
  return {
    id: "source-map", category: "exposure", title: "JavaScript source map is public",
    status: "warn", severity: "low",
    evidence: `GET ${path} → 200 (source map)`,
    description: "Source maps rebuild your original front-end code, comments included. That makes it easier to find bugs, hidden endpoints and keys left in the code.",
    recommendation: "Don't deploy `.map` files to production, or upload them only to your error tracker (Next.js: leave `productionBrowserSourceMaps` off).",
  };
}
