import type { Finding } from "../types";
import { getHeaderList, type Headers } from "./util";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair, ...attrs] = header.split(";");
  const name = pair.split("=")[0].trim();
  const attrMap = new Map(
    attrs.map((a) => {
      const [k, ...v] = a.trim().split("=");
      return [k.toLowerCase(), v.join("=").trim()] as const;
    }),
  );
  return {
    name,
    secure: attrMap.has("secure"),
    httpOnly: attrMap.has("httponly"),
    sameSite: attrMap.get("samesite")?.toLowerCase() ?? null,
  };
}

/** Cookie names that usually hold a session or auth token. */
const SESSION_LIKE = /sess|sid|auth|token|login|jwt|remember|xsrf|csrf|laravel|phpsessid|jsessionid|asp\.net/i;

export function runCookieChecks(headers: Headers, isHttps: boolean): Finding[] {
  const cookies = getHeaderList(headers, "set-cookie").map(parseSetCookie);
  if (cookies.length === 0) {
    return [{
      id: "cookies-none", category: "cookies", title: "Cookies",
      status: "info", severity: "info",
      description: "The page did not set any cookies, so there are no cookie flags to check.",
    }];
  }

  const findings: Finding[] = [];
  for (const c of cookies) {
    const problems: string[] = [];
    const sessionLike = SESSION_LIKE.test(c.name);
    if (isHttps && !c.secure) problems.push("missing `Secure` (can be sent over plain HTTP)");
    // CSRF tokens are meant to be read by JS, so don't demand HttpOnly for them.
    if (!c.httpOnly && sessionLike && !/xsrf|csrf/i.test(c.name)) problems.push("missing `HttpOnly` (readable by JavaScript, so an XSS bug can steal it)");
    if (!c.sameSite) problems.push("no `SameSite` attribute");
    else if (c.sameSite === "none" && !c.secure) problems.push("`SameSite=None` without `Secure` is rejected by browsers");

    findings.push({
      id: `cookie-${c.name}`,
      category: "cookies",
      title: `Cookie \`${c.name}\``,
      status: problems.length ? (sessionLike ? "fail" : "warn") : "pass",
      severity: problems.length ? (sessionLike ? "medium" : "low") : "medium",
      description: problems.length
        ? `${sessionLike ? "This looks like a session/auth cookie and is " : "Cookie is "}${problems.join("; ")}.`
        : "Secure, HttpOnly-appropriate and SameSite flags are set.",
      evidence: `Secure=${c.secure} HttpOnly=${c.httpOnly} SameSite=${c.sameSite ?? "(not set)"}`,
      recommendation: problems.length ? "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`)." : undefined,
    });
  }
  return findings;
}
