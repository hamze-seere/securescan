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

/**
 * @param extraSetCookies Set-Cookie values from redirect hops before the final page. They reach the
 *   browser too, so they are judged the same way. Later values for the same name win.
 */
export function runCookieChecks(headers: Headers, isHttps: boolean, extraSetCookies: string[] = []): Finding[] {
  const byName = new Map<string, ParsedCookie>();
  for (const c of [...extraSetCookies, ...getHeaderList(headers, "set-cookie")].map(parseSetCookie)) {
    if (c.name) byName.set(c.name, c);
  }
  const cookies = [...byName.values()];
  if (cookies.length === 0) {
    return [{
      id: "cookies-none", category: "cookies", title: "Cookies",
      status: "info", severity: "info",
      description: "The page did not set any cookies, so there are no cookie flags to check.",
    }];
  }

  const findings: Finding[] = [];
  for (const c of cookies) {
    const serious: string[] = [];
    const minor: string[] = [];
    const sessionLike = SESSION_LIKE.test(c.name);
    // Browsers refuse __Secure-/__Host- cookies that lack Secure (and __Host- pins them to this host),
    // so a prefixed cookie that was accepted is guaranteed to be Secure.
    const prefix = /^__Host-/.test(c.name) ? "__Host-" : /^__Secure-/.test(c.name) ? "__Secure-" : null;
    if (isHttps && !c.secure) serious.push(prefix ? `missing \`Secure\`, so browsers will reject this \`${prefix}\` cookie` : "missing `Secure` (can be sent over plain HTTP)");
    // CSRF tokens are meant to be read by JS, so don't demand HttpOnly for them.
    if (!c.httpOnly && sessionLike && !/xsrf|csrf/i.test(c.name)) serious.push("missing `HttpOnly` (readable by JavaScript, so an XSS bug can steal it)");
    if (!c.sameSite) minor.push("no `SameSite` attribute (most browsers now default to Lax, but not all)");
    else if (c.sameSite === "none" && !c.secure) serious.push("`SameSite=None` without `Secure` is rejected by browsers");

    const problems = [...serious, ...minor];
    const failing = serious.length > 0 && sessionLike;
    findings.push({
      id: `cookie-${c.name}`,
      category: "cookies",
      title: `Cookie \`${c.name}\``,
      status: problems.length ? (failing ? "fail" : "warn") : "pass",
      severity: failing || (!problems.length && sessionLike) ? "medium" : "low",
      description: problems.length
        ? `${sessionLike ? "This looks like a session/auth cookie and is " : "Cookie is "}${problems.join("; ")}.`
        : `Secure, HttpOnly-appropriate and SameSite flags are set${prefix ? `, and the \`${prefix}\` prefix makes browsers enforce them` : ""}.`,
      evidence: `Secure=${c.secure} HttpOnly=${c.httpOnly} SameSite=${c.sameSite ?? "(not set)"}`,
      recommendation: problems.length
        ? `Set cookies with \`Secure; HttpOnly; SameSite=Lax\` (or \`Strict\`)${sessionLike && !prefix ? ", and consider the `__Host-` name prefix for session cookies" : ""}.`
        : undefined,
    });
  }
  return findings;
}
