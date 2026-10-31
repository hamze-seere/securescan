import type { Finding, HttpResponseData } from "../types";
import { getHeader } from "./util";

/** A harmless made-up origin. If the server echoes it back, it trusts any origin. */
export const PROBE_ORIGIN = "https://securescan-cors-probe.example";

export interface CorsProbe {
  origin: string;
  /** What it means when the server allows this origin. */
  meaning: string;
}

/**
 * Origins sent in the Origin header. Only the header is sent: SecureScan never contacts these hosts.
 * Besides "any origin", they catch the usual allow-list mistakes: trusting `null`
 * (sandboxed iframes, data: URLs) and unanchored regexes such as /example\.com/.
 */
export function corsProbes(host: string): CorsProbe[] {
  const bare = host.replace(/^www\./, "");
  return [
    { origin: PROBE_ORIGIN, meaning: "reflects any Origin back" },
    { origin: "null", meaning: "trusts the `null` origin, which any site can send from a sandboxed iframe" },
    { origin: `https://${bare}.securescan-probe.example`, meaning: `trusts origins that merely start with \`${bare}\` (an unanchored allow-list check)` },
    { origin: `https://securescanprobe${bare}`, meaning: `trusts origins that merely end with \`${bare}\` (an unanchored allow-list check)` },
  ];
}

type ProbeResult = { probe: CorsProbe; res: HttpResponseData | null };

export function runCorsCheck(results: ProbeResult[] | HttpResponseData | null): Finding {
  const base = { id: "cors", category: "cors" as const, title: "CORS policy" };
  // Single-response form kept for callers that only probe with PROBE_ORIGIN.
  const list: ProbeResult[] = Array.isArray(results)
    ? results
    : [{ probe: { origin: PROBE_ORIGIN, meaning: "reflects any Origin back" }, res: results }];
  const answered = list.filter((r): r is { probe: CorsProbe; res: HttpResponseData } => r.res !== null);
  if (answered.length === 0) {
    return { ...base, status: "info", severity: "info", description: "The CORS probe request did not complete." };
  }

  const acaoOf = (res: HttpResponseData) => getHeader(res.headers, "access-control-allow-origin")?.trim();
  const credsOf = (res: HttpResponseData) => getHeader(res.headers, "access-control-allow-credentials")?.trim().toLowerCase() === "true";

  // `Access-Control-Allow-Origin: null` trusts every sandboxed document, whatever origin was asked about.
  const nullMeaning = corsProbes("")[1].meaning;
  const trusted = answered.filter(({ probe, res }) => acaoOf(res) === probe.origin || acaoOf(res) === "null");
  if (trusted.length) {
    const credentials = trusted.some(({ res }) => credsOf(res));
    const evidence = trusted
      .map(({ probe, res }) => `Origin: ${probe.origin}\nAccess-Control-Allow-Origin: ${acaoOf(res)}${credsOf(res) ? "\nAccess-Control-Allow-Credentials: true" : ""}`)
      .join("\n\n");
    const meanings = [...new Set(trusted.map(({ probe, res }) => (acaoOf(res) === "null" ? nullMeaning : probe.meaning)))];
    const what = meanings.join("; it also ");
    return { ...base, status: "fail", severity: credentials ? "high" : "medium", evidence,
      recommendation: "Compare the Origin header against an exact allow-list of trusted origins. Never reflect it blindly, never allow `null`, and anchor any pattern to the full origin.",
      description: credentials
        ? `The server ${what}, and allows credentials. A malicious site can read logged-in users' data from this site.`
        : `The server ${what}. If any endpoint returns private data, other sites can read it.` };
  }

  const first = answered[0].res;
  const acao = acaoOf(first);
  if (!acao) {
    return { ...base, status: "pass", severity: "high",
      description: `No CORS headers were returned for ${answered.length > 1 ? "any of the foreign test origins" : "a foreign origin"}, so other websites cannot read responses from this site.` };
  }
  const evidence = `Origin: ${answered[0].probe.origin}\nAccess-Control-Allow-Origin: ${acao}`;
  if (acao === "*") {
    return { ...base, status: "info", severity: "info", evidence,
      description: "`Access-Control-Allow-Origin: *` lets any site read public responses. Browsers never send cookies with a wildcard, so this is fine for public content and APIs." };
  }
  // A fixed, specific origin. If it varies per request, caches must key on Origin.
  const vary = getHeader(first.headers, "vary") ?? "";
  if (!/(^|,)\s*(origin|\*)\s*(,|$)/i.test(vary) && answered.some(({ res }) => acaoOf(res) !== acao)) {
    return { ...base, status: "warn", severity: "low", evidence: `${evidence}\nVary: ${vary || "(not set)"}`,
      recommendation: "Add `Vary: Origin` to responses whose Access-Control-Allow-Origin depends on the request.",
      description: "The allowed origin changes per request but the response has no `Vary: Origin`, so a shared cache can serve one origin's CORS headers to another." };
  }
  return { ...base, status: "pass", severity: "high", evidence,
    description: `CORS is restricted to a specific origin (${acao}).` };
}
