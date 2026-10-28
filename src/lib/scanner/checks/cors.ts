import type { Finding, HttpResponseData } from "../types";
import { getHeader } from "./util";

/** A harmless made-up origin. If the server echoes it back, it trusts any origin. */
export const PROBE_ORIGIN = "https://securescan-cors-probe.example";

export function runCorsCheck(res: HttpResponseData | null): Finding {
  const base = { id: "cors", category: "cors" as const, title: "CORS policy" };
  if (!res) {
    return { ...base, status: "info", severity: "info", description: "The CORS probe request did not complete." };
  }
  const acao = getHeader(res.headers, "access-control-allow-origin");
  const credentials = getHeader(res.headers, "access-control-allow-credentials")?.trim().toLowerCase() === "true";

  if (!acao) {
    return { ...base, status: "pass", severity: "high",
      description: "No CORS headers were returned for a foreign origin, so other websites cannot read responses from this site." };
  }
  const evidence = `Origin: ${PROBE_ORIGIN}\nAccess-Control-Allow-Origin: ${acao}${credentials ? "\nAccess-Control-Allow-Credentials: true" : ""}`;

  if (acao === PROBE_ORIGIN || acao === "null") {
    return { ...base, status: "fail", severity: credentials ? "high" : "medium", evidence,
      recommendation: "Only allow an explicit allow-list of trusted origins. Never reflect the Origin header back blindly.",
      description: credentials
        ? "The server reflects any Origin and allows credentials. A malicious site can read logged-in users' data from this site."
        : "The server reflects any Origin back. If any endpoint returns private data, other sites can read it." };
  }
  if (acao === "*") {
    return { ...base, status: "info", severity: "info", evidence,
      description: "`Access-Control-Allow-Origin: *` lets any site read public responses. Browsers never send cookies with a wildcard, so this is fine for public content and APIs." };
  }
  return { ...base, status: "pass", severity: "high", evidence,
    description: `CORS is restricted to a specific origin (${acao}).` };
}
