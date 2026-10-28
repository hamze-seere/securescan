import { randomUUID } from "node:crypto";
import { fetchWithRedirects, request } from "./httpClient";
import { parseTargetUrl } from "./ssrf";
import { runHeaderChecks } from "./checks/headers";
import { runCookieChecks } from "./checks/cookies";
import { runDisclosureChecks } from "./checks/disclosure";
import { checkHttpsRedirect, checkTls } from "./checks/transport";
import { checkSecurityTxt, runExposureChecks } from "./checks/exposure";
import { runContentChecks } from "./checks/content";
import { PROBE_ORIGIN, runCorsCheck } from "./checks/cors";
import { computeGrade, computeScore, summarize } from "./score";
import type { FetchResult, Finding, ScanReport } from "./types";

export { BlockedTargetError, parseTargetUrl } from "./ssrf";
export type * from "./types";

export class UnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnreachableError";
  }
}

function withProtocol(url: URL, protocol: "http:" | "https:"): URL | null {
  if (url.protocol === protocol) return new URL(url);
  if (url.port) return null; // custom port: we can't guess the other protocol's port
  const copy = new URL(url);
  copy.protocol = protocol;
  return copy;
}

const errorMessage = (e: unknown) => {
  if (e instanceof Error) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOTFOUND") return "domain not found";
    if (code === "ECONNREFUSED") return "connection refused";
    if (code === "ECONNRESET") return "connection reset";
    return e.message;
  }
  return String(e);
};

/** Runs every check against `input` and returns a graded report. Non-intrusive: GET/HEAD requests only. */
export async function runScan(input: string): Promise<ScanReport> {
  const started = Date.now();
  const target = parseTargetUrl(input);

  const httpsUrl = withProtocol(target, "https:");
  const httpUrl = withProtocol(target, "http:");

  const [httpsRes, httpRes] = await Promise.allSettled([
    httpsUrl ? fetchWithRedirects(httpsUrl) : Promise.reject(new Error("not attempted")),
    httpUrl ? fetchWithRedirects(httpUrl, { maxBytes: 4096 }) : Promise.reject(new Error("not attempted")),
  ]);

  // Prefer the HTTPS result for analysis; fall back to plain HTTP.
  let main: FetchResult;
  if (httpsRes.status === "fulfilled") main = httpsRes.value;
  else if (httpRes.status === "fulfilled") {
    // re-fetch HTTP with a full body since the parallel request was truncated
    main = await fetchWithRedirects(httpUrl!);
  } else {
    // Surface SSRF blocks (e.g. domain resolving to a private IP) as-is.
    const reason = httpsRes.reason instanceof Error && httpsRes.reason.name === "BlockedTargetError"
      ? httpsRes.reason
      : new UnreachableError(`Could not reach ${target.hostname}: ${errorMessage(httpsRes.reason)}.`);
    throw reason;
  }

  const final = main.final;
  const finalUrl = new URL(final.url);
  const isHttps = finalUrl.protocol === "https:";
  const origin = finalUrl.origin;

  const probe = (path: string) =>
    request(parseTargetUrl(origin + path), { maxBytes: 64 * 1024, timeoutMs: 6000 }).catch(() => null);

  const [exposure, securityTxt, corsRes] = await Promise.all([
    runExposureChecks(probe),
    probe("/.well-known/security.txt"),
    request(finalUrl, { headers: { Origin: PROBE_ORIGIN }, maxBytes: 1024, timeoutMs: 6000 }).catch(() => null),
  ]);

  const findings: Finding[] = [
    ...checkTls(isHttps ? final.tls : null, httpsRes.status === "rejected" ? errorMessage(httpsRes.reason) : null),
  ];
  if (httpUrl) {
    findings.push(
      checkHttpsRedirect(
        httpRes.status === "fulfilled"
          ? { chain: httpRes.value.chain, finalUrl: httpRes.value.final.url }
          : { error: errorMessage(httpRes.reason) },
      ),
    );
  }
  findings.push(
    ...runHeaderChecks(final.headers, isHttps),
    ...runCookieChecks(final.headers, isHttps),
    ...runDisclosureChecks(final.headers),
    ...exposure,
    checkSecurityTxt(securityTxt),
    ...runContentChecks(final.body, isHttps, final.headers),
    runCorsCheck(corsRes),
  );

  const score = computeScore(findings);
  return {
    id: randomUUID(),
    target: target.toString(),
    finalUrl: final.url,
    ip: final.remoteAddress,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    grade: computeGrade(findings, score),
    score,
    summary: summarize(findings),
    findings,
    tls: isHttps ? final.tls : null,
    redirectChain: main.chain,
    responseHeaders: final.headers,
  };
}
