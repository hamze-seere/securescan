import { randomUUID } from "node:crypto";
import { fetchWithRedirects, request } from "./httpClient";
import { parseTargetUrl } from "./ssrf";
import { runHeaderChecks } from "./checks/headers";
import { runCookieChecks } from "./checks/cookies";
import { runDisclosureChecks } from "./checks/disclosure";
import { checkHttpsRedirect, checkTls } from "./checks/transport";
import { checkSecurityTxt, runExposureChecks } from "./checks/exposure";
import { runContentChecks } from "./checks/content";
import { corsProbes, runCorsCheck } from "./checks/cors";
import { checkOpenRedirect, checkSourceMap, openRedirectPath, sourceMapUrl } from "./checks/leaks";
import { runEmailChecks } from "./checks/email";
import { runDnsChecks } from "./checks/dns";
import { createDnsClient, type DnsClient } from "./dnsClient";
import net from "node:net";
import { computeGrade, computeScore, summarize } from "./score";
import type { FetchResult, Finding, HttpResponseData, ScanReport } from "./types";

export { BlockedTargetError, parseTargetUrl } from "./ssrf";
export { ScanBudgetError } from "./httpClient";
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

export type ScanStage = "connecting" | "analysing" | "probing" | "done";

export interface ScanOptions {
  /** Inject a DNS client (used by tests). */
  dns?: DnsClient;
  /**
   * Total time the scan may take. Checks still running when it runs out are dropped and the report
   * is marked `partial`, so a slow target can't hold a serverless function open.
   */
  budgetMs?: number;
  /** Aborts the scan, e.g. when the client disconnects. */
  signal?: AbortSignal;
  /** Called as the scan moves between stages, for progress display. */
  onProgress?: (stage: ScanStage) => void;
}

export const DEFAULT_BUDGET_MS = 20_000;

/** Bodies of probe responses only need to be long enough to match a signature. */
const PROBE_BYTES = 16 * 1024;

/** Runs every check against `input` and returns a graded report. Non-intrusive: GET requests only. */
export async function runScan(input: string, options: ScanOptions = {}): Promise<ScanReport> {
  const started = Date.now();
  const target = parseTargetUrl(input);
  const budget = AbortSignal.any([
    AbortSignal.timeout(options.budgetMs ?? DEFAULT_BUDGET_MS),
    ...(options.signal ? [options.signal] : []),
  ]);
  const progress = options.onProgress ?? (() => {});
  const budgetSpent = new Promise<void>((resolve) => {
    if (budget.aborted) resolve();
    else budget.addEventListener("abort", () => resolve(), { once: true });
  });
  /** Resolves to `fallback` instead of waiting past the budget. */
  const inBudget = <T>(p: Promise<T>, fallback: T) => Promise.race([p, budgetSpent.then(() => fallback)]);

  progress("connecting");
  const httpsUrl = withProtocol(target, "https:");
  const httpUrl = withProtocol(target, "http:");

  const [httpsRes, httpRes] = await Promise.allSettled([
    httpsUrl ? fetchWithRedirects(httpsUrl, { signal: budget }) : Promise.reject(new Error("not attempted")),
    httpUrl ? fetchWithRedirects(httpUrl, { maxBytes: 4096, signal: budget }) : Promise.reject(new Error("not attempted")),
  ]);

  // Prefer the HTTPS result for analysis; fall back to plain HTTP.
  let main: FetchResult;
  if (httpsRes.status === "fulfilled") main = httpsRes.value;
  else if (httpRes.status === "fulfilled") {
    // The parallel HTTP request kept only 4 KB; fetch again only if the page was longer than that.
    main = httpRes.value.final.truncated ? await fetchWithRedirects(httpUrl!, { signal: budget }) : httpRes.value;
  } else {
    // Surface SSRF blocks (e.g. domain resolving to a private IP) and budget overruns as-is.
    const reason = httpsRes.reason instanceof Error && ["BlockedTargetError", "ScanBudgetError"].includes(httpsRes.reason.name)
      ? httpsRes.reason
      : new UnreachableError(`Could not reach ${target.hostname}: ${errorMessage(httpsRes.reason)}.`);
    throw reason;
  }

  progress("analysing");
  const final = main.final;
  const finalUrl = new URL(final.url);
  const isHttps = finalUrl.protocol === "https:";
  const origin = finalUrl.origin;

  const probe = (path: string) =>
    request(parseTargetUrl(origin + path), { maxBytes: PROBE_BYTES, timeoutMs: 6000, signal: budget }).catch(() => null);

  // Email & DNS checks only make sense for real domain names, not raw IPs.
  const host = finalUrl.hostname;
  const isDomain = !net.isIP(host.replace(/^\[|\]$/g, "")) && host.includes(".");
  const dns = options.dns ?? createDnsClient();

  const cors = corsProbes(host);
  const mapUrl = sourceMapUrl(final.body, final.url);
  progress("probing");
  const [exposure, securityTxt, corsResults, emailFindings, dnsFindings, redirectRes, mapRes] = await Promise.all([
    runExposureChecks(probe),
    fetchSecurityTxt(origin, budget),
    Promise.all(cors.map(async (p) => ({
      probe: p,
      res: await request(finalUrl, { headers: { Origin: p.origin }, maxBytes: 1024, timeoutMs: 6000, signal: budget }).catch(() => null),
    }))),
    isDomain ? inBudget(runEmailChecks(host, dns).catch(() => []), null) : Promise.resolve([]),
    isDomain ? inBudget(runDnsChecks(host, dns).catch(() => []), null) : Promise.resolve([]),
    probe(openRedirectPath()),
    mapUrl ? request(parseTargetUrl(mapUrl), { maxBytes: PROBE_BYTES, timeoutMs: 6000, signal: budget }).catch(() => null) : null,
  ]);
  const partial = budget.aborted;

  const httpsError = httpsRes.status === "fulfilled" ? null
    : httpsUrl ? errorMessage(httpsRes.reason)
    : "not tried, because the URL names a custom port for plain HTTP";
  const findings: Finding[] = [...checkTls(isHttps ? final.tls : null, httpsError)];
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
    ...runHeaderChecks(final.headers, isHttps, final.body),
    ...runCookieChecks(final.headers, isHttps, main.hopCookies),
    ...runDisclosureChecks(final.headers),
    // A probe cut off by the budget looks the same as a missing file, so "nothing exposed" can't be trusted.
    ...(partial ? exposure.filter((f) => f.status !== "pass") : exposure),
    checkSecurityTxt(securityTxt),
    ...[checkOpenRedirect(redirectRes), mapUrl ? checkSourceMap(mapRes, mapUrl) : null].filter((f): f is Finding => f !== null),
    ...runContentChecks(final.body, isHttps, final.headers, final.url),
    runCorsCheck(corsResults),
    ...(emailFindings ?? []),
    ...(dnsFindings ?? []),
  );
  if (partial) {
    findings.push({
      id: "scan-partial", category: "transport", title: "Scan incomplete",
      status: "info", severity: "info",
      description: `The scan stopped after ${Math.round((Date.now() - started) / 1000)}s because the site responded slowly, so some checks are missing from this report.`,
      recommendation: "Scan again; if it keeps happening, the site may be rate-limiting or very slow.",
    });
  }

  const score = computeScore(findings);
  progress("done");
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
    ...(partial ? { partial: true } : {}),
  };
}

/** RFC 9116 location first (following redirects, as browsers do), then the legacy root path. */
async function fetchSecurityTxt(origin: string, signal: AbortSignal): Promise<HttpResponseData | null> {
  const get = (path: string) =>
    fetchWithRedirects(parseTargetUrl(origin + path), { maxRedirects: 2, maxBytes: PROBE_BYTES, timeoutMs: 6000, signal })
      .then((r) => r.final)
      .catch(() => null);
  const wellKnown = await get("/.well-known/security.txt");
  if (wellKnown?.status === 200) return wellKnown;
  return (await get("/security.txt")) ?? wellKnown;
}
