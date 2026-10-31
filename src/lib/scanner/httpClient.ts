import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import type { TLSSocket } from "node:tls";
import zlib from "node:zlib";
import type { LookupFunction } from "node:net";
import { allowPrivateTargets, BlockedTargetError, isPrivateIp, parseTargetUrl } from "./ssrf";
import type { FetchResult, HttpResponseData, TlsInfo } from "./types";

const USER_AGENT = "SecureScan/1.0 (+security posture scanner; non-intrusive)";

export interface RequestOptions {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  /** Max (decompressed) body bytes to keep. Protects against huge pages and zip bombs. */
  maxBytes?: number;
  timeoutMs?: number;
  /** Aborts the request early, e.g. when the overall scan time budget runs out. */
  signal?: AbortSignal;
}

export class ScanBudgetError extends Error {
  constructor() {
    super("Scan time budget exceeded");
    this.name = "ScanBudgetError";
  }
}

/** Headers whose repeated values must stay separate: joining them with ", " changes their meaning. */
const DISTINCT_HEADERS = ["content-security-policy", "content-security-policy-report-only", "strict-transport-security"];

/**
 * DNS lookup hook used for every connection. It resolves the hostname and only
 * hands Node a *public* address, so the socket can never be pointed at an
 * internal host - even if DNS changes between validation and connect (rebinding).
 */
const safeLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { all: true, family: options.family ?? 0 }, (err, addresses) => {
    if (err) return callback(err, "", 0);
    const allowed = allowPrivateTargets() ? addresses : addresses.filter((a) => !isPrivateIp(a.address));
    if (allowed.length === 0) {
      return callback(new BlockedTargetError(`${hostname} resolves to a private or reserved address.`), "", 0);
    }
    if (options.all) {
      (callback as unknown as (e: null, a: dns.LookupAddress[]) => void)(null, allowed);
    } else {
      callback(null, allowed[0].address, allowed[0].family);
    }
  });
};

function readTlsInfo(socket: TLSSocket): TlsInfo {
  const cert = socket.getPeerCertificate();
  const hasCert = cert && Object.keys(cert).length > 0;
  const validTo = hasCert && cert.valid_to ? new Date(cert.valid_to) : null;
  const flat = (v: unknown) => (Array.isArray(v) ? v.join(", ") : typeof v === "string" ? v : null);
  return {
    protocol: socket.getProtocol() ?? null,
    cipher: socket.getCipher()?.name ?? null,
    authorized: socket.authorized,
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
    subject: hasCert ? flat(cert.subject?.CN) : null,
    issuer: hasCert ? (flat(cert.issuer?.O) ?? flat(cert.issuer?.CN)) : null,
    validFrom: hasCert && cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
    validTo: validTo ? validTo.toISOString() : null,
    daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null,
    altNames: hasCert && cert.subjectaltname
      ? cert.subjectaltname.split(",").map((s) => s.trim().replace(/^DNS:/, "")).slice(0, 20)
      : [],
  };
}

/** Performs a single HTTP(S) request without following redirects. */
export function request(url: URL, opts: RequestOptions = {}): Promise<HttpResponseData> {
  const { method = "GET", headers = {}, maxBytes = 512 * 1024, timeoutMs = 8000, signal } = opts;
  const lib = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new ScanBudgetError());
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () => {
      req.destroy();
      finish(() => reject(new ScanBudgetError()));
    };

    const req = lib.request(
      url,
      {
        method,
        agent: false,
        lookup: safeLookup,
        // We *want* to connect to sites with bad certs so we can report on them.
        // Validity is recorded from socket.authorized instead.
        rejectUnauthorized: false,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
          "Accept-Encoding": "gzip, deflate, br",
          ...headers,
        },
      },
      (res) => {
        const socket = res.socket as TLSSocket;
        const tls = url.protocol === "https:" && typeof socket.getPeerCertificate === "function"
          ? readTlsInfo(socket)
          : null;
        const remoteAddress = res.socket.remoteAddress ?? null;

        const encoding = String(res.headers["content-encoding"] ?? "").toLowerCase();
        let stream: NodeJS.ReadableStream = res;
        if (method !== "HEAD") {
          if (encoding === "gzip") stream = res.pipe(zlib.createGunzip());
          else if (encoding === "br") stream = res.pipe(zlib.createBrotliDecompress());
          else if (encoding === "deflate") stream = res.pipe(zlib.createInflate());
        }

        const responseHeaders = { ...res.headers } as Record<string, string | string[]>;
        for (const name of DISTINCT_HEADERS) {
          const values = res.headersDistinct[name];
          if (values && values.length > 1) responseHeaders[name] = values;
        }

        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        const done = () =>
          finish(() =>
            resolve({
              url: url.toString(),
              status: res.statusCode ?? 0,
              headers: responseHeaders,
              body: Buffer.concat(chunks).toString("utf8"),
              remoteAddress,
              tls,
              truncated,
            }),
          );

        stream.on("data", (chunk: Buffer) => {
          if (size >= maxBytes) return;
          const room = maxBytes - size;
          chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
          size += Math.min(chunk.length, room);
          if (size >= maxBytes) {
            truncated = true;
            done(); // got enough - stop downloading
            res.destroy();
          }
        });
        stream.on("end", done);
        stream.on("error", () => done()); // truncated/corrupt compression: keep what we have
        res.on("error", () => done());
      },
    );

    const timer = setTimeout(() => {
      req.destroy();
      finish(() => reject(new Error(`Timed out after ${timeoutMs / 1000}s`)));
    }, timeoutMs);

    signal?.addEventListener("abort", onAbort, { once: true });
    req.on("error", (err) => finish(() => reject(err)));
    req.end();
  });
}

/** Follows up to `maxRedirects` redirects, re-validating every hop against the SSRF rules. */
export async function fetchWithRedirects(
  start: URL,
  opts: RequestOptions & { maxRedirects?: number } = {},
): Promise<FetchResult> {
  const { maxRedirects = 5, ...reqOpts } = opts;
  const chain: { url: string; status: number }[] = [];
  const hopCookies: string[] = [];
  let current = start;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const res = await request(current, reqOpts);
    chain.push({ url: res.url, status: res.status });
    const location = res.headers["location"];
    if (res.status >= 300 && res.status < 400 && typeof location === "string") {
      // Cookies set on a redirect (often the session cookie on "/" -> "/login") still reach the browser.
      const setCookie = res.headers["set-cookie"];
      if (setCookie) hopCookies.push(...(Array.isArray(setCookie) ? setCookie : [setCookie]));
      if (hop === maxRedirects) throw new Error(`Too many redirects (>${maxRedirects}).`);
      // Re-validate: a public site must not be able to bounce us into an internal one.
      current = parseTargetUrl(new URL(location, current).toString());
      continue;
    }
    return { final: res, chain, hopCookies };
  }
  throw new Error("Redirect handling failed.");
}
