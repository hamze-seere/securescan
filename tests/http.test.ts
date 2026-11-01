/**
 * The HTTP client's safety limits, against a local server: connect-time SSRF checks,
 * redirects into private space, body caps, zip bombs and the scan time budget.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import zlib from "node:zlib";
import type { AddressInfo } from "node:net";
import { fetchWithRedirects, request, ScanBudgetError } from "../src/lib/scanner/httpClient";
import { checkTls } from "../src/lib/scanner/checks/transport";
import { runScan } from "../src/lib/scanner/index";
import type { TlsInfo } from "../src/lib/scanner/types";

const allowPrivate = (on: boolean) => { process.env.ALLOW_PRIVATE_TARGETS = on ? "true" : "false"; };

let server: http.Server;
let base = "";
const bomb = zlib.gzipSync(Buffer.alloc(20 * 1024 * 1024)); // 20 MB of zeros, ~20 KB compressed

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === "/big") return res.end("x".repeat(200_000));
    if (req.url === "/bomb") {
      res.writeHead(200, { "Content-Encoding": "gzip" });
      return res.end(bomb);
    }
    if (req.url === "/to-private") {
      // The first hop was allowed; the redirect target must be checked again under production rules.
      allowPrivate(false);
      res.writeHead(302, { Location: `http://127.0.0.1:${(server.address() as AddressInfo).port}/` });
      return res.end();
    }
    if (req.url === "/" || req.url === "/hang-home") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body>ok</body></html>");
    }
    // Every other path (probes, security.txt) never answers.
  });
  // The scanner only connects to standard web ports; the integration test uses 8080.
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(8443, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
  allowPrivate(true);
});

test("the connect-time DNS check refuses hostnames that resolve to private addresses", async () => {
  allowPrivate(false);
  const port = (server.address() as AddressInfo).port;
  // `request` skips parseTargetUrl, so only the lookup hook stands between it and localhost.
  await assert.rejects(request(new URL(`http://localhost:${port}/`), { timeoutMs: 3000 }), { name: "BlockedTargetError" });
  allowPrivate(true);
});

test("a redirect into private address space is blocked", async () => {
  allowPrivate(true);
  await assert.rejects(fetchWithRedirects(new URL(`${base}/to-private`)), { name: "BlockedTargetError" });
  allowPrivate(true);
});

test("bodies are capped, including decompressed zip bombs", async () => {
  allowPrivate(true);
  const big = await request(new URL(`${base}/big`), { maxBytes: 1000 });
  assert.equal(big.body.length, 1000);
  assert.equal(big.truncated, true);

  const boom = await request(new URL(`${base}/bomb`), { maxBytes: 64 * 1024 });
  assert.equal(Buffer.byteLength(boom.body), 64 * 1024);
  assert.equal(boom.truncated, true);
});

test("an aborted budget rejects in-flight requests with ScanBudgetError", async () => {
  allowPrivate(true);
  await assert.rejects(request(new URL(`${base}/never`), { signal: AbortSignal.timeout(100) }), ScanBudgetError);
});

test("a scan that runs out of time returns a partial report instead of failing", async () => {
  allowPrivate(true);
  const report = await runScan(`${base}/`, { budgetMs: 1500 });
  assert.equal(report.partial, true);
  const ids = report.findings.map((f) => f.id);
  assert.ok(ids.includes("scan-partial"));
  // Probes that timed out must not be reported as "nothing exposed".
  assert.ok(!ids.includes("exposure-ok"));
});

const tls = (over: Partial<TlsInfo>): TlsInfo => ({
  protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", authorized: true, authorizationError: null,
  subject: "example.com", issuer: "Let's Encrypt", validFrom: null, validTo: "2027-01-01T00:00:00.000Z",
  daysRemaining: 90, altNames: [], ...over,
});
const statusOf = (findings: ReturnType<typeof checkTls>, id: string) => findings.find((f) => f.id === id)?.status;

test("TLS: certificate trust, expiry and protocol version", () => {
  const good = checkTls(tls({}), null);
  assert.deepEqual(good.map((f) => f.status), ["pass", "pass", "pass"]);

  assert.equal(statusOf(checkTls(tls({ authorized: false, authorizationError: "CERT_HAS_EXPIRED", daysRemaining: -3 }), null), "tls-cert"), "fail");
  assert.equal(statusOf(checkTls(tls({ authorized: false, daysRemaining: -3 }), null), "tls-expiry"), undefined, "expired certs are not penalised twice");
  assert.equal(statusOf(checkTls(tls({ daysRemaining: 5 }), null), "tls-expiry"), "warn");
  assert.equal(statusOf(checkTls(tls({ protocol: "TLSv1" }), null), "tls-protocol"), "fail");

  const none = checkTls(null, "ECONNREFUSED");
  assert.equal(none[0].id, "tls-missing");
  assert.match(none[0].description, /ECONNREFUSED/);
});
