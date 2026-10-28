/**
 * End-to-end scan against a deliberately insecure local server.
 * Uses ALLOW_PRIVATE_TARGETS (dev-only) so the scanner may connect to 127.0.0.1.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import zlib from "node:zlib";
import type { AddressInfo } from "node:net";
import { runScan, parseTargetUrl } from "../src/lib/scanner/index";

// Read at call time by the scanner, so setting it here is enough.
process.env.ALLOW_PRIVATE_TARGETS = "true";

let server: http.Server;
let port = 8080;

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === "/.env") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("APP_ENV=production\nDB_PASSWORD=hunter2\n");
    }
    if (req.url === "/old") {
      res.writeHead(301, { Location: "/" });
      return res.end();
    }
    const origin = req.headers.origin;
    const html = `<html><body><h1>Insecure demo</h1><script src="http://cdn.example/x.js"></script>${"<p>pad</p>".repeat(200)}</body></html>`;
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Encoding": "gzip",
      Server: "Apache/2.4.41 (Ubuntu)",
      "X-Powered-By": "PHP/7.4.3",
      "Set-Cookie": ["PHPSESSID=abc123; path=/"],
      ...(origin ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" } : {}),
    });
    res.end(zlib.gzipSync(html));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
  port = (server.address() as AddressInfo).port;
});

after(() => server?.close());

test("scans an insecure site and finds the expected problems", async () => {
  const report = await runScan(`http://127.0.0.1:${port}/old`);
  const ids = new Set(report.findings.filter((f) => f.status === "fail" || f.status === "warn").map((f) => f.id));

  for (const expected of ["tls-missing", "csp", "clickjacking", "nosniff", "server-version", "tech-headers", "exposed-/.env", "cors", "cookie-PHPSESSID"]) {
    assert.ok(ids.has(expected), `expected finding ${expected}; got ${[...ids].join(", ")}`);
  }
  assert.equal(report.grade, "F");
  assert.equal(report.redirectChain.length, 2, "followed the 301");
  assert.equal(report.finalUrl, `http://127.0.0.1:${port}/`);
});

test("SSRF guard is active when the dev flag is off", () => {
  process.env.ALLOW_PRIVATE_TARGETS = "false";
  assert.throws(() => parseTargetUrl(`http://127.0.0.1:${port}/`), /Private/);
  process.env.ALLOW_PRIVATE_TARGETS = "true";
});
