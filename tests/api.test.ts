/** The API routes' guards: content type, rate limits, consent, signed shares and size limits. */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { signForSharing } from "../src/lib/reports";
import type { ScanReport } from "../src/lib/scanner/types";

// Limits are read when the route module loads, so set them before importing it.
process.env.SCAN_RATE_LIMIT = "2";
process.env.SCAN_TARGET_RATE_LIMIT = "0";
let scan: typeof import("../src/app/api/scan/route");
let share: typeof import("../src/app/api/share/route");
before(async () => {
  scan = await import("../src/app/api/scan/route");
  share = await import("../src/app/api/share/route");
});

const post = (path: string, body: unknown, ip: string, headers: Record<string, string> = {}) =>
  new NextRequest(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

test("scan: rejects non-JSON requests with 415", async () => {
  const res = await scan.POST(post("/api/scan", "url=example.com", "203.0.113.1", { "content-type": "application/x-www-form-urlencoded" }));
  assert.equal(res.status, 415);
});

test("scan: requires the ownership confirmation", async () => {
  const res = await scan.POST(post("/api/scan", { url: "example.com" }, "203.0.113.2"));
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /permission/);
});

test("scan: limits each client IP, with Retry-After", async () => {
  const ip = "203.0.113.3";
  for (let i = 0; i < 2; i++) assert.equal((await scan.POST(post("/api/scan", {}, ip))).status, 400);
  const limited = await scan.POST(post("/api/scan", {}, ip));
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get("retry-after")) > 0);
  // Another client is unaffected.
  assert.equal((await scan.POST(post("/api/scan", {}, "203.0.113.4"))).status, 400);
});

test("scan: limits scans of one site across all clients, keyed by the bare hostname", async () => {
  for (const url of ["https://example.com/", "example.com."]) {
    const res = await scan.POST(post("/api/scan", { url, authorized: true }, `198.51.100.${url.length}`));
    assert.equal(res.status, 429);
    assert.match((await res.json()).error, /^example\.com has been scanned/);
  }
});

const report = (): ScanReport => ({
  id: randomUUID(), target: "https://example.com/", finalUrl: "https://example.com/", ip: null,
  scannedAt: new Date().toISOString(), durationMs: 1, grade: "B", score: 80,
  summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, findings: [], tls: null, redirectChain: [], responseHeaders: {},
});

test("share: a signed report gets a link, an edited one is refused with 403", async () => {
  const signed = report();
  signForSharing(signed);
  const ok = await share.POST(post("/api/share", { report: signed }, "192.0.2.1"));
  assert.equal(ok.status, 200);
  assert.match((await ok.json()).url, new RegExp(`/r/${signed.id}$`));

  const forged = report();
  signForSharing(forged);
  const res = await share.POST(post("/api/share", { report: { ...forged, grade: "A+" } }, "192.0.2.1"));
  assert.equal(res.status, 403);
});

test("share: rejects oversized and malformed bodies", async () => {
  const big = await share.POST(post("/api/share", { report: report() }, "192.0.2.2", { "content-length": "2000000" }));
  assert.equal(big.status, 413);
  assert.equal((await share.POST(post("/api/share", "{", "192.0.2.2"))).status, 400);
  assert.equal((await share.POST(post("/api/share", { report: "x" }, "192.0.2.2"))).status, 400);
});
