import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { getSharedReport, shareScan, signForSharing } from "../src/lib/reports";
import { getStore } from "../src/lib/store";
import type { ScanReport } from "../src/lib/scanner/types";

// No Redis env vars + NODE_ENV != production -> in-memory store.
const fakeReport = (): ScanReport => ({
  id: randomUUID(), target: "https://example.com/", finalUrl: "https://example.com/", ip: null,
  scannedAt: new Date().toISOString(), durationMs: 1, grade: "B", score: 80,
  summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, findings: [], tls: null, redirectChain: [], responseHeaders: {},
});

/** What the browser sends back: the report after a JSON round trip. */
const roundTrip = (r: ScanReport) => JSON.parse(JSON.stringify(r)) as ScanReport;

test("dev uses the in-memory store", () => {
  assert.equal(getStore()?.kind, "memory");
});

test("a server-signed scan can be shared and read back", async () => {
  const report = fakeReport();
  assert.equal(signForSharing(report), true);
  assert.ok(report.shareToken);
  assert.equal(await getSharedReport(report.id), null, "nothing is stored until shared");

  const result = await shareScan(roundTrip(report));
  assert.equal(result.ok, true);
  const shared = await getSharedReport(report.id);
  assert.equal(shared?.grade, "B");
  assert.equal(shared?.shareToken, undefined, "the token is not published");
});

test("cannot share a report the server never signed (anti-forgery)", async () => {
  const unsigned = await shareScan(fakeReport());
  assert.equal(unsigned.ok ? 0 : unsigned.status, 403);

  const forged = fakeReport();
  signForSharing(forged);
  const tampered = { ...roundTrip(forged), grade: "F" as const };
  const result = await shareScan(tampered);
  assert.equal(result.ok ? 0 : result.status, 403);
  assert.equal(await getSharedReport(forged.id), null);
});

test("signed reports expire after an hour", async () => {
  const report = fakeReport();
  signForSharing(report);
  const result = await shareScan(roundTrip(report), Date.now() + 61 * 60_000);
  assert.equal(result.ok ? 0 : result.status, 410);
});

test("rejects malformed ids (no key injection)", async () => {
  for (const id of ["../../etc", "abc", "securescan:report:x", ""]) {
    const report = { ...fakeReport(), id };
    signForSharing(report);
    const result = await shareScan(report);
    assert.equal(result.ok ? 0 : result.status, 400, id);
    assert.equal(await getSharedReport(id), null);
  }
  for (const bad of [null, "x", 42, {}]) {
    const result = await shareScan(bad);
    assert.equal(result.ok ? 0 : result.status, 400);
  }
});

test("production without Redis disables sharing instead of using memory", () => {
  const env = process.env as Record<string, string | undefined>;
  const prev = env.NODE_ENV;
  env.NODE_ENV = "production";
  try {
    assert.equal(getStore(), null);
    assert.equal(signForSharing(fakeReport()), false);
  } finally {
    env.NODE_ENV = prev;
  }
});

test("Redis REST client speaks the Upstash protocol", async () => {
  const http = await import("node:http");
  const data = new Map<string, string>();
  const seen: unknown[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      assert.equal(req.headers.authorization, "Bearer test-token");
      const [cmd, key, value, ex, ttl] = JSON.parse(body) as string[];
      seen.push(cmd);
      res.setHeader("Content-Type", "application/json");
      if (cmd === "SET") { assert.equal(ex, "EX"); assert.ok(Number(ttl) > 0); data.set(key, value); return res.end(JSON.stringify({ result: "OK" })); }
      if (cmd === "GET") return res.end(JSON.stringify({ result: data.get(key) ?? null }));
      res.end(JSON.stringify({ error: "unknown command" }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as import("node:net").AddressInfo;
  process.env.KV_REST_API_URL = `http://127.0.0.1:${port}/`;
  process.env.KV_REST_API_TOKEN = "test-token";
  try {
    assert.equal(getStore()?.kind, "redis");
    const report = fakeReport();
    assert.equal(signForSharing(report), true);
    assert.deepEqual(seen, [], "signing a scan costs no Redis call");
    assert.equal((await shareScan(roundTrip(report))).ok, true);
    assert.equal((await getSharedReport(report.id))?.id, report.id);
    assert.deepEqual(seen, ["SET", "GET"]);
  } finally {
    delete process.env.KV_REST_API_URL;
    delete process.env.KV_REST_API_TOKEN;
    server.close();
  }
});
