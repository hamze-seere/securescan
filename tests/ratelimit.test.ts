import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { clientIp, memoryRateLimit, rateLimit } from "../src/lib/rateLimit";

test("memory limiter allows `limit` hits per window, then reports when to retry", () => {
  const key = `mem-${Math.random()}`;
  for (let i = 0; i < 3; i++) assert.equal(memoryRateLimit(key, 3).ok, true);
  const blocked = memoryRateLimit(key, 3);
  assert.equal(blocked.ok, false);
  assert.ok(blocked.retryAfter > 0 && blocked.retryAfter <= 60);
  assert.equal(memoryRateLimit(`${key}-other`, 3).ok, true, "keys are independent");
});

test("clientIp takes the first x-forwarded-for entry", () => {
  assert.equal(clientIp(new Headers({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" })), "203.0.113.7");
  assert.equal(clientIp(new Headers({ "x-real-ip": "198.51.100.2" })), "198.51.100.2");
  assert.equal(clientIp(new Headers()), "unknown");
});

test("with Redis configured, counts are shared through one pipeline call per hit", async () => {
  const counts = new Map<string, number>();
  const bodies: unknown[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      assert.equal(req.url, "/pipeline");
      const cmds = JSON.parse(body) as (string | number)[][];
      bodies.push(cmds);
      const key = String(cmds[0][1]);
      counts.set(key, (counts.get(key) ?? 0) + 1);
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ result: counts.get(key) }, { result: 1 }, { result: 42 }]));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  process.env.KV_REST_API_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  process.env.KV_REST_API_TOKEN = "t";
  try {
    assert.equal((await rateLimit("ip", 2)).remaining, 1);
    assert.equal((await rateLimit("ip", 2)).ok, true);
    const blocked = await rateLimit("ip", 2);
    assert.deepEqual(blocked, { ok: false, retryAfter: 42, remaining: 0 });
    assert.deepEqual(bodies[0], [["INCR", "securescan:rl:ip"], ["EXPIRE", "securescan:rl:ip", 60, "NX"], ["TTL", "securescan:rl:ip"]]);
  } finally {
    server.close();
  }
  // Redis down: fall back to the in-memory limiter instead of failing open or erroring.
  const original = console.error;
  console.error = () => {};
  try {
    assert.equal((await rateLimit(`down-${Math.random()}`, 1)).ok, true);
  } finally {
    console.error = original;
    delete process.env.KV_REST_API_URL;
    delete process.env.KV_REST_API_TOKEN;
  }
});
