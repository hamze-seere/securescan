/** Email breach check: providers, privacy rules, rate limits and the API route. */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { breachSource, BreachProviderError, lookupBreaches, maskEmail, normalizeEmail, type BreachResult } from "../src/lib/breach";
import { checkEmail, emailLimits, type EmailReport } from "../src/lib/emailCheck";
import type { DnsClient } from "../src/lib/scanner/dnsClient";

let route: typeof import("../src/app/api/email/route");
before(async () => {
  route = await import("../src/app/api/email/route");
});

/** A fake fetch that records requests and answers with the given status and body. */
function fakeFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string> });
    return new Response(body === undefined ? null : JSON.stringify(body), { status, headers });
  }) as typeof fetch;
  return { impl, calls };
}

const quietDns: DnsClient = {
  txt: async (n) => (n === "example.com" ? ["v=spf1 -all"] : n === "_dmarc.example.com" ? ["v=DMARC1; p=reject; rua=mailto:d@example.com"] : []),
  mx: async (n) => (n === "example.com" ? [{ exchange: "mx.example.com", priority: 10 }] : []),
  caa: async () => [],
  dnssec: async () => false,
};

const found: BreachResult = {
  source: "xposedornot",
  breaches: [{ name: "Example Breach", domain: "breached.example", date: "2019", dataTypes: ["Email addresses", "Passwords"] }],
  total: 1,
};

test("lookupBreaches: newest first, capped at 200 with the real total", async () => {
  const list = Array.from({ length: 250 }, (_, i) => ({ breach: `B${i}`, xposed_date: String(1990 + (i % 30)), xposed_data: "Email addresses" }));
  const r = await lookupBreaches("a@example.com", { env: {} as unknown as NodeJS.ProcessEnv, fetchImpl: fakeFetch(200, { ExposedBreaches: { breaches_details: list } }).impl });
  assert.equal(r.total, 250);
  assert.equal(r.breaches.length, 200);
  assert.equal(r.breaches[0].date, "2019");
  assert.equal(r.breaches.at(-1)!.date! >= "1990", true);
});

const env = (extra: Record<string, string> = {}) =>
  ({ EMAIL_RATE_LIMIT: "100", EMAIL_TARGET_RATE_LIMIT: "100", EMAIL_DAILY_LIMIT: "100000", ...extra }) as unknown as NodeJS.ProcessEnv;

let ipCounter = 0;
const nextIp = () => `198.51.100.${++ipCounter}`;

test("normalizeEmail accepts real addresses and rejects junk", () => {
  assert.deepEqual(normalizeEmail("  Hamze@Example.COM "), { email: "hamze@example.com", domain: "example.com" });
  assert.deepEqual(normalizeEmail("a.b+tag@mail.example.co.uk"), { email: "a.b+tag@mail.example.co.uk", domain: "mail.example.co.uk" });
  for (const bad of ["", "nobody", "a@b", "@example.com", "a@@example.com", ".a@example.com", "a.@example.com", "a..b@example.com", "a@-x.com", "a b@example.com", 42, null, "x".repeat(250) + "@example.com"]) {
    assert.equal(normalizeEmail(bad), null, String(bad));
  }
});

test("maskEmail never returns the full local part", () => {
  assert.equal(maskEmail("hamze@example.com"), "ha***@example.com");
  assert.equal(maskEmail("ab@example.com"), "a***@example.com");
  assert.equal(maskEmail("a@example.com"), "a***@example.com");
});

test("provider: XposedOrNot by default, HIBP when a key is set", () => {
  assert.equal(breachSource({} as unknown as NodeJS.ProcessEnv), "xposedornot");
  assert.equal(breachSource({ HIBP_API_KEY: "k" } as unknown as NodeJS.ProcessEnv), "hibp");
  assert.equal(emailLimits({} as unknown as NodeJS.ProcessEnv).perDay, 90);
  assert.equal(emailLimits({ HIBP_API_KEY: "k" } as unknown as NodeJS.ProcessEnv).perDay, 2000);
  assert.equal(emailLimits({ EMAIL_DAILY_LIMIT: "5" } as unknown as NodeJS.ProcessEnv).perDay, 5);
});

test("HIBP: sends the key and user agent, maps breaches", async () => {
  const f = fakeFetch(200, [{ Name: "Adobe", Title: "Adobe", Domain: "adobe.com", BreachDate: "2013-10-04", DataClasses: ["Email addresses", "Passwords"], Description: "<p>long text</p>" }]);
  const r = await lookupBreaches("a+b@example.com", { env: { HIBP_API_KEY: "secret" } as unknown as NodeJS.ProcessEnv, fetchImpl: f.impl });
  assert.equal(r.source, "hibp");
  assert.deepEqual(r.breaches, [{ name: "Adobe", domain: "adobe.com", date: "2013-10-04", dataTypes: ["Email addresses", "Passwords"] }]);
  assert.match(f.calls[0].url, /breachedaccount\/a%2Bb%40example\.com\?truncateResponse=false$/);
  assert.equal(f.calls[0].headers["hibp-api-key"], "secret");
  assert.match(f.calls[0].headers["user-agent"], /SecureScan/);
});

test("HIBP: 404 means no breaches, 429 and 401 are provider errors", async () => {
  const env = { HIBP_API_KEY: "k" } as unknown as NodeJS.ProcessEnv;
  assert.deepEqual((await lookupBreaches("a@example.com", { env, fetchImpl: fakeFetch(404, undefined).impl })).breaches, []);
  await assert.rejects(lookupBreaches("a@example.com", { env, fetchImpl: fakeFetch(429, {}, { "retry-after": "7" }).impl }), (e: unknown) => e instanceof BreachProviderError && e.retryAfter === 7);
  await assert.rejects(lookupBreaches("a@example.com", { env, fetchImpl: fakeFetch(401, {}).impl }), /configured/);
  await assert.rejects(lookupBreaches("a@example.com", { env, fetchImpl: fakeFetch(200, { not: "a list" }).impl }), BreachProviderError);
});

test("XposedOrNot: maps breaches, handles not-found and network failure", async () => {
  const f = fakeFetch(200, {
    ExposedBreaches: { breaches_details: [{ breach: "LinkedIn", domain: "linkedin.com", xposed_date: "2016", xposed_data: "Email addresses;Passwords", xposed_records: 1, password_risk: "hard" }] },
  });
  const r = await lookupBreaches("a@example.com", { env: {} as unknown as NodeJS.ProcessEnv, fetchImpl: f.impl });
  assert.equal(r.source, "xposedornot");
  assert.deepEqual(r.breaches, [{ name: "LinkedIn", domain: "linkedin.com", date: "2016", dataTypes: ["Email addresses", "Passwords"] }]);
  assert.match(f.calls[0].url, /^https:\/\/api\.xposedornot\.com\/v1\/breach-analytics\?email=a%40example\.com$/);

  assert.deepEqual((await lookupBreaches("a@example.com", { fetchImpl: fakeFetch(404, { Error: "Not found" }).impl, env: {} as unknown as NodeJS.ProcessEnv })).breaches, []);
  assert.deepEqual((await lookupBreaches("a@example.com", { fetchImpl: fakeFetch(200, { ExposedBreaches: null }).impl, env: {} as unknown as NodeJS.ProcessEnv })).breaches, []);
  const down = (async () => { throw new TypeError("fetch failed"); }) as typeof fetch;
  await assert.rejects(lookupBreaches("a@example.com", { fetchImpl: down, env: {} as unknown as NodeJS.ProcessEnv }), /didn't respond/);
});

test("checkEmail: rejects invalid addresses and missing consent", async () => {
  const lookup = async () => found;
  assert.equal((await checkEmail({ email: "nope", authorized: true }, nextIp(), { env: env(), lookup, dns: quietDns })).status, 400);
  const res = await checkEmail({ email: "a@example.com" }, nextIp(), { env: env(), lookup, dns: quietDns });
  assert.equal(res.status, 400);
  assert.match((res.body as { error: string }).error, /permission/);
  assert.equal((await checkEmail({ email: "a@example.com", authorized: "yes" }, nextIp(), { env: env(), lookup, dns: quietDns })).status, 400);
});

test("checkEmail: returns a masked address, breach summaries and domain findings", async () => {
  let looked = "";
  const res = await checkEmail({ email: "Hamze@Example.com", authorized: true }, nextIp(), {
    env: env(),
    lookup: async (e) => ((looked = e), found),
    dns: quietDns,
    now: () => Date.UTC(2026, 0, 1),
  });
  assert.equal(res.status, 200);
  const body = res.body as EmailReport;
  assert.equal(looked, "hamze@example.com", "provider gets the normalized address");
  assert.equal(body.email, "ha***@example.com");
  assert.equal(body.domain, "example.com");
  assert.equal(body.checkedAt, "2026-01-01T00:00:00.000Z");
  assert.equal(body.source.name, "XposedOrNot");
  assert.deepEqual(body.breaches, found.breaches);
  assert.equal(body.breachCount, 1);
  assert.ok(body.domainFindings.some((f) => f.id.includes("spf")), "SPF finding for the domain");
  assert.ok(body.domainFindings.every((f) => f.category === "email"));
  assert.ok(!JSON.stringify(body).includes("hamze@"), "full address never echoed");
});

test("checkEmail: per-IP limit", async () => {
  const ip = nextIp();
  const deps = { env: env({ EMAIL_RATE_LIMIT: "2" }), lookup: async () => found, dns: quietDns };
  assert.equal((await checkEmail({ email: "one@example.com", authorized: true }, ip, deps)).status, 200);
  assert.equal((await checkEmail({ email: "two@example.com", authorized: true }, ip, deps)).status, 200);
  const res = await checkEmail({ email: "three@example.com", authorized: true }, ip, deps);
  assert.equal(res.status, 429);
  assert.ok(Number(res.headers?.["Retry-After"]) > 0);
});

test("checkEmail: per-address limit applies across IPs and letter case", async () => {
  const deps = { env: env({ EMAIL_TARGET_RATE_LIMIT: "1" }), lookup: async () => found, dns: quietDns };
  assert.equal((await checkEmail({ email: "target@example.com", authorized: true }, nextIp(), deps)).status, 200);
  const res = await checkEmail({ email: "TARGET@example.com", authorized: true }, nextIp(), deps);
  assert.equal(res.status, 429);
  assert.match((res.body as { error: string }).error, /checked several times/);
});

test("checkEmail: site-wide daily cap", async () => {
  const res = await checkEmail({ email: "daily@example.com", authorized: true }, nextIp(), { env: env({ EMAIL_DAILY_LIMIT: "0" }), lookup: async () => found, dns: quietDns });
  assert.equal(res.status, 429);
  assert.match((res.body as { error: string }).error, /daily limit/);
});

test("checkEmail: provider errors become 503 and never log the address", async () => {
  const busy = await checkEmail({ email: "busy@example.com", authorized: true }, nextIp(), {
    env: env(),
    lookup: async () => { throw new BreachProviderError("The breach database is busy right now.", 30); },
    dns: quietDns,
  });
  assert.equal(busy.status, 503);
  assert.equal(busy.headers?.["Retry-After"], "30");

  const logged: string[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
  try {
    const res = await checkEmail({ email: "secret.person@example.com", authorized: true }, nextIp(), {
      env: env(),
      lookup: async (e) => { throw new Error(`boom for ${e}`); },
      dns: quietDns,
    });
    assert.equal(res.status, 500);
  } finally {
    console.error = original;
  }
  assert.ok(logged.length > 0);
  assert.ok(logged.every((l) => !l.includes("secret.person")), "address must not reach the logs");
});

test("checkEmail: slow DNS doesn't block the breach result", async () => {
  const slowDns: DnsClient = { txt: () => new Promise(() => {}), mx: () => new Promise(() => {}), caa: async () => [], dnssec: async () => false };
  // The fallback timer is unref'd (so it never holds a serverless function open), and the fake DNS
  // never settles, so keep the event loop alive ourselves or Node exits mid-test.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    const res = await checkEmail({ email: "slow@example.com", authorized: true }, nextIp(), {
      env: env(),
      lookup: async () => found,
      dns: slowDns,
      domainTimeoutMs: 50,
    });
    assert.equal(res.status, 200);
    assert.deepEqual((res.body as EmailReport).domainFindings, []);
  } finally {
    clearInterval(keepAlive);
  }
});

const post = (body: string, headers: Record<string, string> = {}) =>
  new NextRequest("http://localhost/api/email", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": nextIp(), ...headers },
    body,
  });

test("route: content type, size, JSON and method guards", async () => {
  assert.equal((await route.POST(post("email=a@example.com", { "content-type": "application/x-www-form-urlencoded" }))).status, 415);
  assert.equal((await route.POST(post("{}", { "content-length": "5000" }))).status, 413);
  assert.equal((await route.POST(post("{not json"))).status, 400);
  const bad = await route.POST(post(JSON.stringify({ email: "nope", authorized: true })));
  assert.equal(bad.status, 400);
  assert.equal(bad.headers.get("cache-control"), "no-store");
  const get = route.GET();
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
});
