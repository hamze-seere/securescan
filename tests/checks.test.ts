import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCsp, checkHsts, checkFraming, checkReferrerPolicy, runHeaderChecks } from "../src/lib/scanner/checks/headers";
import { parseSetCookie, runCookieChecks } from "../src/lib/scanner/checks/cookies";
import { runDisclosureChecks } from "../src/lib/scanner/checks/disclosure";
import { PROBES, runExposureChecks } from "../src/lib/scanner/checks/exposure";
import { runContentChecks } from "../src/lib/scanner/checks/content";
import { PROBE_ORIGIN, runCorsCheck } from "../src/lib/scanner/checks/cors";
import { computeGrade, computeScore } from "../src/lib/scanner/score";
import type { HttpResponseData } from "../src/lib/scanner/types";

const res = (over: Partial<HttpResponseData>): HttpResponseData => ({
  url: "https://example.com/", status: 200, headers: {}, body: "", remoteAddress: null, tls: null, ...over,
});

test("HSTS: missing fails, short max-age warns, long passes", () => {
  assert.equal(checkHsts({}, true).status, "fail");
  assert.equal(checkHsts({ "strict-transport-security": "max-age=300" }, true).status, "warn");
  assert.equal(checkHsts({ "strict-transport-security": "max-age=63072000; includeSubDomains" }, true).status, "pass");
  assert.equal(checkHsts({}, false).status, "info");
});

test("CSP: detects unsafe-inline, allows nonce + strict-dynamic", () => {
  assert.equal(checkCsp({}).status, "fail");
  assert.equal(checkCsp({ "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'" }).status, "warn");
  assert.equal(checkCsp({ "content-security-policy": "default-src *" }).status, "warn");
  assert.equal(
    checkCsp({ "content-security-policy": "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'" }).status,
    "pass",
  );
});

test("Clickjacking: XFO or frame-ancestors", () => {
  assert.equal(checkFraming({}).status, "fail");
  assert.equal(checkFraming({ "x-frame-options": "DENY" }).status, "pass");
  assert.equal(checkFraming({ "content-security-policy": "frame-ancestors 'self'" }).status, "pass");
  assert.equal(checkFraming({ "content-security-policy": "frame-ancestors *" }).status, "fail");
});

test("Referrer-Policy: last token wins", () => {
  assert.equal(checkReferrerPolicy({ "referrer-policy": "unsafe-url" }).status, "fail");
  assert.equal(checkReferrerPolicy({ "referrer-policy": "unsafe-url, strict-origin-when-cross-origin" }).status, "pass");
});

test("Cookies: flags parsed and session cookies judged strictly", () => {
  const c = parseSetCookie("PHPSESSID=abc; path=/; HttpOnly; SameSite=Lax");
  assert.deepEqual(c, { name: "PHPSESSID", secure: false, httpOnly: true, sameSite: "lax" });

  const [bad] = runCookieChecks({ "set-cookie": ["session=1; Path=/"] }, true);
  assert.equal(bad.status, "fail");
  const [good] = runCookieChecks({ "set-cookie": ["session=1; Path=/; Secure; HttpOnly; SameSite=Strict"] }, true);
  assert.equal(good.status, "pass");
  const [csrf] = runCookieChecks({ "set-cookie": ["XSRF-TOKEN=1; Secure; SameSite=Lax"] }, true);
  assert.equal(csrf.status, "pass", "CSRF cookies may be readable by JS");
});

test("Disclosure: versioned Server header and X-Powered-By", () => {
  const f = runDisclosureChecks({ server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3" });
  assert.deepEqual(f.map((x) => x.id), ["server-version", "tech-headers"]);
  assert.equal(runDisclosureChecks({ server: "cloudflare" })[0].status, "pass");
});

test("Exposure: content signatures avoid soft-404 false positives", async () => {
  // A site that returns the same HTML page with 200 for every path
  const soft404 = await runExposureChecks(async () => res({ headers: { "content-type": "text/html" }, body: "<html><title>Not found</title></html>" }));
  assert.equal(soft404[0].status, "pass");

  const leaky = await runExposureChecks(async (path) =>
    path === "/.env"
      ? res({ headers: { "content-type": "text/plain" }, body: "APP_KEY=base64:xyz\nDB_PASSWORD=secret\n" })
      : res({ status: 404 }),
  );
  assert.equal(leaky.length, 1);
  assert.equal(leaky[0].severity, "critical");
  assert.ok(PROBES.find((p) => p.path === "/.git/HEAD")!.matches("ref: refs/heads/main\n", "text/plain"));
});

test("Mixed content: active vs passive", () => {
  const html = `<script src="http://cdn.example/x.js"></script><img src="http://img.example/a.png"><link rel="stylesheet" href="http://x/s.css"><form action="http://example.com/login">`;
  const ids = runContentChecks(html, true, { "content-type": "text/html" }).map((f) => f.id);
  assert.deepEqual(ids.sort(), ["insecure-form", "mixed-active", "mixed-passive"]);
  assert.equal(runContentChecks(`<script src="https://ok/x.js"></script>`, true, { "content-type": "text/html" })[0].status, "pass");
});

test("CORS: reflected origin with credentials is high severity", () => {
  const f = runCorsCheck(res({ headers: { "access-control-allow-origin": PROBE_ORIGIN, "access-control-allow-credentials": "true" } }));
  assert.equal(f.status, "fail");
  assert.equal(f.severity, "high");
  assert.equal(runCorsCheck(res({ headers: { "access-control-allow-origin": "*" } })).status, "info");
  assert.equal(runCorsCheck(res({})).status, "pass");
});

test("Scoring: perfect headers earn A+, critical failure forces F", () => {
  const strong = runHeaderChecks({
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
  }, true);
  const s = computeScore(strong);
  assert.equal(s, 100);
  assert.equal(computeGrade(strong, s), "A+");

  const withCritical = [...strong, { id: "x", category: "exposure" as const, title: "", status: "fail" as const, severity: "critical" as const, description: "" }];
  assert.equal(computeGrade(withCritical, computeScore(withCritical)), "F");
});
