import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCsp, checkFraming, checkHsts, metaCspPolicies } from "../src/lib/scanner/checks/headers";
import { runCookieChecks } from "../src/lib/scanner/checks/cookies";
import { runDisclosureChecks } from "../src/lib/scanner/checks/disclosure";
import { PROBES, SOFT_404_PATH, checkSecurityTxt, runExposureChecks } from "../src/lib/scanner/checks/exposure";
import { missingSri, runContentChecks } from "../src/lib/scanner/checks/content";
import { corsProbes, runCorsCheck } from "../src/lib/scanner/checks/cors";
import { categoryScores, computeScore } from "../src/lib/scanner/score";
import type { Finding, HttpResponseData } from "../src/lib/scanner/types";

const res = (over: Partial<HttpResponseData>): HttpResponseData => ({
  url: "https://example.com/", status: 200, headers: {}, body: "", remoteAddress: null, tls: null, ...over,
});
const html = { "content-type": "text/html; charset=utf-8" };

test("CSP: with two enforced policies only weaknesses common to both count", () => {
  const strictPlusLoose = checkCsp({
    "content-security-policy": ["script-src 'unsafe-inline' *", "default-src 'self'; object-src 'none'; base-uri 'none'"],
  });
  assert.equal(strictPlusLoose.status, "pass", strictPlusLoose.description);
  const bothLoose = checkCsp({ "content-security-policy": ["script-src 'unsafe-inline'", "default-src 'unsafe-inline'"] });
  assert.equal(bothLoose.status, "warn");
  assert.equal(bothLoose.severity, "high");
});

test("CSP: a <meta> policy counts, but cannot provide frame-ancestors", () => {
  const page = `<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; object-src 'none'; frame-ancestors 'none'"></head>`;
  assert.deepEqual(metaCspPolicies(page), ["default-src 'self'; object-src 'none'; frame-ancestors 'none'"]);
  const csp = checkCsp({}, page);
  assert.equal(csp.status, "pass");
  assert.match(csp.evidence ?? "", /<meta>/);
  assert.equal(checkFraming({}).status, "fail", "frame-ancestors in <meta> is ignored by browsers");
});

test("CSP: unsafe-eval and missing object-src are only minor", () => {
  const f = checkCsp({ "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'" });
  assert.equal(f.status, "warn");
  assert.equal(f.severity, "low");
});

test("HSTS: preload flag without the preload requirements warns", () => {
  assert.equal(checkHsts({ "strict-transport-security": "max-age=63072000; preload" }, true).status, "warn");
  const ok = checkHsts({ "strict-transport-security": "max-age=63072000; includeSubDomains; preload" }, true);
  assert.equal(ok.status, "pass");
  assert.match(ok.description, /preload/i);
});

test("Disclosure: only real version numbers count", () => {
  assert.equal(runDisclosureChecks({ server: "nginx/1.25.3" })[0].status, "warn");
  assert.equal(runDisclosureChecks({ server: "Microsoft-IIS/10.0" })[0].status, "warn");
  assert.equal(runDisclosureChecks({ server: "AmazonS3" })[0].status, "pass");
  assert.equal(runDisclosureChecks({ server: "cloudflare" })[0].status, "pass");
  assert.ok(!runDisclosureChecks({ "x-runtime": "0.012" }).some((f) => f.status !== "pass"), "x-runtime is a timing, not a version");
});

test("Cookies: prefixes, duplicates and redirect-hop cookies", () => {
  const [host] = runCookieChecks({ "set-cookie": ["__Host-session=1; Path=/; Secure; HttpOnly; SameSite=Lax"] }, true);
  assert.equal(host.status, "pass");
  assert.match(host.description, /__Host-/);

  // The same cookie set twice: the later value is what the browser keeps.
  const dup = runCookieChecks({ "set-cookie": ["session=1", "session=2; Secure; HttpOnly; SameSite=Lax"] }, true);
  assert.equal(dup.length, 1);
  assert.equal(dup[0].status, "pass");

  const hop = runCookieChecks({}, true, ["sid=1; Path=/"]);
  assert.equal(hop.length, 1);
  assert.equal(hop[0].status, "fail");

  // A non-session cookie missing only SameSite is a low warning, not a failure.
  const [pref] = runCookieChecks({ "set-cookie": ["theme=dark; Secure"] }, true);
  assert.equal(pref.status, "warn");
  assert.equal(pref.severity, "low");
});

test("Cookies: twenty bad cookies cost at most the category cap", () => {
  const many = runCookieChecks({ "set-cookie": Array.from({ length: 20 }, (_, i) => `session${i}=1`) }, true);
  assert.equal(many.length, 20);
  assert.equal(computeScore(many), 80);
});

test("CORS: null origin and unanchored allow-lists are caught", () => {
  const probes = corsProbes("www.shop.com");
  assert.equal(probes.length, 4);
  assert.ok(probes.some((p) => p.origin === "https://shop.com.securescan-probe.example"));
  assert.ok(probes.some((p) => p.origin === "https://securescanprobeshop.com"));

  const nullOrigin = runCorsCheck(probes.map((probe) => ({
    probe, res: res({ headers: probe.origin === "null" ? { "access-control-allow-origin": "null", "access-control-allow-credentials": "true" } : {} }),
  })));
  assert.equal(nullOrigin.status, "fail");
  assert.equal(nullOrigin.severity, "high");

  const suffix = runCorsCheck(probes.map((probe) => ({
    probe, res: res({ headers: probe.origin.endsWith("shop.com") ? { "access-control-allow-origin": probe.origin } : {} }),
  })));
  assert.equal(suffix.status, "fail");
  assert.equal(suffix.severity, "medium");
  assert.match(suffix.description, /end with/);
});

test("CORS: a per-request origin without Vary: Origin warns", () => {
  const probes = corsProbes("shop.com");
  const results = probes.map((probe, i) => ({
    probe, res: res({ headers: { "access-control-allow-origin": i % 2 ? "https://a.shop.com" : "https://b.shop.com" } }),
  }));
  assert.equal(runCorsCheck(results).status, "warn");
  const withVary = results.map(({ probe, res: r }) => ({ probe, res: { ...r, headers: { ...r.headers, vary: "Accept-Encoding, Origin" } } }));
  assert.equal(runCorsCheck(withVary).status, "pass");
});

test("Mixed content: srcset, comments and upgrade-insecure-requests", () => {
  const ids = (page: string, headers: Record<string, string> = html) => runContentChecks(page, true, headers).map((f) => f.id);
  assert.deepEqual(ids(`<img srcset="https://ok/a.png 1x, http://bad/a@2x.png 2x">`), ["mixed-passive"]);
  assert.deepEqual(ids(`<!-- <script src="http://old/x.js"></script> -->`), ["mixed-ok"]);

  const upgraded = runContentChecks(`<script src="http://cdn/x.js"></script><img src="http://img/a.png">`, true,
    { ...html, "content-security-policy": "upgrade-insecure-requests" });
  assert.deepEqual(upgraded.map((f) => [f.id, f.status]), [["mixed-active", "info"]]);
  // Forms are not covered by the upgrade.
  assert.ok(ids(`<form action="http://x/login">`, { ...html, "content-security-policy": "upgrade-insecure-requests" }).includes("insecure-form"));
  // Non-HTML responses are not inspected.
  assert.deepEqual(runContentChecks(`<script src="http://x/a.js">`, true, { "content-type": "application/json" }), []);
});

test("SRI: CDN files without integrity warn, analytics are informational", () => {
  const page = `
    <script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/x.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/a/1/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>
    <script src="/local.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/css@2/s.css">`;
  const missing = missingSri(page, "https://example.com/");
  assert.deepEqual(missing.map((m) => m.url).sort(), ["https://cdn.jsdelivr.net/npm/lib@1.0.0/x.js", "https://unpkg.com/css@2/s.css"]);
  const sri = runContentChecks(page, true, html, "https://example.com/").find((f) => f.id === "sri")!;
  assert.equal(sri.status, "warn");
  assert.equal(sri.severity, "medium");

  const analytics = runContentChecks(`<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>`, true, html, "https://example.com/")
    .find((f) => f.id === "sri")!;
  assert.equal(analytics.status, "info");
});

test("Exposure: new probes match their real formats", () => {
  const probe = (path: string) => PROBES.find((p) => p.path === path)!;
  assert.ok(probe("/.git/index").matches("DIRC\u0000\u0000\u0000\u0002", "application/octet-stream"));
  assert.ok(probe("/.DS_Store").matches("\u0000\u0000\u0000\u0001Bud1\u0000", "application/octet-stream"));
  assert.ok(!probe("/.DS_Store").matches("<p>Bud1 is a band</p>", "text/html"));
  assert.ok(probe("/backup.zip").matches("PK\u0003\u0004rest", "application/zip"));
  assert.ok(probe("/.htpasswd").matches("admin:$apr1$abc$def\n", "text/plain"));
  assert.ok(probe("/.aws/credentials").matches("[default]\naws_access_key_id = AKIA\n", "text/plain"));
  assert.ok(probe("/actuator/env").matches(`{"activeProfiles":[],"propertySources":[]}`, "application/json"));
  assert.ok(probe("/docker-compose.yml").matches("services:\n  db:\n    image: postgres\n", "text/yaml"));
});

test("Exposure: a site that answers every path with the same text is a soft 404", async () => {
  const seen: string[] = [];
  const findings = await runExposureChecks(async (path) => {
    seen.push(path);
    return res({ headers: { "content-type": "text/plain" }, body: "NOT_FOUND=true\n" });
  });
  assert.ok(seen.includes(SOFT_404_PATH));
  assert.equal(findings[0].id, "exposure-ok");
});

test("security.txt: placeholder, missing or past Expires, HTML pages", () => {
  const now = new Date("2026-10-31T00:00:00Z");
  const txt = (body: string, url = "https://example.com/.well-known/security.txt") =>
    checkSecurityTxt(res({ url, headers: { "content-type": "text/plain" }, body }), now);

  assert.equal(txt("Contact: mailto:security@shop.com\nExpires: 2027-06-01T00:00:00Z\n").status, "pass");
  assert.equal(txt("Contact: mailto:security@shop.com\n").status, "warn");
  const expired = txt("Contact: mailto:security@shop.com\nExpires: 2025-01-01T00:00:00Z\n");
  assert.equal(expired.status, "warn");
  assert.match(expired.description, /2025-01-01/);
  assert.equal(txt("Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00Z\n").status, "warn");
  assert.match(txt("Contact: https://shop.com/report\nExpires: 2027-06-01T00:00:00Z\n", "https://shop.com/security.txt").description, /RFC 9116/);
  assert.equal(checkSecurityTxt(res({ headers: html, body: "<p>Contact: us</p>" }), now).status, "info");
});

test("Category scores show where points were lost", () => {
  const f = (category: Finding["category"], status: Finding["status"], severity: Finding["severity"]): Finding =>
    ({ id: `${category}-${status}-${severity}`, category, title: "", description: "", status, severity });
  const scores = categoryScores([f("headers", "pass", "high"), f("headers", "fail", "high"), f("cors", "pass", "high"), f("dns", "info", "info")]);
  const headers = scores.find((s) => s.category === "headers")!;
  assert.deepEqual(headers, { category: "headers", score: 50, pointsLost: 15, issues: 1 });
  assert.equal(scores.find((s) => s.category === "cors")!.score, 100);
  assert.equal(scores.find((s) => s.category === "dns"), undefined, "info-only categories have nothing to score");
});
