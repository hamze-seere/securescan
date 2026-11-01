/** Email insights: new mail checks, address type, provider, domain age, risk summary and owner verification. */
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { checkBimi, checkMtaSts, checkTlsRpt, runEmailChecks } from "../src/lib/scanner/checks/email";
import { cachedDns, classifyAddress, domainAge, mailProvider, riskSummary } from "../src/lib/emailInsights";
import { buildReport, gravatarProfile, lockDownSteps, verifyConfig, verifyEmail, type ExposureReport } from "../src/lib/exposure";
import { checkEmail, type EmailReport } from "../src/lib/emailCheck";
import type { Breach, BreachResult } from "../src/lib/breach";
import type { DnsClient } from "../src/lib/scanner/dnsClient";
import type { KeyValueStore } from "../src/lib/store";

let route: typeof import("../src/app/api/email/verify/route");
before(async () => {
  route = await import("../src/app/api/email/verify/route");
});

const env = (extra: Record<string, string> = {}) =>
  ({ EMAIL_RATE_LIMIT: "100", EMAIL_TARGET_RATE_LIMIT: "100", EMAIL_DAILY_LIMIT: "100000", EMAIL_VERIFY_RATE_LIMIT: "100",
    EMAIL_VERIFY_TARGET_RATE_LIMIT: "100", EMAIL_VERIFY_DAILY_LIMIT: "100000", ...extra }) as unknown as NodeJS.ProcessEnv;
const devEnv = (extra: Record<string, string> = {}) => env({ EMAIL_VERIFY_DEV_BYPASS: "true", NODE_ENV: "development", ...extra });

let ipCounter = 0;
const nextIp = () => `203.0.113.${++ipCounter}`;

function memStore(): KeyValueStore & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return { kind: "memory", data, get: async (k) => data.get(k) ?? null, set: async (k, v) => void data.set(k, v) };
}

/** A fake fetch answering by URL prefix. */
function routes(table: Record<string, () => Response>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    const key = Object.keys(table).find((k) => String(url).startsWith(k));
    if (!key) throw new Error(`unexpected fetch ${url}`);
    return table[key]();
  }) as typeof fetch;
  return { impl, calls };
}
const jsonRes = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const b = (name: string, date: string, dataTypes: string[]): Breach => ({ name, domain: null, date, dataTypes });
const NOW = Date.parse("2026-11-01T00:00:00Z");

// ---------- New mail checks ----------

test("MTA-STS: missing, valid, missing id, duplicates", () => {
  assert.equal(checkMtaSts("x.com", [], true).status, "info");
  assert.match(checkMtaSts("x.com", [], true).recommendation!, /mta-sts\.x\.com/);
  assert.equal(checkMtaSts("x.com", ["v=STSv1; id=2026"], true).status, "pass");
  assert.equal(checkMtaSts("x.com", ["v=STSv1;"], true).status, "warn");
  assert.equal(checkMtaSts("x.com", ["v=STSv1; id=1", "v=STSv1; id=2"], true).status, "warn");
  assert.equal(checkMtaSts("x.com", [], false).recommendation, undefined);
});

test("TLS-RPT: needs a mailto: or https: rua", () => {
  assert.equal(checkTlsRpt("x.com", [], true).status, "info");
  assert.equal(checkTlsRpt("x.com", ["v=TLSRPTv1; rua=mailto:tls@x.com"], true).status, "pass");
  assert.equal(checkTlsRpt("x.com", ["v=TLSRPTv1; rua=https://r.x.com/tls"], true).status, "pass");
  assert.equal(checkTlsRpt("x.com", ["v=TLSRPTv1;"], true).status, "warn");
});

test("BIMI: only counts with an enforcing DMARC policy and an https logo", () => {
  assert.equal(checkBimi("x.com", [], true).status, "info");
  assert.equal(checkBimi("x.com", ["v=BIMI1; l=https://x.com/logo.svg"], true).status, "pass");
  assert.equal(checkBimi("x.com", ["v=BIMI1; l=https://x.com/logo.svg"], false).status, "warn");
  assert.equal(checkBimi("x.com", ["v=BIMI1; l=http://x.com/logo.svg"], true).status, "warn");
});

test("runEmailChecks now returns MTA-STS, TLS-RPT and BIMI too", async () => {
  const zone: Record<string, string[]> = {
    "x.com": ["v=spf1 -all"],
    "_dmarc.x.com": ["v=DMARC1; p=reject"],
    "_mta-sts.x.com": ["v=STSv1; id=1"],
    "_smtp._tls.x.com": ["v=TLSRPTv1; rua=mailto:t@x.com"],
    "default._bimi.x.com": ["v=BIMI1; l=https://x.com/l.svg"],
  };
  const dns: DnsClient = { txt: async (n) => zone[n] ?? [], mx: async () => [{ exchange: "mx.x.com", priority: 1 }], caa: async () => [], dnssec: async () => false };
  const findings = await runEmailChecks("x.com", dns);
  assert.deepEqual(findings.map((f) => f.id), ["mx", "spf", "dmarc", "dkim", "mta-sts", "tls-rpt", "bimi"]);
  assert.ok(findings.filter((f) => ["mta-sts", "tls-rpt", "bimi"].includes(f.id)).every((f) => f.status === "pass"));
});

// ---------- Address type and provider ----------

test("classifyAddress: disposable, free webmail, custom, role and plus tags", () => {
  assert.equal(classifyAddress("x@mailinator.com").kind, "disposable");
  assert.equal(classifyAddress("x@gmail.com").kind, "free");
  assert.equal(classifyAddress("x@acme.co.uk").kind, "custom");
  assert.equal(classifyAddress("support@acme.com").role, true);
  assert.equal(classifyAddress("support+eu@acme.com").role, true);
  assert.equal(classifyAddress("hamze@acme.com").role, false);
  assert.equal(classifyAddress("hamze+shop@gmail.com").plusTag, true);
  assert.equal(classifyAddress("hamze@gmail.com").plusTag, false);
});

test("mailProvider names the host from the preferred MX", () => {
  assert.equal(mailProvider([{ exchange: "alt1.aspmx.l.google.com", priority: 5 }, { exchange: "aspmx.l.google.com", priority: 1 }]), "Google Workspace / Gmail");
  assert.equal(mailProvider([{ exchange: "acme-com.mail.protection.outlook.com", priority: 0 }]), "Microsoft 365 / Outlook");
  assert.equal(mailProvider([{ exchange: "mail.protonmail.ch.", priority: 10 }]), "Proton Mail");
  assert.equal(mailProvider([{ exchange: "route1.mx.cloudflare.net", priority: 1 }]), "Cloudflare Email Routing");
  assert.equal(mailProvider([{ exchange: "mail.acme.com", priority: 1 }]), "Self-hosted or other provider");
  assert.equal(mailProvider([]), null);
});

test("cachedDns asks each question once", async () => {
  let asked = 0;
  const dns = cachedDns({ txt: async () => (asked++, ["a"]), mx: async () => [], caa: async () => [], dnssec: async () => false });
  await Promise.all([dns.txt("x.com"), dns.txt("x.com"), dns.txt("x.com")]);
  await dns.txt("y.com");
  assert.equal(asked, 2);
});

// ---------- Domain age ----------

beforeEach(() => {
  const g = globalThis as Record<string, unknown>;
  delete g.__securescanRdapBootstrap;
  delete g.__securescanRdapAges;
});

test("domainAge: IANA bootstrap, then the registry's RDAP server, cached", async () => {
  const f = routes({
    "https://data.iana.org/rdap/dns.json": () => jsonRes({ services: [[["com", "net"], ["https://rdap.example-registry.com/v1/"]]] }),
    "https://rdap.example-registry.com/v1/domain/acme.com": () => jsonRes({ events: [{ eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" }, { eventAction: "registration", eventDate: "2026-10-01T00:00:00Z" }] }),
  });
  const age = await domainAge("mail.acme.com", { fetchImpl: f.impl, now: NOW });
  assert.deepEqual(age, { domain: "acme.com", registered: "2026-10-01", days: 31 });
  await domainAge("acme.com", { fetchImpl: f.impl, now: NOW });
  assert.equal(f.calls.length, 2, "second lookup comes from the cache");
});

test("domainAge: null when the TLD has no RDAP service or the registry fails", async () => {
  const f = routes({
    "https://data.iana.org/rdap/dns.json": () => jsonRes({ services: [[["com"], ["https://rdap.example-registry.com/v1/"]]] }),
    "https://rdap.example-registry.com/": () => new Response("nope", { status: 500 }),
  });
  assert.equal(await domainAge("uni.edu.so", { fetchImpl: f.impl, now: NOW }), null);
  assert.equal(await domainAge("broken.com", { fetchImpl: f.impl, now: NOW }), null);
  const down = routes({});
  delete (globalThis as Record<string, unknown>).__securescanRdapBootstrap;
  assert.equal(await domainAge("other.com", { fetchImpl: down.impl, now: NOW }), null, "network errors don't throw");
});

// ---------- Risk summary ----------

test("riskSummary: levels, counts, timeline and top data types", () => {
  assert.equal(riskSummary([], NOW).level, "none");
  assert.equal(riskSummary([b("A", "2015", ["Email addresses"])], NOW).level, "low");
  assert.equal(riskSummary([b("A", "2015", ["Passwords"])], NOW).level, "medium");
  assert.equal(riskSummary([b("A", "2024-05-01", ["Passwords"])], NOW).level, "high", "recent password leak");
  const list = [
    b("New", "2025-02-01", ["Email addresses", "Phone numbers", "Names"]),
    b("Mid", "2019", ["Email addresses", "Passwords", "Physical addresses"]),
    b("Old", "2019", ["Email addresses", "Phone numbers"]),
  ];
  const r = riskSummary(list, NOW);
  assert.equal(r.level, "medium");
  assert.equal(r.passwordLeaks, 1);
  assert.equal(r.phoneLeaks, 2);
  assert.equal(r.addressLeaks, 1);
  assert.equal(r.mostRecent?.name, "New");
  assert.deepEqual(r.byYear, [{ year: "2019", count: 2 }, { year: "2025", count: 1 }]);
  assert.deepEqual(r.dataTypes[0], { type: "Email addresses", count: 3 });
  assert.deepEqual(r.dataTypes[1], { type: "Phone numbers", count: 2 });
});

test("checkEmail includes the address info, risk summary and verify flag", async () => {
  const dns: DnsClient = { txt: async () => [], mx: async (n) => (n === "acme.com" ? [{ exchange: "aspmx.l.google.com", priority: 1 }] : []), caa: async () => [], dnssec: async () => false };
  const lookup = async (): Promise<BreachResult> => ({ source: "xposedornot", breaches: [b("A", "2025", ["Passwords", "Phone numbers"])], total: 1 });
  const res = await checkEmail({ email: "Me+news@acme.com", authorized: true }, nextIp(), {
    env: env(), lookup, dns, now: () => NOW,
    domainAge: async (d) => ({ domain: d, registered: "2001-01-01", days: 9000 }),
  });
  assert.equal(res.status, 200);
  const r = res.body as EmailReport;
  assert.deepEqual(r.address, { kind: "custom", role: false, plusTag: true, provider: "Google Workspace / Gmail", domainAge: { domain: "acme.com", registered: "2001-01-01", days: 9000 } });
  assert.equal(r.risk.level, "high");
  assert.equal(r.risk.phoneLeaks, 1);
  assert.equal(r.domainFindings.length, 7);
  assert.equal(r.verifyAvailable, false, "no Resend key and no dev bypass");
});

test("checkEmail skips the registry lookup for free webmail", async () => {
  let asked = false;
  const res = await checkEmail({ email: "me@gmail.com", authorized: true }, nextIp(), {
    env: env(), lookup: async () => ({ source: "xposedornot", breaches: [], total: 0 }),
    dns: { txt: async () => [], mx: async () => [], caa: async () => [], dnssec: async () => false },
    domainAge: async () => { asked = true; return null; },
  });
  assert.equal((res.body as EmailReport).address.kind, "free");
  assert.equal(asked, false);
});

// ---------- Gravatar ----------

const GRAVATAR_HASH = "8c2a47d3bdb8d3096a6479f53eac3b724291db5f1c31611100f675be5537329d"; // sha256("me@example.com")

test("gravatarProfile: profile fields, avatar as a data URL, hidden and non-https links dropped", async () => {
  const f = routes({
    [`https://api.gravatar.com/v3/profiles/${GRAVATAR_HASH}`]: () => jsonRes({
      display_name: "Hamze", location: "Hargeisa", profile_url: "https://gravatar.com/hamze", job_title: "Engineer",
      verified_accounts: [
        { service_label: "GitHub", url: "https://github.com/hamze" },
        { service_label: "Hidden", url: "https://example.com/h", is_hidden: true },
        { service_label: "Bad", url: "javascript:alert(1)" },
      ],
    }),
    [`https://gravatar.com/avatar/${GRAVATAR_HASH}`]: () => new Response(new Uint8Array([1, 2, 3]), { headers: { "content-type": "image/png" } }),
  });
  const p = await gravatarProfile(" Me@Example.com ", f.impl);
  assert.equal(p?.displayName, "Hamze");
  assert.equal(p?.jobTitle, "Engineer");
  assert.equal(p?.avatar, "data:image/png;base64,AQID");
  assert.deepEqual(p?.accounts, [{ service: "GitHub", url: "https://github.com/hamze" }]);
});

test("gravatarProfile: null with no profile and no photo; SVG avatars refused", async () => {
  const none = routes({ "https://api.gravatar.com/": () => new Response("{}", { status: 404 }), "https://gravatar.com/avatar/": () => new Response("", { status: 404 }) });
  assert.equal(await gravatarProfile("me@example.com", none.impl), null);
  const svg = routes({
    "https://api.gravatar.com/": () => jsonRes({ display_name: "X" }),
    "https://gravatar.com/avatar/": () => new Response("<svg/>", { headers: { "content-type": "image/svg+xml" } }),
  });
  assert.equal((await gravatarProfile("me@example.com", svg.impl))?.avatar, null);
});

// ---------- Owner verification ----------

test("verifyConfig: off without Resend or a store; dev bypass ignored in production", () => {
  const store = memStore();
  assert.equal(verifyConfig(env(), store).available, false);
  assert.equal(verifyConfig(env({ RESEND_API_KEY: "re_x" }), store).available, true);
  assert.equal(verifyConfig(env({ RESEND_API_KEY: "re_x" }), null).available, false);
  assert.equal(verifyConfig(devEnv(), store).available, true);
  assert.equal(verifyConfig(devEnv({ NODE_ENV: "production" }), store).available, false);
});

test("verify: 503 when not configured", async () => {
  const res = await verifyEmail({ action: "send", email: "a@example.com" }, nextIp(), { env: env(), store: memStore() });
  assert.equal(res.status, 503);
});

test("verify: send emails the code through Resend and never returns it", async () => {
  const store = memStore();
  const f = routes({ "https://api.resend.com/emails": () => jsonRes({ id: "1" }) });
  const res = await verifyEmail({ action: "send", email: "Owner@Example.com" }, nextIp(), { env: env({ RESEND_API_KEY: "re_test" }), store, fetchImpl: f.impl });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { sent: true, email: "ow***@example.com" });
  const sent = JSON.parse(String(f.calls[0].init?.body));
  assert.deepEqual(sent.to, ["owner@example.com"]);
  assert.match(sent.text, /\b\d{6}\b/);
  assert.equal((f.calls[0].init?.headers as Record<string, string>).Authorization, "Bearer re_test");
  const stored = [...store.data.values()][0];
  assert.ok(stored && !stored.includes(sent.text.match(/\d{6}/)[0]), "only a hash of the code is stored");
});

test("verify: Resend failure is a 503, disposable inboxes are refused", async () => {
  const fail = routes({ "https://api.resend.com/emails": () => jsonRes({ message: "bad" }, 422) });
  const res = await verifyEmail({ action: "send", email: "x@example.com" }, nextIp(), { env: env({ RESEND_API_KEY: "re" }), store: memStore(), fetchImpl: fail.impl });
  assert.equal(res.status, 503);
  const disposable = await verifyEmail({ action: "send", email: "x@mailinator.com" }, nextIp(), { env: devEnv(), store: memStore() });
  assert.equal(disposable.status, 400);
});

const profileFetch = routes({
  "https://api.gravatar.com/": () => jsonRes({ display_name: "Owner" }),
  "https://gravatar.com/avatar/": () => new Response("", { status: 404 }),
});
const ownerBreaches = async (): Promise<BreachResult> => ({
  source: "xposedornot",
  breaches: [b("PhoneCo", "2024", ["Email addresses", "Phone numbers", "Names"]), b("ShopX", "2018", ["Passwords", "Physical addresses", "Dates of birth"])],
  total: 2,
});

test("verify: right code returns the exposure report once; wrong code fails", async () => {
  const store = memStore();
  const deps = { env: devEnv(), store, fetchImpl: profileFetch.impl, lookup: ownerBreaches, now: () => NOW };
  const sent = await verifyEmail({ action: "send", email: "owner2@example.com" }, nextIp(), deps);
  const code = (sent.body as { devCode: string }).devCode;
  assert.match(code, /^\d{6}$/);

  const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
  assert.equal((await verifyEmail({ action: "confirm", email: "owner2@example.com", code: wrong }, nextIp(), deps)).status, 400);
  assert.equal((await verifyEmail({ action: "confirm", email: "owner2@example.com", code: "12ab" }, nextIp(), deps)).status, 400);

  const ok = await verifyEmail({ action: "confirm", email: "OWNER2@example.com", code }, nextIp(), deps);
  assert.equal(ok.status, 200);
  const r = ok.body as ExposureReport;
  assert.equal(r.profile?.displayName, "Owner");
  assert.deepEqual(r.personalData.phone, ["PhoneCo"]);
  assert.deepEqual(r.personalData.address, ["ShopX"]);
  assert.deepEqual(r.personalData.birthdates, ["ShopX"]);
  assert.deepEqual(r.personalData.names, ["PhoneCo"]);
  assert.ok(r.steps.some((s) => /SIM swap/.test(s.title)));

  const again = await verifyEmail({ action: "confirm", email: "owner2@example.com", code }, nextIp(), deps);
  assert.equal(again.status, 400, "codes work once");
});

test("verify: five wrong tries lock the address out", async () => {
  const store = memStore();
  const deps = { env: devEnv(), store, fetchImpl: profileFetch.impl, lookup: ownerBreaches };
  const code = ((await verifyEmail({ action: "send", email: "locked@example.com" }, nextIp(), deps)).body as { devCode: string }).devCode;
  const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
  for (let i = 0; i < 5; i++) assert.equal((await verifyEmail({ action: "confirm", email: "locked@example.com", code: wrong }, nextIp(), deps)).status, 400);
  assert.equal((await verifyEmail({ action: "confirm", email: "locked@example.com", code }, nextIp(), deps)).status, 429, "even the right code is refused now");
});

test("verify: sends are limited per address", async () => {
  const deps = { env: devEnv({ EMAIL_VERIFY_TARGET_RATE_LIMIT: "2" }), store: memStore() };
  for (let i = 0; i < 2; i++) assert.equal((await verifyEmail({ action: "send", email: "spam-me@example.com" }, nextIp(), deps)).status, 200);
  assert.equal((await verifyEmail({ action: "send", email: "spam-me@example.com" }, nextIp(), deps)).status, 429);
});

test("lockDownSteps: always ends with breach alerts; skips what doesn't apply", () => {
  const clean = buildReport("me+x@example.com", { source: "xposedornot", breaches: [], total: 0 }, null, NOW);
  assert.deepEqual(clean.steps.map((s) => s.title), ["Get alerts for new breaches"]);
  const steps = lockDownSteps("me@example.com", riskSummary([b("A", "2024", ["Passwords"])], NOW),
    { phone: [], address: [], names: [], birthdates: [], passwords: ["A"] }, { displayName: null, location: null, description: null, jobTitle: null, company: null, profileUrl: null, avatar: "data:", accounts: [] });
  assert.deepEqual(steps.map((s) => s.priority), ["now", "now", "consider", "consider", "consider"]);
});

test("verify route: guards and method", async () => {
  const post = (body: string, headers: Record<string, string> = {}) =>
    new NextRequest("http://localhost/api/email/verify", { method: "POST", body, headers: { "content-type": "application/json", ...headers } });
  assert.equal((await route.POST(post("x", { "content-type": "text/plain" }))).status, 415);
  assert.equal((await route.POST(post("{}", { "content-length": "5000" }))).status, 413);
  assert.equal((await route.POST(post("{bad"))).status, 400);
  const res = route.GET();
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("allow"), "POST");
});
