import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeSpf, checkDmarc, checkSpf, runEmailChecks } from "../src/lib/scanner/checks/email";
import { runDnsChecks } from "../src/lib/scanner/checks/dns";
import { domainChain, orgDomain, type DnsClient } from "../src/lib/scanner/dnsClient";

/** In-memory fake DNS: zone maps record name -> records. */
function fakeDns(zone: {
  txt?: Record<string, string[]>;
  mx?: Record<string, { exchange: string; priority: number }[]>;
  caa?: Record<string, { tag: string; value: string; critical: number }[]>;
  dnssec?: Record<string, boolean | null>;
}): DnsClient {
  return {
    txt: async (n) => zone.txt?.[n] ?? [],
    mx: async (n) => zone.mx?.[n] ?? [],
    caa: async (n) => zone.caa?.[n] ?? [],
    dnssec: async (n) => (zone.dnssec && n in zone.dnssec ? zone.dnssec[n] : false),
  };
}

test("orgDomain handles subdomains and two-level suffixes", () => {
  assert.equal(orgDomain("shop.example.com"), "example.com");
  assert.equal(orgDomain("www.nugaaluniversity.edu.so"), "nugaaluniversity.edu.so");
  assert.equal(orgDomain("a.b.example.co.uk"), "example.co.uk");
  assert.deepEqual(domainChain("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"]);
});

test("SPF analysis", () => {
  assert.deepEqual(analyzeSpf("v=spf1 include:_spf.google.com mx -all"), { qualifier: "-", lookups: 2, hasRedirect: false });
  assert.equal(checkSpf("x.com", ["v=spf1 +all"], true).severity, "high");
  assert.equal(checkSpf("x.com", ["v=spf1 include:a.com ?all"], true).status, "warn");
  assert.equal(checkSpf("x.com", ["v=spf1 -all", "v=spf1 ~all"], true).status, "fail", "duplicate SPF = PermError");
  assert.equal(checkSpf("x.com", ["v=spf1 include:_spf.google.com ~all"], true).status, "pass");
  assert.equal(checkSpf("x.com", ["v=spf1 redirect=_spf.x.com"], true).status, "pass");
  assert.equal(checkSpf("x.com", [], true).status, "fail", "missing SPF on a mail domain");
  assert.equal(checkSpf("x.com", [], false).status, "info", "missing SPF on a non-mail domain is advisory");
  const many = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.com`).join(" ") + " -all";
  assert.equal(checkSpf("x.com", [many], true).status, "warn");
});

test("DMARC policies", () => {
  assert.equal(checkDmarc(null, "x.com", true).status, "fail");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=none; rua=mailto:a@x.com" }, "x.com", true).status, "warn");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject" }, "x.com", true).status, "pass");
  assert.equal(checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject; pct=20" }, "x.com", true).status, "warn");
  // Subdomain inherits the parent's sp= policy
  const sub = checkDmarc({ name: "_dmarc.x.com", record: "v=DMARC1; p=reject; sp=none" }, "mail.x.com", true);
  assert.equal(sub.status, "warn");
  assert.match(sub.description, /inherited/);
});

test("email checks end-to-end on a well-configured domain", async () => {
  const dns = fakeDns({
    txt: {
      "example.com": ["v=spf1 include:_spf.google.com -all", "google-site-verification=abc"],
      "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
      "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
      "s1._domainkey.example.com": ["v=DKIM1; p="], // revoked key - must not count
    },
    mx: { "example.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] },
  });
  const findings = await runEmailChecks("www.example.com", dns);
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  assert.equal(byId.spf.status, "pass");
  assert.equal(byId.dmarc.status, "pass");
  assert.equal(byId.dkim.status, "pass");
  assert.match(byId.dkim.description, /google/);
  assert.doesNotMatch(byId.dkim.description, /s1/);
});

test("email checks on an unprotected mail domain", async () => {
  const dns = fakeDns({ mx: { "victim.org": [{ exchange: "mx.victim.org", priority: 10 }] } });
  const ids = (await runEmailChecks("victim.org", dns)).filter((f) => f.status === "fail").map((f) => f.id);
  assert.deepEqual(ids.sort(), ["dmarc", "spf"]);
});

test("CAA is inherited from the parent domain", async () => {
  const dns = fakeDns({ caa: { "example.com": [{ tag: "issue", value: "letsencrypt.org", critical: 0 }] } });
  const [caa] = await runDnsChecks("app.example.com", dns);
  assert.equal(caa.status, "pass");
  assert.match(caa.description, /letsencrypt\.org.*inherited from example\.com/);
  const [none] = await runDnsChecks("nocaa.com", fakeDns({}));
  assert.equal(none.status, "warn");
});

test("DNSSEC: signed, unsigned and unknown", async () => {
  const [, signed] = await runDnsChecks("www.secure.com", fakeDns({ dnssec: { "secure.com": true } }));
  assert.equal(signed.status, "pass");
  const [, unsigned] = await runDnsChecks("plain.com", fakeDns({}));
  assert.equal(unsigned.status, "warn");
  const [, unknown] = await runDnsChecks("x.com", fakeDns({ dnssec: { "x.com": null } }));
  assert.equal(unknown.status, "info");
});
