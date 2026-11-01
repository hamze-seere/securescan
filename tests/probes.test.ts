import { test } from "node:test";
import assert from "node:assert/strict";
import { checkOpenRedirect, checkSourceMap, openRedirectPath, REDIRECT_CANARY, sourceMapUrl } from "../src/lib/scanner/checks/leaks";
import { badgeSvg } from "../src/lib/badge";
import type { HttpResponseData } from "../src/lib/scanner/types";

const res = (over: Partial<HttpResponseData>): HttpResponseData => ({
  url: "https://example.com/", status: 200, headers: {}, body: "", remoteAddress: null, tls: null, ...over,
});

test("open redirect: only a redirect to the canary host is reported", () => {
  assert.match(openRedirectPath(), /[?&]next=https%3A%2F%2Fsecurescan\.invalid%2F/);
  assert.equal(checkOpenRedirect(res({ status: 302, headers: { location: REDIRECT_CANARY } }))?.status, "fail");
  assert.equal(checkOpenRedirect(res({ status: 301, headers: { location: "//securescan.invalid/x" } }))?.id, "open-redirect");
  for (const r of [
    null,
    res({ status: 200 }),
    res({ status: 302, headers: { location: "/login?next=https://securescan.invalid/" } }),
    res({ status: 302, headers: { location: "https://securescan.invalid.example.com/" } }),
    res({ status: 302, headers: {} }),
  ]) assert.equal(checkOpenRedirect(r), null);
});

test("source map: probes the first same-origin script and needs real map content", () => {
  const html = `<!-- <script src="/old.js"></script> -->
    <script src="https://cdn.example.net/lib.js"></script>
    <script src="/_next/static/app.js?v=3" defer></script>`;
  const url = sourceMapUrl(html, "https://example.com/page")!;
  assert.equal(url, "https://example.com/_next/static/app.js.map");
  assert.equal(sourceMapUrl("<script>inline()</script>", "https://example.com/"), null);

  const map = '{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}';
  assert.equal(checkSourceMap(res({ body: map }), url)?.status, "warn");
  assert.equal(checkSourceMap(res({ status: 404, body: map }), url), null);
  assert.equal(checkSourceMap(res({ body: "<html>soft 404</html>" }), url), null);
});

test("badge SVG is escaped, coloured by grade, and grey when the report is missing", () => {
  const a = badgeSvg("A+");
  assert.match(a, /^<svg [^>]*role="img"[^>]*aria-label="securescan: A\+"/);
  assert.match(a, /#1f9d63/);
  assert.doesNotMatch(a, /<script|href=/i);
  assert.match(badgeSvg(null), /not found/);
  assert.match(badgeSvg(null), /#7d8b95/);
  const evil = badgeSvg("F", `<script>"x"&'`);
  assert.doesNotMatch(evil, /<script/);
  assert.match(evil, /&#60;script&#62;&#34;x&#34;&#38;&#39;/);
});
