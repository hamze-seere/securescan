import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
// @ts-expect-error - plain JS module without type declarations
import { main, gradeRank } from "../action/check.mjs";

let server: http.Server;
let api = "";
let grade = "B";

before(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/api/scan") {
        const { url, authorized } = JSON.parse(body);
        assert.equal(authorized, true);
        return res.end(JSON.stringify({
          id: "3f1c2b9e-1a2b-4c3d-8e9f-0a1b2c3d4e5f", target: url, finalUrl: url, grade, score: 77, shareAvailable: true,
          summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
          findings: [{ id: "csp", category: "headers", title: "Content-Security-Policy (CSP)", status: "fail", severity: "high", description: "x", recommendation: "Add a CSP | strict" }],
        }));
      }
      if (req.url === "/api/share") return res.end(JSON.stringify({ url: `${api}/r/abc` }));
      res.statusCode = 404;
      res.end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => server.close());

function env(minGrade: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-action-"));
  return {
    INPUT_URL: "https://example.com",
    INPUT_API_URL: api,
    INPUT_MIN_GRADE: minGrade,
    GITHUB_OUTPUT: path.join(dir, "out"),
    GITHUB_STEP_SUMMARY: path.join(dir, "summary"),
  };
}

test("grade ordering", () => {
  assert.ok(gradeRank("A+") > gradeRank("A"));
  assert.ok(gradeRank("B") > gradeRank("C"));
  assert.equal(gradeRank("Z"), -1);
});

test("passes when grade meets the minimum, writes outputs and summary", async () => {
  grade = "B";
  const e = env("B");
  assert.equal(await main(e), 0);
  const out = fs.readFileSync(e.GITHUB_OUTPUT, "utf8");
  assert.match(out, /grade=B/);
  assert.match(out, /report-url=http:\/\/127\.0\.0\.1:\d+\/r\/abc/);
  const summary = fs.readFileSync(e.GITHUB_STEP_SUMMARY, "utf8");
  assert.match(summary, /scored \*\*B\*\*/);
  assert.match(summary, /Add a CSP \\\| strict/, "pipes in table cells are escaped");
});

test("fails when grade is below the minimum", async () => {
  grade = "C";
  assert.equal(await main(env("A")), 1);
});

test("rejects an invalid min-grade", async () => {
  await assert.rejects(() => main(env("Q")), /Invalid min-grade/);
});
