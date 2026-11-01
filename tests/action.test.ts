import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import type { AddressInfo } from "node:net";
// @ts-expect-error - plain JS module without type declarations
import { main, gradeRank, toSarif, escapeCommand, isEntryPoint } from "../action/check.mjs";

let server: http.Server;
let api = "";
let grade = "B";
let failuresBeforeOk = 0;
let scanCalls = 0;

before(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/api/scan") {
        scanCalls++;
        if (failuresBeforeOk > 0) {
          failuresBeforeOk--;
          res.statusCode = 503;
          return res.end(JSON.stringify({ error: "temporarily unavailable" }));
        }
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
    dir,
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

test("retries transient 5xx responses from the API", async () => {
  grade = "B";
  failuresBeforeOk = 2;
  scanCalls = 0;
  assert.equal(await main(env("B"), { retryDelayMs: 1 }), 0);
  assert.equal(scanCalls, 3);
});

test("writes a SARIF file with one result per failing finding", async () => {
  grade = "B";
  const e = { ...env("B"), INPUT_SARIF: "" };
  e.INPUT_SARIF = path.join(e.dir, "securescan.sarif");
  assert.equal(await main(e), 0);
  const sarif = JSON.parse(fs.readFileSync(e.INPUT_SARIF, "utf8"));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.rules[0].id, "csp");
  assert.equal(run.tool.driver.rules[0].properties["security-severity"], "7.5");
  assert.equal(run.results[0].level, "error");
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, "https://example.com");
  assert.match(fs.readFileSync(e.GITHUB_OUTPUT, "utf8"), /sarif=.*securescan.sarif/);
});

test("SARIF skips passing findings", () => {
  const sarif = toSarif({
    finalUrl: "https://a.example/",
    findings: [
      { id: "hsts", category: "headers", title: "HSTS", status: "pass", severity: "high", description: "ok" },
      { id: "nosniff", category: "headers", title: "nosniff", status: "warn", severity: "low", description: "missing" },
    ],
  });
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].level, "note");
});

test("workflow-command text is escaped so it cannot inject commands", () => {
  assert.equal(escapeCommand("bad\n::set-output name=x::y 100%"), "bad%0A::set-output name=x::y 100%25");
});

test("entry-point guard matches Windows and space-containing paths", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ss action dir "));
  const script = path.join(dir, "check.mjs");
  fs.copyFileSync(path.join(process.cwd(), "action", "check.mjs"), script);
  // The old guard compared against `file://${argv[1]}`, which never matches these paths.
  assert.equal(isEntryPoint(pathToFileURL(script).href, script), true);
  assert.equal(isEntryPoint(pathToFileURL(script).href, undefined), false);
  // Run it for real with no inputs: it must execute main() and fail loudly, not exit 0 silently.
  const r = spawnSync(process.execPath, [script], { env: { PATH: process.env.PATH ?? "" } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /::error title=SecureScan::Input `url` is required/);
});

test("CLI flags map onto the Action inputs", async () => {
  // @ts-expect-error - plain JS module without type declarations
  const { cliEnv, DEFAULT_API } = await import("../bin/securescan.mjs");
  const env = cliEnv(["https://example.com", "--min-grade", "A", "--no-share", "--sarif", "out.sarif"]);
  assert.equal(env.INPUT_URL, "https://example.com");
  assert.equal(env.INPUT_API_URL, DEFAULT_API);
  assert.equal(env.INPUT_MIN_GRADE, "A");
  assert.equal(env.INPUT_SHARE, "false");
  assert.equal(env.INPUT_SARIF, "out.sarif");
  assert.equal(cliEnv(["https://example.com"], { SECURESCAN_API: "https://mine.example" }).INPUT_API_URL, "https://mine.example");
  assert.equal(cliEnv(["--help"]), null);
  assert.throws(() => cliEnv([]), /Expected one URL/);
});
