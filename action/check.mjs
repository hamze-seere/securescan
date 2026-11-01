// SecureScan GitHub Action: scans a URL via a SecureScan API and gates the build on the grade.
// Zero dependencies - runs on plain Node 20+ (global fetch).
import { appendFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const GRADES = ["F", "D", "C", "B", "A", "A+"];
export const gradeRank = (g) => GRADES.indexOf(String(g).trim().toUpperCase());

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };
/** HTTP statuses worth retrying: rate limits and transient upstream/gateway failures. */
const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const REQUEST_TIMEOUT_MS = 60_000;

/** Escape text for a workflow command (`::error ...::message`) so it cannot inject further commands. */
export const escapeCommand = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

export function summaryMarkdown(report, { minGrade, passed, reportUrl }) {
  const host = new URL(report.finalUrl).host;
  const issues = report.findings
    .filter((f) => f.status === "fail" || f.status === "warn")
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const esc = (s = "") => String(s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  return [
    `## ${passed ? "✅" : "❌"} SecureScan: ${host} scored **${report.grade}** (${report.score}/100)`,
    "",
    `Minimum required grade: **${minGrade}**${reportUrl ? ` · [Full report](${reportUrl})` : ""}`,
    "",
    `| Critical | High | Medium | Low |`,
    `|---|---|---|---|`,
    `| ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} |`,
    "",
    issues.length ? "| Severity | Issue | Fix |\n|---|---|---|\n" + issues.map((f) => `| ${SEV_ICON[f.severity]} ${f.severity} | ${esc(f.title)} | ${esc(f.recommendation)} |`).join("\n") : "No issues found. 🎉",
    "",
  ].join("\n");
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SARIF_SCORE = { critical: "9.5", high: "7.5", medium: "5.0", low: "2.5", info: "0.0" };

/** SARIF 2.1.0 log for GitHub code scanning: one rule per finding id, one result per failing/warning finding. */
export function toSarif(report, { reportUrl = "" } = {}) {
  const issues = report.findings.filter((f) => f.status === "fail" || f.status === "warn");
  const rules = issues.map((f) => ({
    id: f.id,
    name: f.id.replace(/[^A-Za-z0-9]+/g, "_"),
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    help: { text: f.recommendation || f.description },
    ...(reportUrl ? { helpUri: reportUrl } : {}),
    properties: { tags: ["security", f.category], "security-severity": SARIF_SCORE[f.severity] ?? "0.0" },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "SecureScan", informationUri: "https://github.com/hamze-seere/securescan", rules } },
      results: issues.map((f, ruleIndex) => ({
        ruleId: f.id,
        ruleIndex,
        level: SARIF_LEVEL[f.severity] ?? "note",
        message: { text: `${f.title}: ${f.description}${f.evidence ? ` (evidence: ${f.evidence})` : ""}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: report.finalUrl } } }],
        partialFingerprints: { securescanFinding: `${new URL(report.finalUrl).host}/${f.id}` },
      })),
    }],
  };
}

function setOutput(env, name, value) {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function main(env = process.env, { retryDelayMs = 15_000 } = {}) {
  const url = env.INPUT_URL?.trim();
  const api = env.INPUT_API_URL?.trim().replace(/\/$/, "");
  const minGrade = (env.INPUT_MIN_GRADE || "B").trim().toUpperCase();
  const wantShare = (env.INPUT_SHARE ?? "true") !== "false";
  const sarifPath = env.INPUT_SARIF?.trim();

  if (!url) throw new Error("Input `url` is required.");
  if (!api) throw new Error("Input `api-url` is required (your SecureScan deployment).");
  if (gradeRank(minGrade) < 0) throw new Error(`Invalid min-grade "${minGrade}". Use one of: ${GRADES.join(", ")}`);

  console.log(`🔍 Scanning ${url} via ${api} (minimum grade ${minGrade})…`);

  let report;
  for (let attempt = 1; attempt <= 3; attempt++) {
    let res, data;
    try {
      res = await fetch(`${api}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "securescan-github-action" },
        body: JSON.stringify({ url, authorized: true }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      data = await res.json().catch(() => ({}));
    } catch (err) {
      // Network error or timeout talking to the API itself
      if (attempt < 3) {
        console.log(`⏳ ${err.name === "TimeoutError" ? "API timed out" : err.message}. Retrying…`);
        await sleep(retryDelayMs);
        continue;
      }
      throw new Error(`Could not reach the SecureScan API: ${err.message}`);
    }
    if (res.ok) { report = data; break; }
    // Rate-limited, or the API/target was briefly unavailable (e.g. deployment still propagating): wait and retry.
    if (RETRYABLE.has(res.status) && attempt < 3) {
      const retryAfter = Number(res.headers.get("retry-after"));
      const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter, 120) * 1000 : retryDelayMs;
      console.log(`⏳ ${data.error ?? res.status}. Retrying in ${Math.round(wait / 1000)}s…`);
      await sleep(wait);
      continue;
    }
    throw new Error(`Scan failed (HTTP ${res.status}): ${data.error ?? "unknown error"}`);
  }

  let reportUrl = "";
  if (wantShare && report.shareAvailable) {
    try {
      const res = await fetch(`${api}/api/share`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.url) reportUrl = data.url;
    } catch {
      // A share link is a nice-to-have; never fail the gate over it.
    }
  }

  const passed = gradeRank(report.grade) >= gradeRank(minGrade);
  setOutput(env, "grade", report.grade);
  setOutput(env, "score", report.score);
  setOutput(env, "report-url", reportUrl);

  if (sarifPath) {
    writeFileSync(sarifPath, JSON.stringify(toSarif(report, { reportUrl }), null, 2));
    setOutput(env, "sarif", sarifPath);
  }

  const md = summaryMarkdown(report, { minGrade, passed, reportUrl });
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md);
  console.log(md);

  if (!passed) {
    // ::error:: makes GitHub show an annotation on the run
    console.log(`::error title=SecureScan::${escapeCommand(`Grade ${report.grade} is below the minimum ${minGrade}`)}`);
    return 1;
  }
  console.log(`✅ Grade ${report.grade} meets the minimum ${minGrade}.`);
  return 0;
}

/** True when this module is the entry script. pathToFileURL handles Windows drive letters and spaces. */
export const isEntryPoint = (moduleUrl, argv1) => Boolean(argv1) && moduleUrl === pathToFileURL(argv1).href;

// Run when executed directly (not when imported by tests)
if (isEntryPoint(import.meta.url, process.argv[1])) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.log(`::error title=SecureScan::${escapeCommand(err.message)}`);
    process.exit(1);
  });
}
