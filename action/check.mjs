// SecureScan GitHub Action: scans a URL via a SecureScan API and gates the build on the grade.
// Zero dependencies - runs on plain Node 20+ (global fetch).
import { appendFileSync } from "node:fs";

export const GRADES = ["F", "D", "C", "B", "A", "A+"];
export const gradeRank = (g) => GRADES.indexOf(String(g).trim().toUpperCase());

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

export function summaryMarkdown(report, { minGrade, passed, reportUrl }) {
  const host = new URL(report.finalUrl).host;
  const issues = report.findings
    .filter((f) => f.status === "fail" || f.status === "warn")
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const esc = (s = "") => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
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

function setOutput(env, name, value) {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

export async function main(env = process.env) {
  const url = env.INPUT_URL?.trim();
  const api = env.INPUT_API_URL?.trim().replace(/\/$/, "");
  const minGrade = (env.INPUT_MIN_GRADE || "B").trim().toUpperCase();
  const wantShare = (env.INPUT_SHARE ?? "true") !== "false";

  if (!url) throw new Error("Input `url` is required.");
  if (!api) throw new Error("Input `api-url` is required (your SecureScan deployment).");
  if (gradeRank(minGrade) < 0) throw new Error(`Invalid min-grade "${minGrade}". Use one of: ${GRADES.join(", ")}`);

  console.log(`🔍 Scanning ${url} via ${api} (minimum grade ${minGrade})…`);

  let report;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await fetch(`${api}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "securescan-github-action" },
      body: JSON.stringify({ url, authorized: true }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { report = data; break; }
    // Rate-limited or the target was briefly unreachable (e.g. deployment still propagating): wait and retry.
    if ((res.status === 429 || res.status === 502) && attempt < 3) {
      const wait = Number(res.headers.get("retry-after") || 15);
      console.log(`⏳ ${data.error ?? res.status}. Retrying in ${wait}s…`);
      await new Promise((r) => setTimeout(r, wait * 1000));
      continue;
    }
    throw new Error(`Scan failed (HTTP ${res.status}): ${data.error ?? "unknown error"}`);
  }

  let reportUrl = "";
  if (wantShare && report.shareAvailable) {
    const res = await fetch(`${api}/api/share`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: report.id }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.url) reportUrl = data.url;
  }

  const passed = gradeRank(report.grade) >= gradeRank(minGrade);
  setOutput(env, "grade", report.grade);
  setOutput(env, "score", report.score);
  setOutput(env, "report-url", reportUrl);

  const md = summaryMarkdown(report, { minGrade, passed, reportUrl });
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md);
  console.log(md);

  if (!passed) {
    // ::error:: makes GitHub show an annotation on the run
    console.log(`::error title=SecureScan::Grade ${report.grade} is below the minimum ${minGrade}`);
    return 1;
  }
  console.log(`✅ Grade ${report.grade} meets the minimum ${minGrade}.`);
  return 0;
}

// Run when executed directly (not when imported by tests)
if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.log(`::error title=SecureScan::${err.message}`);
    process.exit(1);
  });
}
