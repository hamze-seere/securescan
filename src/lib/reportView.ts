import type { Category, Finding, ScanReport, Severity } from "@/lib/scanner/types";

/** Display helpers shared by the web report, the PDF export and the Markdown export. */

export const CATEGORY_LABEL: Record<Category, string> = {
  transport: "Transport & TLS",
  headers: "Security headers",
  cookies: "Cookies",
  exposure: "Exposed files",
  cors: "Cross-origin (CORS)",
  content: "Page content",
  disclosure: "Information disclosure",
  email: "Email security",
  dns: "DNS security",
};
export const CATEGORY_ORDER: Category[] = ["transport", "exposure", "headers", "cookies", "email", "dns", "cors", "content", "disclosure"];
export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const isIssue = (f: Finding) => f.status === "fail" || f.status === "warn";

/** Makes text safe inside one Markdown table cell: no pipes or line breaks to break the row. */
export function markdownCell(text: string): string {
  return text.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n+/g, " ").trim();
}

export function toMarkdown(r: ScanReport): string {
  const lines = [
    `# SecureScan report: ${new URL(r.finalUrl).host}`,
    ``,
    `**Grade:** ${r.grade} (${r.score}/100) · scanned ${new Date(r.scannedAt).toUTCString()}`,
    ...(r.partial ? [``, `> Some checks did not finish in time, so this report is partial.`] : []),
    ``,
    `| Severity | Issue | Fix |`,
    `|---|---|---|`,
    ...r.findings
      .filter(isIssue)
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
      .map((f) => `| ${f.severity} | ${markdownCell(f.title)} | ${markdownCell(f.recommendation ?? "")} |`),
  ];
  return lines.join("\n");
}

export interface ReportDiff {
  previousGrade: ScanReport["grade"];
  previousScore: number;
  scannedAt: string;
  /** Issues in this scan that the previous one didn't have. */
  newIssues: Finding[];
  /** Issues in the previous scan that are gone now. */
  fixed: Finding[];
}

/** Compares two scans of the same site, matching findings by id. */
export function diffReports(current: ScanReport, previous: ScanReport): ReportDiff {
  const issueIds = (r: ScanReport) => new Set(r.findings.filter(isIssue).map((f) => f.id));
  const before = issueIds(previous);
  const now = issueIds(current);
  return {
    previousGrade: previous.grade,
    previousScore: previous.score,
    scannedAt: previous.scannedAt,
    newIssues: current.findings.filter((f) => isIssue(f) && !before.has(f.id)),
    fixed: previous.findings.filter((f) => isIssue(f) && !now.has(f.id)),
  };
}

/** Drops localStorage entries that aren't usable reports (old formats, hand edits). */
export function isStoredReport(value: unknown): value is ScanReport {
  if (!value || typeof value !== "object") return false;
  const r = value as Partial<ScanReport>;
  return typeof r.id === "string" && typeof r.grade === "string" && typeof r.score === "number"
    && typeof r.scannedAt === "string" && Array.isArray(r.findings) && typeof r.finalUrl === "string"
    && URL.canParse(r.finalUrl) && !!r.summary && typeof r.summary === "object";
}
