import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { diffReports, isStoredReport, markdownCell, toMarkdown } from "../src/lib/reportView";
import { buildReportPdf } from "../src/lib/pdf";
import type { Finding, ScanReport } from "../src/lib/scanner/types";

const finding = (id: string, status: Finding["status"], extra: Partial<Finding> = {}): Finding => ({
  id, category: "headers", title: id, status, severity: "medium", description: "d", ...extra,
});

const report = (findings: Finding[], extra: Partial<ScanReport> = {}): ScanReport => ({
  id: randomUUID(), target: "https://example.com/", finalUrl: "https://example.com/", ip: null,
  scannedAt: new Date().toISOString(), durationMs: 1, grade: "B", score: 80,
  summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, findings, tls: null, redirectChain: [], responseHeaders: {},
  ...extra,
});

test("Markdown cells escape pipes and line breaks so a finding can't break the table", () => {
  assert.equal(markdownCell("a | b\nc\r\nd \\ e"), "a \\| b c d \\\\ e");
  const md = toMarkdown(report([finding("x", "fail", { title: "Bad | title", recommendation: "Line one\nLine two" })], { partial: true }));
  const row = md.split("\n").find((l) => l.startsWith("| medium"))!;
  assert.equal(row, "| medium | Bad \\| title | Line one Line two |");
  assert.match(md, /partial/);
});

test("diff lists new and fixed issues between two scans", () => {
  const before = report([finding("hsts", "fail"), finding("csp", "warn"), finding("nosniff", "pass")], { grade: "C", score: 60 });
  const after = report([finding("hsts", "pass"), finding("csp", "warn"), finding("nosniff", "fail")]);
  const d = diffReports(after, before);
  assert.equal(d.previousGrade, "C");
  assert.deepEqual(d.fixed.map((f) => f.id), ["hsts"]);
  assert.deepEqual(d.newIssues.map((f) => f.id), ["nosniff"]);
});

test("history entries are validated before use", () => {
  assert.equal(isStoredReport(report([])), true);
  for (const bad of [null, "x", {}, { ...report([]), finalUrl: "not a url" }, { ...report([]), findings: "nope" }]) {
    assert.equal(isStoredReport(bad), false);
  }
});

test("PDF export builds, including category scores and a partial notice", async () => {
  const pdf = await buildReportPdf(report([finding("csp", "fail"), finding("hsts", "pass", { category: "transport" })], { partial: true }));
  assert.equal(Buffer.from(pdf.subarray(0, 5)).toString(), "%PDF-");
  assert.ok(pdf.length > 1000);
});
