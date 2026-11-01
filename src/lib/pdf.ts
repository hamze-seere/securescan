import { PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage, type RGB } from "pdf-lib";
import type { Finding, ScanReport, Severity } from "@/lib/scanner/types";
import { categoryScores } from "@/lib/scanner/score";
import { CATEGORY_LABEL, CATEGORY_ORDER } from "@/lib/reportView";

/**
 * Builds a printable PDF report in the browser (no server round-trip).
 * Uses pdf-lib's built-in Helvetica, so text is sanitised to the WinAnsi character set.
 */

const A4: [number, number] = [595.28, 841.89];
const M = 48; // page margin
const W = A4[0] - M * 2;

const hex = (h: string): RGB => rgb(parseInt(h.slice(1, 3), 16) / 255, parseInt(h.slice(3, 5), 16) / 255, parseInt(h.slice(5, 7), 16) / 255);
const C = {
  ink: hex("#0c1012"),
  text: hex("#1d2429"),
  muted: hex("#5f6b74"),
  line: hex("#dfe4e8"),
  panel: hex("#f4f6f8"),
  signal: hex("#1f9d63"),
  white: rgb(1, 1, 1),
};
const SEV: Record<Severity, RGB> = {
  critical: hex("#d92d3f"),
  high: hex("#e36a1e"),
  medium: hex("#c89400"),
  low: hex("#2f7fd6"),
  info: hex("#7d8b95"),
};
const GRADE: Record<string, RGB> = { "A+": hex("#1f9d63"), A: hex("#1f9d63"), B: hex("#6c9a1e"), C: hex("#c89400"), D: hex("#e36a1e"), F: hex("#d92d3f") };
const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Map typographic characters to WinAnsi-safe ones and drop anything else. */
export function sanitize(text: string): string {
  return text
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/→/g, "->")
    .replace(/[✓✔]/g, "OK")
    .replace(/[  ]/g, " ")
    .replace(/`/g, "")
    .replace(/[^\x20-\x7E\xA0-\xFF\n]/g, "");
}

function wrap(text: string, font: PDFFont, size: number, width: number): string[] {
  const lines: string[] = [];
  for (const para of sanitize(text).split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/)) {
      // Hard-break very long tokens (URLs, header values)
      let w = word;
      while (font.widthOfTextAtSize(w, size) > width) {
        let cut = w.length;
        while (cut > 1 && font.widthOfTextAtSize(w.slice(0, cut), size) > width) cut--;
        if (line) { lines.push(line); line = ""; }
        lines.push(w.slice(0, cut));
        w = w.slice(cut);
      }
      const candidate = line ? `${line} ${w}` : w;
      if (font.widthOfTextAtSize(candidate, size) > width && line) {
        lines.push(line);
        line = w;
      } else {
        line = candidate;
      }
    }
    lines.push(line);
  }
  return lines;
}

export async function buildReportPdf(report: ScanReport): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const host = new URL(report.finalUrl).host;
  doc.setTitle(`SecureScan report - ${host}`);
  doc.setAuthor("SecureScan");
  doc.setCreationDate(new Date(report.scannedAt));

  const regular = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const mono = await doc.embedFont(StandardFonts.Courier);

  let page: PDFPage = doc.addPage(A4);
  let y = A4[1] - M;

  const newPage = () => {
    page = doc.addPage(A4);
    y = A4[1] - M;
  };
  const ensure = (h: number) => {
    if (y - h < M + 20) newPage();
  };
  const text = (s: string, x: number, size: number, font = regular, color = C.text) =>
    page.drawText(sanitize(s), { x, y, size, font, color });

  // ---- Header band
  page.drawRectangle({ x: 0, y: A4[1] - 92, width: A4[0], height: 92, color: C.ink });
  page.drawText("SECURESCAN", { x: M, y: A4[1] - 44, size: 11, font: bold, color: hex("#7cf0b4") });
  page.drawText("Website security posture report", { x: M, y: A4[1] - 64, size: 16, font: bold, color: C.white });
  y = A4[1] - 130;

  // ---- Grade + summary
  const gColor = GRADE[report.grade] ?? C.muted;
  page.drawCircle({ x: M + 38, y: y - 22, size: 38, borderColor: gColor, borderWidth: 4 });
  const gw = bold.widthOfTextAtSize(report.grade, 30);
  page.drawText(report.grade, { x: M + 38 - gw / 2, y: y - 30, size: 30, font: bold, color: gColor });

  const tx = M + 100;
  text(host, tx, 18, bold, C.ink);
  y -= 20;
  text(`Score ${report.score}/100  -  ${report.finalUrl}`, tx, 9.5, regular, C.muted);
  y -= 14;
  text(`Scanned ${new Date(report.scannedAt).toUTCString()}${report.ip ? `  -  IP ${report.ip}` : ""}`, tx, 9.5, regular, C.muted);
  y -= 22;

  let bx = tx;
  for (const s of ["critical", "high", "medium", "low"] as Severity[]) {
    const label = `${report.summary[s]} ${s}`;
    const bw = bold.widthOfTextAtSize(label, 8.5) + 14;
    page.drawRectangle({ x: bx, y: y - 4, width: bw, height: 16, color: report.summary[s] ? SEV[s] : C.panel });
    page.drawText(label, { x: bx + 7, y: y + 1, size: 8.5, font: bold, color: report.summary[s] ? C.white : C.muted });
    bx += bw + 6;
  }
  y -= 44;

  if (report.partial) {
    page.drawRectangle({ x: M, y: y - 6, width: W, height: 20, color: C.panel });
    text("Some checks did not finish within the time limit, so this report is partial.", M + 8, 9, bold, C.text);
    y -= 32;
  }

  // ---- Findings
  const issues = report.findings.filter((f) => f.status === "fail" || f.status === "warn").sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  const passed = report.findings.filter((f) => f.status === "pass");

  /** `keep` = minimum height that must fit under the heading (avoids orphaned headings). */
  const section = (title: string, keep = 40) => {
    ensure(keep);
    page.drawLine({ start: { x: M, y: y + 14 }, end: { x: A4[0] - M, y: y + 14 }, thickness: 0.6, color: C.line });
    text(title.toUpperCase(), M, 9, bold, C.muted);
    y -= 20;
  };

  const findingBlock = (f: Finding) => {
    const desc = wrap(f.description, regular, 9.5, W - 12);
    const fix = f.recommendation ? wrap(`Fix: ${f.recommendation}`, regular, 9.5, W - 24) : [];
    const ev = f.evidence ? wrap(f.evidence, mono, 7.5, W - 24).slice(0, 6) : [];
    const h = 18 + desc.length * 12.5 + (ev.length ? ev.length * 9.5 + 10 : 0) + (fix.length ? fix.length * 12.5 + 10 : 0) + 10;
    ensure(h);

    const tag = f.severity.toUpperCase();
    const tw = bold.widthOfTextAtSize(tag, 7.5) + 10;
    page.drawRectangle({ x: M, y: y - 3, width: tw, height: 13, color: SEV[f.severity] });
    page.drawText(tag, { x: M + 5, y: y, size: 7.5, font: bold, color: C.white });
    text(f.title, M + tw + 8, 11, bold, C.ink);
    y -= 17;

    for (const l of desc) { text(l, M + 12, 9.5); y -= 12.5; }
    if (ev.length) {
      y -= 2;
      page.drawRectangle({ x: M + 12, y: y - ev.length * 9.5 + 6, width: W - 12, height: ev.length * 9.5 + 6, color: C.panel });
      for (const l of ev) { text(l, M + 18, 7.5, mono, C.muted); y -= 9.5; }
      y -= 8;
    }
    if (fix.length) {
      y -= 2;
      page.drawRectangle({ x: M + 12, y: y - fix.length * 12.5 + 8, width: 2.5, height: fix.length * 12.5 + 2, color: C.signal });
      for (const l of fix) { text(l, M + 22, 9.5, regular, C.text); y -= 12.5; }
      y -= 6;
    }
    y -= 10;
  };

  const subscores = categoryScores(report.findings);
  if (subscores.length) {
    section("Score by category", 30);
    const colW = W / 3;
    CATEGORY_ORDER.flatMap((cat) => subscores.filter((s) => s.category === cat)).forEach((s, i) => {
      const col = i % 3;
      if (col === 0 && i > 0) y -= 24;
      if (col === 0) ensure(24);
      const x = M + col * colW;
      const barW = colW - 16;
      text(CATEGORY_LABEL[s.category], x, 8.5, regular, C.muted);
      const label = String(s.score);
      text(label, x + barW - bold.widthOfTextAtSize(label, 8.5), 8.5, bold, C.ink);
      page.drawRectangle({ x, y: y - 8, width: barW, height: 3.5, color: C.line });
      const fill = s.score >= 90 ? C.signal : s.score >= 60 ? SEV.medium : SEV.critical;
      page.drawRectangle({ x, y: y - 8, width: Math.max(1, (barW * s.score) / 100), height: 3.5, color: fill });
    });
    y -= 40;
  }

  section(`Issues found (${issues.length})`);
  if (!issues.length) { text("No issues found.", M, 10); y -= 20; }
  issues.forEach(findingBlock);

  section(`Passed checks (${passed.length})`);
  for (const f of passed) {
    const lines = wrap(`${f.title}: ${f.description}`, regular, 9, W - 16);
    ensure(lines.length * 12 + 4);
    page.drawCircle({ x: M + 4, y: y + 3, size: 2.5, color: C.signal });
    for (const l of lines) { text(l, M + 14, 9); y -= 12; }
    y -= 3;
  }

  if (report.tls) {
    section("TLS certificate", 110);
    const rows: [string, string | null][] = [
      ["Subject", report.tls.subject], ["Issuer", report.tls.issuer], ["Protocol", report.tls.protocol],
      ["Cipher", report.tls.cipher], ["Valid until", report.tls.validTo ? `${report.tls.validTo.slice(0, 10)} (${report.tls.daysRemaining} days)` : null],
      ["Trusted", report.tls.authorized ? "Yes" : `No (${report.tls.authorizationError})`],
    ];
    for (const [k, v] of rows) {
      ensure(14);
      text(k, M, 9, bold, C.muted);
      text(v ?? "-", M + 90, 9);
      y -= 13;
    }
  }

  // ---- Footer on every page
  const pages = doc.getPages();
  pages.forEach((p, i) => {
    p.drawText(sanitize(`SecureScan  -  ${host}  -  ${report.scannedAt.slice(0, 10)}`), { x: M, y: 24, size: 7.5, font: regular, color: C.muted });
    const label = `Page ${i + 1} of ${pages.length}`;
    p.drawText(label, { x: A4[0] - M - regular.widthOfTextAtSize(label, 7.5), y: 24, size: 7.5, font: regular, color: C.muted });
  });

  return doc.save();
}

export async function downloadReportPdf(report: ScanReport) {
  const bytes = await buildReportPdf(report);
  const blob = new Blob([bytes as BlobPart], { type: "application/pdf" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `securescan-${new URL(report.finalUrl).host}-${report.scannedAt.slice(0, 10)}.pdf`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
