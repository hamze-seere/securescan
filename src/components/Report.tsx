"use client";

import { useMemo, useRef, useState } from "react";
import type { Finding, ScanReport, Severity } from "@/lib/scanner/types";
import { categoryScores } from "@/lib/scanner/score";
import { CATEGORY_LABEL, CATEGORY_ORDER, diffReports, isIssue, SEVERITY_RANK, toMarkdown } from "@/lib/reportView";
import { GradeDial } from "./GradeBadge";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "text-sev-critical bg-sev-critical/10 ring-sev-critical/30",
  high: "text-sev-high bg-sev-high/10 ring-sev-high/30",
  medium: "text-sev-medium bg-sev-medium/10 ring-sev-medium/30",
  low: "text-sev-low bg-sev-low/10 ring-sev-low/30",
  info: "text-ink-300 bg-ink-800 ring-ink-700",
};

type Filter = "issues" | "passed" | "all";

/** Renders `code` spans from check descriptions. React escapes everything, so this is XSS-safe. */
function RichText({ text }: { text: string }) {
  return <>{text.split(/(`[^`]+`)/g).map((part, i) => (part.startsWith("`") && part.endsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : part))}</>;
}

type ShareState = { status: "idle" | "working" | "done" | "error"; url?: string; expiresAt?: string; message?: string };

const badgeMarkdown = (shareUrl: string, id: string) =>
  `[![SecureScan grade](${new URL(`/api/badge?id=${id}`, shareUrl).href})](${shareUrl})`;

const FILTERS: [Filter, string][] = [["issues", "Issues"], ["passed", "Passed"], ["all", "All"]];

export default function Report({ report, previous, onRescan, readOnly = false }: {
  report: ScanReport;
  /** An earlier scan of the same site, to show what changed. */
  previous?: ScanReport;
  onRescan?: () => void;
  readOnly?: boolean;
}) {
  const [filter, setFilter] = useState<Filter>("issues");
  const [copied, setCopied] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [share, setShare] = useState<ShareState>({ status: "idle" });
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const host = new URL(report.finalUrl).host;
  const issues = report.findings.filter(isIssue).length;
  const passed = report.findings.filter((f) => f.status === "pass").length;
  const subscores = useMemo(() => {
    const scores = categoryScores(report.findings);
    return CATEGORY_ORDER.flatMap((cat) => scores.filter((s) => s.category === cat));
  }, [report]);
  const diff = useMemo(() => (previous && previous.id !== report.id ? diffReports(report, previous) : null), [report, previous]);

  /** Arrow keys, Home and End move between tabs (WAI-ARIA tabs pattern). */
  function onTabKey(e: React.KeyboardEvent, index: number) {
    const last = FILTERS.length - 1;
    const next = e.key === "ArrowRight" ? (index === last ? 0 : index + 1)
      : e.key === "ArrowLeft" ? (index === 0 ? last : index - 1)
      : e.key === "Home" ? 0 : e.key === "End" ? last : null;
    if (next === null) return;
    e.preventDefault();
    setFilter(FILTERS[next][0]);
    tabRefs.current[next]?.focus();
  }

  const grouped = useMemo(() => {
    const visible = report.findings.filter((f) =>
      filter === "all" ? true : filter === "issues" ? isIssue(f) : f.status === "pass",
    );
    return CATEGORY_ORDER.map((cat) => ({
      cat,
      items: visible
        .filter((f) => f.category === cat)
        .sort((a, b) => Number(isIssue(b)) - Number(isIssue(a)) || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]),
    })).filter((g) => g.items.length > 0);
  }, [report, filter]);

  function download() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `securescan-${host}-${report.scannedAt.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function exportPdf() {
    setPdfBusy(true);
    try {
      // Loaded on demand so pdf-lib (~200 KB) isn't in the initial page bundle.
      const { downloadReportPdf } = await import("@/lib/pdf");
      await downloadReportPdf(report);
    } finally {
      setPdfBusy(false);
    }
  }

  async function createShareLink() {
    setShare({ status: "working" });
    try {
      const res = await fetch("/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report }),
      });
      const data = (await res.json()) as { url?: string; expiresAt?: string; error?: string };
      if (!res.ok || !data.url) throw new Error(data.error ?? "Could not create link.");
      setShare({ status: "done", url: data.url, expiresAt: data.expiresAt });
      navigator.clipboard?.writeText(data.url).catch(() => {});
    } catch (e) {
      setShare({ status: "error", message: e instanceof Error ? e.message : "Could not create link." });
    }
  }

  async function copyMarkdown() {
    try {
      await navigator.clipboard.writeText(toMarkdown(report));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard blocked */
    }
  }

  return (
    <article className="animate-fade-up" aria-label={`Security report for ${host}`}>
      {/* Summary */}
      <div className="rounded-2xl border border-ink-800 bg-ink-900/80 p-6 sm:p-8">
        <div className="flex flex-col gap-8 sm:flex-row sm:items-center">
          <GradeDial grade={report.grade} score={report.score} />
          <div className="min-w-0 flex-1">
            <h2 className="truncate font-mono text-2xl font-semibold tracking-tight">{host}</h2>
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-ink-400">Final URL</dt>
              <dd className="truncate font-mono text-ink-300">{report.finalUrl}</dd>
              <dt className="text-ink-400">IP</dt>
              <dd className="font-mono text-ink-300">{report.ip ?? "-"}</dd>
              <dt className="text-ink-400">Scanned</dt>
              <dd className="text-ink-300">{new Date(report.scannedAt).toLocaleString()} · {(report.durationMs / 1000).toFixed(1)}s</dd>
            </dl>
            <div className="mt-5 flex flex-wrap gap-2">
              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
                <span key={s} className={`rounded-md px-2.5 py-1 font-mono text-xs ring-1 ring-inset ${report.summary[s] ? SEVERITY_STYLE[s] : "bg-ink-850 text-ink-600 ring-ink-800"}`}>
                  {report.summary[s]} {s}
                </span>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-8 flex flex-wrap gap-2 border-t border-ink-800 pt-5">
          {!readOnly && onRescan && <ActionButton onClick={onRescan}>↻ Rescan</ActionButton>}
          {!readOnly && report.shareAvailable && (
            <ActionButton onClick={createShareLink} disabled={share.status === "working"} primary>
              {share.status === "working" ? "Creating link…" : share.status === "done" ? "Link copied ✓" : "Share link"}
            </ActionButton>
          )}
          <ActionButton onClick={exportPdf} disabled={pdfBusy}>{pdfBusy ? "Building PDF…" : "Export PDF"}</ActionButton>
          <ActionButton onClick={download}>Download JSON</ActionButton>
          <ActionButton onClick={copyMarkdown}>{copied ? "Copied ✓" : "Copy as Markdown"}</ActionButton>
        </div>
        {share.status === "done" && share.url && (
          <div className="mt-4 flex flex-col gap-2 rounded-lg border border-signal-dim bg-signal/5 px-4 py-3 text-sm sm:flex-row sm:items-center">
            <span className="shrink-0 text-ink-300">
              Shareable link{share.expiresAt ? ` (valid until ${new Date(share.expiresAt).toLocaleDateString()})` : ""}:
            </span>
            <a href={share.url} target="_blank" rel="noopener noreferrer" className="truncate font-mono text-signal hover:underline">{share.url}</a>
            <button
              onClick={() => navigator.clipboard?.writeText(badgeMarkdown(share.url!, report.id)).catch(() => {})}
              className="shrink-0 text-xs text-ink-400 underline-offset-2 hover:text-ink-100 hover:underline sm:ml-auto"
            >
              Copy README badge
            </button>
          </div>
        )}
        {share.status === "error" && (
          <p role="alert" className="mt-4 text-sm text-[#ffb3ba]">{share.message}</p>
        )}
        {report.partial && (
          <p role="note" className="mt-4 rounded-lg border border-sev-medium/30 bg-sev-medium/10 px-4 py-3 text-sm text-ink-100">
            Some checks didn&apos;t finish within the time limit, so this report is partial. Rescan to try again.
          </p>
        )}
      </div>

      {diff && (
        <section aria-label="Changes since the last scan" className="mt-6 rounded-xl border border-ink-800 bg-ink-900/60 px-5 py-4 text-sm">
          <p className="text-ink-300">
            Since your scan on {new Date(diff.scannedAt).toLocaleDateString()}:{" "}
            <span className="font-mono text-ink-100">{diff.previousGrade} ({diff.previousScore})</span>
            {" → "}
            <span className="font-mono text-ink-100">{report.grade} ({report.score})</span>
            {!diff.newIssues.length && !diff.fixed.length && " · no change in issues"}
          </p>
          {diff.fixed.length > 0 && (
            <p className="mt-2 text-sev-pass">Fixed: {diff.fixed.map((f) => f.title).join(", ")}</p>
          )}
          {diff.newIssues.length > 0 && (
            <p className="mt-2 text-sev-medium">New: {diff.newIssues.map((f) => f.title).join(", ")}</p>
          )}
        </section>
      )}

      {/* Score by category */}
      {subscores.length > 0 && (
        <section aria-label="Score by category" className="mt-6 grid gap-x-6 gap-y-3 rounded-xl border border-ink-800 bg-ink-900/60 p-5 sm:grid-cols-2 lg:grid-cols-3">
          {subscores.map((s) => (
            <div key={s.category} className="text-sm">
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-ink-300">{CATEGORY_LABEL[s.category]}</span>
                <span className="font-mono text-ink-100">{s.score}</span>
              </div>
              <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-ink-800" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={s.score} aria-label={`${CATEGORY_LABEL[s.category]} score`}>
                <div
                  className={`h-full rounded-full ${s.score >= 90 ? "bg-sev-pass" : s.score >= 60 ? "bg-sev-medium" : "bg-sev-critical"}`}
                  style={{ width: `${s.score}%` }}
                />
              </div>
            </div>
          ))}
        </section>
      )}

      {/* Filters */}
      <div role="tablist" aria-label="Filter findings" className="mt-8 inline-flex rounded-lg border border-ink-800 bg-ink-900 p-1 text-sm">
        {FILTERS.map(([key, label], i) => (
          <button
            key={key}
            ref={(el) => { tabRefs.current[i] = el; }}
            id={`tab-${key}`}
            role="tab"
            aria-selected={filter === key}
            aria-controls="findings-panel"
            tabIndex={filter === key ? 0 : -1}
            onClick={() => setFilter(key)}
            onKeyDown={(e) => onTabKey(e, i)}
            className={`rounded-md px-3.5 py-1.5 transition ${filter === key ? "bg-ink-700 text-ink-100" : "text-ink-400 hover:text-ink-100"}`}
          >
            {key === "issues" ? `${label} (${issues})` : key === "passed" ? `${label} (${passed})` : label}
          </button>
        ))}
      </div>

      {/* Findings */}
      <div id="findings-panel" role="tabpanel" aria-labelledby={`tab-${filter}`} className="mt-6 space-y-8">
        {grouped.length === 0 && (
          <p className="rounded-xl border border-ink-800 bg-ink-900/60 p-6 text-sm text-ink-300">
            {filter === "issues" ? "No issues found. This site is in excellent shape. 🎉" : "Nothing to show."}
          </p>
        )}
        {grouped.map(({ cat, items }) => (
          <section key={cat}>
            <h3 className="mb-3 font-mono text-xs uppercase tracking-[0.18em] text-ink-400">{CATEGORY_LABEL[cat]}</h3>
            <ul className="divide-y divide-ink-800 overflow-hidden rounded-xl border border-ink-800 bg-ink-900/60">
              {items.map((f) => <FindingRow key={f.id} f={f} />)}
            </ul>
          </section>
        ))}
      </div>

      {/* Technical details */}
      <div className="mt-10 grid gap-4 lg:grid-cols-2">
        {report.tls && (
          <Panel title="TLS certificate">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              {[
                ["Subject", report.tls.subject],
                ["Issuer", report.tls.issuer],
                ["Protocol", report.tls.protocol],
                ["Cipher", report.tls.cipher],
                ["Valid until", report.tls.validTo ? `${new Date(report.tls.validTo).toLocaleDateString()} (${report.tls.daysRemaining} days)` : null],
                ["Trusted", report.tls.authorized ? "Yes" : `No (${report.tls.authorizationError})`],
              ].map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-ink-400">{k}</dt>
                  <dd className="break-all font-mono text-ink-300">{v ?? "-"}</dd>
                </div>
              ))}
            </dl>
          </Panel>
        )}
        <Panel title="Redirect chain">
          <ol className="space-y-1.5 font-mono text-xs">
            {report.redirectChain.map((h, i) => (
              <li key={i} className="flex gap-3">
                <span className={h.status >= 300 && h.status < 400 ? "text-sev-medium" : "text-sev-pass"}>{h.status}</span>
                <span className="break-all text-ink-300">{h.url}</span>
              </li>
            ))}
          </ol>
        </Panel>
        <details className="group rounded-xl border border-ink-800 bg-ink-900/60 lg:col-span-2">
          <summary className="cursor-pointer list-none px-5 py-4 text-sm font-medium marker:hidden">
            <span className="mr-2 inline-block text-ink-400 transition group-open:rotate-90">›</span>
            Raw response headers
          </summary>
          <pre className="overflow-x-auto border-t border-ink-800 px-5 py-4 font-mono text-xs leading-relaxed text-ink-300">
            {Object.entries(report.responseHeaders)
              .flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => `${k}: ${x}`) : [`${k}: ${v}`]))
              .join("\n")}
          </pre>
        </details>
      </div>
    </article>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const issue = isIssue(f);
  const icon = f.status === "pass" ? "✓" : f.status === "fail" ? "✕" : f.status === "warn" ? "!" : "i";
  const iconColor = f.status === "pass" ? "text-sev-pass" : f.status === "info" ? "text-ink-400" : f.status === "fail" ? "text-sev-critical" : "text-sev-medium";
  return (
    <li>
      <details className="group" open={issue && (f.severity === "critical" || f.severity === "high")}>
        <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3.5 transition hover:bg-ink-850 sm:px-5">
          <span className={`grid size-5 shrink-0 place-items-center rounded-full font-mono text-xs font-bold ring-1 ring-current/30 ${iconColor}`} aria-label={f.status}>
            {icon}
          </span>
          <span className="min-w-0 flex-1 text-sm font-medium"><RichText text={f.title} /></span>
          {issue && (
            <span className={`rounded px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide ring-1 ring-inset ${SEVERITY_STYLE[f.severity]}`}>
              {f.severity}
            </span>
          )}
          <span className="text-ink-600 transition group-open:rotate-90" aria-hidden="true">›</span>
        </summary>
        <div className="space-y-3 px-4 pb-4 pl-12 text-sm leading-relaxed text-ink-300 sm:px-5 sm:pl-13">
          <p><RichText text={f.description} /></p>
          {f.evidence && (
            <pre className="overflow-x-auto rounded-lg bg-ink-950 px-3 py-2 font-mono text-xs whitespace-pre-wrap break-all text-ink-300 ring-1 ring-ink-800">
              {f.evidence}
            </pre>
          )}
          {f.recommendation && (
            <p className="rounded-lg border-l-2 border-signal bg-signal/5 px-3 py-2 text-ink-100">
              <span className="mr-1.5 font-mono text-xs uppercase tracking-wide text-signal">Fix</span>
              <RichText text={f.recommendation} />
            </p>
          )}
        </div>
      </details>
    </li>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-ink-800 bg-ink-900/60 p-5">
      <h3 className="mb-4 text-sm font-medium">{title}</h3>
      {children}
    </section>
  );
}

function ActionButton({ onClick, children, disabled, primary }: { onClick: () => void; children: React.ReactNode; disabled?: boolean; primary?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3.5 py-2 text-sm transition active:scale-[0.98] disabled:cursor-wait disabled:opacity-60 ${
        primary
          ? "border-signal-dim bg-signal/10 text-signal hover:bg-signal/15"
          : "border-ink-700 bg-ink-850 text-ink-300 hover:border-ink-600 hover:text-ink-100"
      }`}
    >
      {children}
    </button>
  );
}
