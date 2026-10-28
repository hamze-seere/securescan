"use client";

import { useEffect, useRef, useState } from "react";
import type { ScanReport } from "@/lib/scanner/types";
import Report from "./Report";
import { GradeBadge } from "./GradeBadge";

const HISTORY_KEY = "securescan:history";
const HISTORY_MAX = 6;

const STEPS = [
  "Validating target & resolving DNS",
  "Negotiating TLS handshake",
  "Following redirect chain",
  "Analysing security headers",
  "Inspecting cookies",
  "Probing for exposed files",
  "Testing CORS policy",
  "Scoring results",
];

function loadHistory(): ScanReport[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(parsed) ? (parsed as ScanReport[]).slice(0, HISTORY_MAX) : [];
  } catch {
    return [];
  }
}

function saveHistory(items: ScanReport[]) {
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX)));
  } catch {
    /* storage full or disabled - history is a nice-to-have */
  }
}

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanReport[]>([]);
  const resultRef = useRef<HTMLDivElement>(null);

  // Read localStorage only after mount (not during render) to avoid hydration mismatches.
  useEffect(() => {
    const id = requestAnimationFrame(() => setHistory(loadHistory()));
    return () => cancelAnimationFrame(id);
  }, []);

  useEffect(() => {
    if (!loading) return;
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 850);
    return () => window.clearInterval(id);
  }, [loading]);

  async function scan(e?: React.FormEvent) {
    e?.preventDefault();
    if (!url.trim() || !authorized || loading) return;
    setLoading(true);
    setStep(0);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, authorized }),
      });
      const data = (await res.json()) as ScanReport | { error: string };
      if (!res.ok || "error" in data) {
        setError("error" in data ? data.error : `Scan failed (HTTP ${res.status}).`);
        return;
      }
      setReport(data);
      const next = [data, ...history.filter((h) => h.finalUrl !== data.finalUrl)];
      setHistory(next.slice(0, HISTORY_MAX));
      saveHistory(next);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch {
      setError("Network error. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <section className="pt-14 pb-10 sm:pt-24">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-signal">Website security posture scanner</p>
        <h1 className="mt-4 max-w-3xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
          Find the holes before <span className="text-signal">someone else</span> does.
        </h1>
        <p className="mt-5 max-w-xl text-lg leading-relaxed text-ink-300">
          Enter a URL to get a graded report on its TLS, security headers, cookies, exposed secrets and CORS setup,
          with a concrete fix for every issue.
        </p>

        <form onSubmit={scan} className="mt-10 max-w-2xl">
          <div className="group relative flex items-center rounded-xl border border-ink-700 bg-ink-900 p-1.5 shadow-[0_0_0_1px_transparent] transition focus-within:border-signal-dim focus-within:shadow-[0_0_0_4px_rgb(124_240_180_/_0.08)]">
            <span className="pl-3 pr-1 font-mono text-sm text-signal select-none" aria-hidden="true">$</span>
            <label htmlFor="url" className="sr-only">Website URL</label>
            <input
              id="url"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="yoursite.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              maxLength={2048}
              className="min-w-0 flex-1 bg-transparent px-2 py-3 font-mono text-base outline-none placeholder:text-ink-600"
            />
            <button
              type="submit"
              disabled={!url.trim() || !authorized || loading}
              className="shrink-0 rounded-lg bg-signal px-5 py-3 text-sm font-semibold text-ink-950 transition hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {loading ? "Scanning…" : "Scan"}
            </button>
          </div>
          <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm text-ink-300 select-none">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="mt-0.5 size-4 shrink-0 accent-[#7cf0b4]"
            />
            I own this website or have permission to test it. Only passive, non-intrusive requests are made.
          </label>
        </form>

        {error && (
          <div role="alert" className="mt-6 max-w-2xl animate-fade-up rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-4 py-3 text-sm text-[#ffb3ba]">
            {error}
          </div>
        )}
      </section>

      <div ref={resultRef} className="scroll-mt-6">
        {loading && <ScanProgress step={step} target={url} />}
        {report && !loading && <Report report={report} onRescan={() => scan()} />}
      </div>

      {history.length > 0 && !loading && (
        <section className="mt-16">
          <div className="flex items-baseline justify-between">
            <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-ink-400">Recent scans (stored in your browser)</h2>
            <button
              onClick={() => { setHistory([]); saveHistory([]); }}
              className="text-xs text-ink-400 transition-colors hover:text-ink-100"
            >
              Clear
            </button>
          </div>
          <ul className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {history.map((h) => (
              <li key={h.id}>
                <button
                  onClick={() => { setReport(h); setError(null); resultRef.current?.scrollIntoView({ behavior: "smooth" }); }}
                  className="flex w-full items-center gap-3 rounded-lg border border-ink-800 bg-ink-900/70 p-3 text-left transition hover:border-ink-600"
                >
                  <GradeBadge grade={h.grade} size="sm" />
                  <span className="min-w-0">
                    <span className="block truncate font-mono text-sm">{new URL(h.finalUrl).host}</span>
                    <span className="block text-xs text-ink-400">{new Date(h.scannedAt).toLocaleString()}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

function ScanProgress({ step, target }: { step: number; target: string }) {
  return (
    <div className="animate-fade-up rounded-2xl border border-ink-800 bg-ink-900/80 p-6 font-mono text-sm" aria-live="polite">
      <p className="text-ink-400">
        <span className="text-signal">scanning</span> {target}
      </p>
      <ol className="relative mt-4 space-y-2 overflow-hidden" style={{ "--scan-h": `${STEPS.length * 28}px` } as React.CSSProperties}>
        <span className="pointer-events-none absolute inset-x-0 top-0 h-px animate-scan bg-gradient-to-r from-transparent via-signal to-transparent" />
        {STEPS.map((label, i) => (
          <li key={label} className={`flex items-center gap-3 transition-colors ${i < step ? "text-ink-400" : i === step ? "text-ink-100" : "text-ink-700"}`}>
            <span className="w-4 text-center">{i < step ? "✓" : i === step ? <Spinner /> : "·"}</span>
            {label}
          </li>
        ))}
      </ol>
    </div>
  );
}

function Spinner() {
  return <span className="inline-block size-3 animate-spin rounded-full border-2 border-signal border-t-transparent align-middle" />;
}
