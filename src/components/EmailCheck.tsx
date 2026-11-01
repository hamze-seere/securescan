"use client";

import { useRef, useState } from "react";
import type { EmailReport } from "@/lib/emailCheck";
import { FindingRow } from "./Report";
import { AddressPanel, RiskPanel, VerifyPanel } from "./EmailInsights";

/** Email breach check. Results stay in memory only: nothing is saved in the browser or on the server. */
export default function EmailCheck() {
  const [email, setEmail] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<EmailReport | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  async function check(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim() || !authorized || loading) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, authorized }),
      });
      const data = (await res.json()) as EmailReport | { error: string };
      if (!res.ok || "error" in data) {
        setError("error" in data ? data.error : `Check failed (HTTP ${res.status}).`);
        return;
      }
      setReport(data);
      setEmail(""); // don't leave the address sitting in the form
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch {
      setError("Network error. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section id="email" className="mt-28 scroll-mt-8">
      <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-signal">Email breach check</h2>
      <p className="mt-3 max-w-xl text-2xl font-semibold tracking-tight text-balance">Has your email address leaked in a data breach?</p>
      <p className="mt-4 max-w-xl leading-relaxed text-ink-300">
        See which known breaches include an address, how risky that is and what kind of data leaked, who hosts the
        mailbox, and whether its domain is protected against spoofing. The address is never stored or logged.
      </p>

      <form onSubmit={check} className="mt-8 max-w-2xl">
        <div className="relative flex items-center rounded-xl border border-ink-700 bg-ink-900 p-1.5 transition focus-within:border-signal-dim focus-within:shadow-[0_0_0_4px_rgb(124_240_180_/_0.08)]">
          <span className="pl-3 pr-1 font-mono text-sm text-signal select-none" aria-hidden="true">@</span>
          <label htmlFor="email-address" className="sr-only">Email address</label>
          <input
            id="email-address"
            type="email"
            autoComplete="email"
            autoCapitalize="off"
            spellCheck={false}
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            maxLength={254}
            className="min-w-0 flex-1 bg-transparent px-2 py-3 font-mono text-base outline-none placeholder:text-ink-600"
          />
          <button
            type="submit"
            disabled={!email.trim() || !authorized || loading}
            className="shrink-0 rounded-lg bg-signal px-5 py-3 text-sm font-semibold text-ink-950 transition hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? "Checking…" : "Check"}
          </button>
        </div>
        <label className="mt-4 flex cursor-pointer items-start gap-3 text-sm text-ink-300 select-none">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 size-4 shrink-0 accent-[#7cf0b4]"
          />
          This is my email address, or I have permission to check it.
        </label>
      </form>

      {error && (
        <div role="alert" className="mt-6 max-w-2xl animate-fade-up rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-4 py-3 text-sm text-[#ffb3ba]">
          {error}
        </div>
      )}

      <div ref={resultRef} className="scroll-mt-6" aria-live="polite">
        {report && !loading && <EmailResult report={report} />}
      </div>
    </section>
  );
}

const SHOWN_AT_FIRST = 10;

function EmailResult({ report }: { report: EmailReport }) {
  const [showAll, setShowAll] = useState(false);
  const count = report.breachCount;
  const breached = count > 0;
  const shown = showAll ? report.breaches : report.breaches.slice(0, SHOWN_AT_FIRST);
  return (
    <article className="mt-8 animate-fade-up space-y-6">
      <div className={`rounded-2xl border p-6 ${breached ? "border-sev-critical/30 bg-sev-critical/5" : "border-sev-pass/30 bg-sev-pass/5"}`}>
        <p className="font-mono text-sm text-ink-400">{report.email}</p>
        <p className={`mt-2 text-2xl font-semibold tracking-tight ${breached ? "text-sev-critical" : "text-sev-pass"}`}>
          {breached ? `Found in ${count} known breach${count > 1 ? "es" : ""}` : "Not found in any known breach"}
        </p>
        <p className="mt-2 max-w-xl text-sm leading-relaxed text-ink-300">
          {breached
            ? "Change the password on these sites and anywhere you reused it, and turn on two-factor authentication. A password manager makes unique passwords easy."
            : "Good news. This doesn't guarantee the address never leaked, only that it isn't in the breaches this database knows about."}
        </p>
      </div>

      {breached && <RiskPanel risk={report.risk} breachCount={count} />}
      <AddressPanel address={report.address} domain={report.domain} />
      {report.verifyAvailable && <VerifyPanel />}

      {breached && (
        <div>
        <ul className="divide-y divide-ink-800 overflow-hidden rounded-xl border border-ink-800 bg-ink-900/60">
          {shown.map((b, i) => (
            <li key={`${b.name}-${i}`} className="px-4 py-3.5 sm:px-5">
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="text-sm font-medium">{b.name}</span>
                {b.domain && <span className="font-mono text-xs text-ink-400">{b.domain}</span>}
                {b.date && <span className="ml-auto font-mono text-xs tabular-nums text-ink-400">{b.date}</span>}
              </div>
              {b.dataTypes.length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Data exposed">
                  {b.dataTypes.map((d) => (
                    <li key={d} className={`rounded px-2 py-0.5 text-[11px] ring-1 ring-inset ${/password/i.test(d) ? "bg-sev-high/10 text-sev-high ring-sev-high/30" : "bg-ink-850 text-ink-300 ring-ink-700"}`}>
                      {d}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
        {report.breaches.length > SHOWN_AT_FIRST && (
          <button
            type="button"
            onClick={() => setShowAll((v) => !v)}
            className="mt-3 text-sm text-signal hover:underline"
          >
            {showAll ? "Show fewer" : `Show all ${report.breaches.length}`}
          </button>
        )}
        {count > report.breaches.length && (
          <p className="mt-2 text-xs text-ink-400">Showing the {report.breaches.length} most recent of {count} breaches.</p>
        )}
        </div>
      )}

      {report.domainFindings.length > 0 && (
        <section>
          <h3 className="text-sm font-medium">Spoofing protection for {report.domain}</h3>
          <ul className="mt-3 divide-y divide-ink-800 overflow-hidden rounded-xl border border-ink-800 bg-ink-900/60">
            {report.domainFindings.map((f) => <FindingRow key={f.id} f={f} />)}
          </ul>
        </section>
      )}

      <p className="text-xs text-ink-400">
        Breach data from{" "}
        <a href={report.source.url} target="_blank" rel="noopener noreferrer" className="text-signal hover:underline">
          {report.source.name}
        </a>
        . Checked {new Date(report.checkedAt).toLocaleString()}.
      </p>
    </article>
  );
}
