"use client";

import { useState } from "react";
import type { AddressInfo, RiskLevel, RiskSummary } from "@/lib/emailInsights";
import type { ExposureReport, LockDownStep } from "@/lib/exposure";

const LEVEL: Record<RiskLevel, { label: string; text: string; ring: string }> = {
  none: { label: "No known exposure", text: "text-sev-pass", ring: "border-sev-pass/30 bg-sev-pass/10" },
  low: { label: "Low risk", text: "text-sev-low", ring: "border-sev-low/30 bg-sev-low/10" },
  medium: { label: "Medium risk", text: "text-sev-medium", ring: "border-sev-medium/30 bg-sev-medium/10" },
  high: { label: "High risk", text: "text-sev-critical", ring: "border-sev-critical/30 bg-sev-critical/10" },
};

const panel = "rounded-xl border border-ink-800 bg-ink-900/60";

export function RiskPanel({ risk, breachCount }: { risk: RiskSummary; breachCount: number }) {
  const level = LEVEL[risk.level];
  const maxYear = Math.max(1, ...risk.byYear.map((y) => y.count));
  const maxType = Math.max(1, ...risk.dataTypes.map((d) => d.count));
  return (
    <section className={`${panel} p-5`} aria-label="Breach risk summary">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="text-sm font-medium">Risk summary</h3>
        <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${level.ring} ${level.text}`}>{level.label}</span>
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Breaches" value={breachCount} />
        <Stat label="Leaked passwords" value={risk.passwordLeaks} alert={risk.passwordLeaks > 0} />
        <Stat label="Leaked phone number" value={risk.phoneLeaks} alert={risk.phoneLeaks > 0} />
        <Stat label="Most recent" value={risk.mostRecent?.date?.slice(0, 4) ?? "–"} hint={risk.mostRecent?.name} />
      </dl>

      {risk.phoneLeaks > 0 && (
        <p className="mt-4 rounded-lg border border-sev-high/30 bg-sev-high/10 px-3 py-2 text-sm text-sev-high">
          Your phone number was exposed in {risk.phoneLeaks} breach{risk.phoneLeaks > 1 ? "es" : ""}. Expect scam calls and
          texts, and ask your carrier for a SIM-swap PIN.
        </p>
      )}

      {risk.byYear.length > 1 && (
        <div className="mt-5">
          <h4 className="text-xs text-ink-400">Breaches by year</h4>
          <div className="mt-2 flex h-20 items-end gap-1" role="img" aria-label={risk.byYear.map((y) => `${y.year}: ${y.count}`).join(", ")}>
            {risk.byYear.map((y) => (
              <div key={y.year} className="group relative flex-1" title={`${y.year}: ${y.count}`}>
                <div className="rounded-sm bg-signal/70 group-hover:bg-signal" style={{ height: `${Math.max(6, (y.count / maxYear) * 80)}px` }} />
              </div>
            ))}
          </div>
          <div className="mt-1 flex justify-between font-mono text-[10px] text-ink-400">
            <span>{risk.byYear[0].year}</span>
            <span>{risk.byYear.at(-1)!.year}</span>
          </div>
        </div>
      )}

      {risk.dataTypes.length > 0 && (
        <div className="mt-5">
          <h4 className="text-xs text-ink-400">What leaked most often</h4>
          <ul className="mt-2 space-y-1.5">
            {risk.dataTypes.map((d) => (
              <li key={d.type} className="grid grid-cols-[minmax(0,10rem)_1fr_2rem] items-center gap-3 text-xs">
                <span className="truncate text-ink-300">{d.type}</span>
                <span className="h-1.5 rounded-full bg-ink-800">
                  <span className={`block h-full rounded-full ${/password/i.test(d.type) ? "bg-sev-high" : "bg-signal-dim"}`} style={{ width: `${(d.count / maxType) * 100}%` }} />
                </span>
                <span className="text-right font-mono tabular-nums text-ink-400">{d.count}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Stat({ label, value, alert, hint }: { label: string; value: number | string; alert?: boolean; hint?: string }) {
  return (
    <div className="rounded-lg bg-ink-850 px-3 py-2.5">
      <dt className="text-[11px] text-ink-400">{label}</dt>
      <dd className={`mt-0.5 text-xl font-semibold tabular-nums ${alert ? "text-sev-high" : ""}`}>{value}</dd>
      {hint && <dd className="truncate text-[11px] text-ink-400" title={hint}>{hint}</dd>}
    </div>
  );
}

const KIND: Record<AddressInfo["kind"], string> = {
  disposable: "Disposable (throwaway inbox)",
  free: "Free webmail",
  custom: "Organisation or personal domain",
};

export function AddressPanel({ address, domain }: { address: AddressInfo; domain: string }) {
  const age = address.domainAge;
  const rows: [string, React.ReactNode][] = [
    ["Address type", <span key="k" className={address.kind === "disposable" ? "text-sev-medium" : ""}>{KIND[address.kind]}</span>],
    ["Mail provider", address.provider ?? `No mail servers for ${domain}`],
    ["Domain registered", age
      ? <span key="a" className={age.days < 90 ? "text-sev-high" : ""}>{age.registered} ({formatAge(age.days)}{age.days < 90 ? ", very new: a common sign of phishing" : ""})</span>
      : address.kind === "free" ? "Not checked for free webmail" : "Not available from the registry"],
    ["Shared role address", address.role ? "Yes (e.g. info@, support@): often targeted by phishing" : "No"],
    ["Plus-addressing", address.plusTag ? "Yes: the +tag shows which site leaked it" : "No"],
  ];
  return (
    <section className={`${panel} p-5`} aria-label="About this address">
      <h3 className="text-sm font-medium">About this address</h3>
      <dl className="mt-3 divide-y divide-ink-800 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="grid gap-1 py-2 sm:grid-cols-[11rem_1fr]">
            <dt className="text-ink-400">{k}</dt>
            <dd className="text-ink-200">{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function formatAge(days: number): string {
  if (days < 60) return `${days} days old`;
  if (days < 730) return `${Math.round(days / 30)} months old`;
  return `${Math.floor(days / 365)} years old`;
}

/** Owner verification: an emailed one-time code unlocks the personal exposure report. */
export function VerifyPanel() {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [stage, setStage] = useState<"email" | "code">("email");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [report, setReport] = useState<ExposureReport | null>(null);

  async function call(body: Record<string, string>) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/email/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        setError(typeof data.error === "string" ? data.error : `Request failed (HTTP ${res.status}).`);
        return null;
      }
      return data;
    } catch {
      setError("Network error. Is the server running?");
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim() || busy) return;
    const data = await call({ action: "send", email });
    if (!data) return;
    setStage("code");
    if (typeof data.devCode === "string") {
      setCode(data.devCode);
      setNote("Development mode: the code was filled in for you instead of being emailed.");
    } else {
      setNote(`We sent a 6-digit code to ${String(data.email)}. It expires in 10 minutes.`);
    }
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault();
    if (!/^\d{6}$/.test(code.trim()) || busy) return;
    const data = await call({ action: "confirm", email, code });
    if (!data) return;
    setReport(data as unknown as ExposureReport);
    setEmail("");
    setCode("");
    setNote(null);
  }

  if (report) return <ExposureView report={report} />;

  const input = "min-w-0 flex-1 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5 font-mono text-sm outline-none focus:border-signal-dim placeholder:text-ink-600";
  const button = "shrink-0 rounded-lg bg-signal px-4 py-2.5 text-sm font-semibold text-ink-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40";
  return (
    <section className="rounded-xl border border-signal-dim/40 bg-signal/5 p-5" aria-label="Full exposure report">
      <h3 className="text-sm font-medium">Is this your address? Get your full exposure report</h3>
      <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-ink-300">
        Prove you own it with a one-time code, and see your public profile photo and linked accounts, which breaches leaked
        your phone number, name or home address, and a step-by-step plan to lock things down.
      </p>
      {stage === "email" ? (
        <form onSubmit={send} className="mt-4 flex max-w-lg gap-2">
          <label htmlFor="verify-email" className="sr-only">Your email address</label>
          <input id="verify-email" type="email" autoComplete="email" spellCheck={false} placeholder="you@example.com" maxLength={254}
            value={email} onChange={(e) => setEmail(e.target.value)} className={input} />
          <button type="submit" disabled={!email.trim() || busy} className={button}>{busy ? "Sending…" : "Send code"}</button>
        </form>
      ) : (
        <form onSubmit={confirm} className="mt-4 flex max-w-lg gap-2">
          <label htmlFor="verify-code" className="sr-only">6-digit code</label>
          <input id="verify-code" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" maxLength={6}
            value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className={`${input} tracking-[0.3em]`} />
          <button type="submit" disabled={code.length !== 6 || busy} className={button}>{busy ? "Checking…" : "Verify"}</button>
          <button type="button" onClick={() => { setStage("email"); setCode(""); setNote(null); }} className="text-sm text-ink-400 hover:text-ink-200">Back</button>
        </form>
      )}
      {note && <p className="mt-3 text-xs text-ink-300">{note}</p>}
      {error && <p role="alert" className="mt-3 text-sm text-[#ffb3ba]">{error}</p>}
    </section>
  );
}

const PRIORITY: Record<LockDownStep["priority"], { label: string; cls: string }> = {
  now: { label: "Do now", cls: "bg-sev-critical/10 text-sev-critical ring-sev-critical/30" },
  soon: { label: "Soon", cls: "bg-sev-medium/10 text-sev-medium ring-sev-medium/30" },
  consider: { label: "Consider", cls: "bg-ink-850 text-ink-300 ring-ink-700" },
};

function ExposureView({ report }: { report: ExposureReport }) {
  const p = report.profile;
  const pd = report.personalData;
  const exposures: [string, string[]][] = [
    ["Phone number", pd.phone],
    ["Home address", pd.address],
    ["Name", pd.names],
    ["Date of birth", pd.birthdates],
    ["Password", pd.passwords],
  ];
  return (
    <section className="animate-fade-up space-y-5 rounded-xl border border-signal-dim/40 bg-signal/5 p-5" aria-label="Your exposure report">
      <div>
        <h3 className="text-sm font-medium">Your exposure report</h3>
        <p className="mt-1 font-mono text-xs text-ink-400">{report.email} · verified {new Date(report.verifiedAt).toLocaleString()}</p>
      </div>

      <div className={`${panel} p-4`}>
        <h4 className="text-xs text-ink-400">Public profile (Gravatar)</h4>
        {p ? (
          <div className="mt-3 flex gap-4">
            {p.avatar
              // eslint-disable-next-line @next/next/no-img-element -- a data: URL fetched by the server, not an optimisable remote image
              ? <img src={p.avatar} alt="Your public Gravatar photo" width={72} height={72} className="size-18 shrink-0 rounded-full ring-1 ring-ink-700" />
              : <div className="grid size-18 shrink-0 place-items-center rounded-full bg-ink-850 text-xs text-ink-400">No photo</div>}
            <div className="min-w-0 text-sm">
              <p className="font-medium">{p.displayName ?? "No display name"}</p>
              {(p.jobTitle || p.company) && <p className="text-ink-300">{[p.jobTitle, p.company].filter(Boolean).join(" at ")}</p>}
              {p.location && <p className="text-ink-300">{p.location}</p>}
              {p.description && <p className="mt-1 text-ink-400">{p.description}</p>}
              {p.accounts.length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Linked accounts">
                  {p.accounts.map((a) => (
                    <li key={a.url}>
                      <a href={a.url} target="_blank" rel="noopener noreferrer" className="rounded bg-ink-850 px-2 py-0.5 text-xs text-signal ring-1 ring-inset ring-ink-700 hover:underline">{a.service}</a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <p className="mt-2 text-sm text-ink-300">No public Gravatar profile or photo is linked to this address.</p>
        )}
      </div>

      <div className={`${panel} p-4`}>
        <h4 className="text-xs text-ink-400">Personal data found in breaches</h4>
        <ul className="mt-2 divide-y divide-ink-800 text-sm">
          {exposures.map(([label, list]) => (
            <li key={label} className="grid gap-1 py-2 sm:grid-cols-[9rem_1fr]">
              <span className={list.length ? "text-sev-high" : "text-ink-400"}>{label}</span>
              <span className="text-ink-300">
                {list.length ? `${list.length} breach${list.length > 1 ? "es" : ""}: ${list.slice(0, 6).join(", ")}${list.length > 6 ? ` and ${list.length - 6} more` : ""}` : "Not found"}
              </span>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-ink-400">Breach databases record which kinds of data leaked, not the values, so your actual number or address is never shown here.</p>
      </div>

      <div>
        <h4 className="text-sm font-medium">Lock it down</h4>
        <ol className="mt-3 space-y-2">
          {report.steps.map((s) => (
            <li key={s.title} className={`${panel} px-4 py-3`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1 ring-inset ${PRIORITY[s.priority].cls}`}>{PRIORITY[s.priority].label}</span>
                <span className="text-sm font-medium">{s.title}</span>
              </div>
              <p className="mt-1.5 text-sm leading-relaxed text-ink-300">{s.detail}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
