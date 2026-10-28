import Link from "next/link";
import { SiteFooter, SiteHeader } from "@/components/SiteChrome";

export default function ReportNotFound() {
  return (
    <div className="mx-auto flex min-h-dvh max-w-5xl flex-col px-5 sm:px-8">
      <SiteHeader />
      <main className="flex flex-1 flex-col items-start justify-center py-24">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-sev-medium">404 · report not found</p>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight">This report has expired or never existed.</h1>
        <p className="mt-3 max-w-lg text-ink-300">Shared reports are kept for 30 days. Run a fresh scan to get an up-to-date result.</p>
        <Link href="/" className="mt-8 rounded-lg bg-signal px-5 py-3 text-sm font-semibold text-ink-950 hover:brightness-110">
          Run a new scan
        </Link>
      </main>
      <SiteFooter />
    </div>
  );
}
