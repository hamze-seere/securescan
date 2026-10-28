import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import Report from "@/components/Report";
import { SiteFooter, SiteHeader } from "@/components/SiteChrome";
import { getSharedReport } from "@/lib/reports";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  const report = await getSharedReport(id);
  const host = report ? new URL(report.finalUrl).host : null;
  return {
    title: host ? `${host}: Grade ${report!.grade} · SecureScan` : "Report not found · SecureScan",
    description: host ? `Security posture report for ${host}: grade ${report!.grade} (${report!.score}/100).` : undefined,
    // Reports are unlisted: reachable by link, never indexed by search engines.
    robots: { index: false, follow: false },
  };
}

export default async function SharedReportPage({ params }: Props) {
  const { id } = await params;
  const report = await getSharedReport(id);
  if (!report) notFound();

  return (
    <div className="mx-auto flex min-h-dvh max-w-5xl flex-col px-5 sm:px-8">
      <SiteHeader />
      <main className="flex-1 pb-20">
        <div className="mt-8 mb-6 flex flex-col gap-3 rounded-xl border border-ink-800 bg-ink-900/60 px-5 py-4 text-sm sm:flex-row sm:items-center sm:justify-between">
          <p className="text-ink-300">
            <span className="font-mono text-xs uppercase tracking-[0.18em] text-signal">Shared report</span>
            <span className="mx-2 text-ink-600">·</span>
            Snapshot from {new Date(report.scannedAt).toUTCString()}
          </p>
          <Link href="/" className="font-medium text-signal hover:underline">Scan your own site →</Link>
        </div>
        <Report report={report} readOnly />
      </main>
      <SiteFooter />
    </div>
  );
}
