import { NextResponse, type NextRequest } from "next/server";
import { BlockedTargetError, parseTargetUrl, runScan, ScanBudgetError, UnreachableError } from "@/lib/scanner";
import { clientIp, rateLimit } from "@/lib/rateLimit";
import { signForSharing } from "@/lib/reports";

export const runtime = "nodejs"; // needs node:tls, node:dns, node:http
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const LIMIT = Number(process.env.SCAN_RATE_LIMIT ?? 5);
/** Scans of one site per 10 minutes from everyone together, so many IPs can't aim the scanner at it. */
const TARGET_LIMIT = Number(process.env.SCAN_TARGET_RATE_LIMIT ?? 10);

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });

export async function POST(req: NextRequest) {
  // Only accept JSON. This also blocks simple cross-site form posts (CSRF-style abuse).
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }

  const limit = await rateLimit(`scan:${clientIp(req.headers)}`, LIMIT);
  if (!limit.ok) {
    return json(
      { error: `Too many scans. Try again in ${limit.retryAfter}s.` },
      429,
      { "Retry-After": String(limit.retryAfter) },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const { url, authorized } = (body ?? {}) as { url?: unknown; authorized?: unknown };
  if (typeof url !== "string" || url.length > 2048) {
    return json({ error: "`url` must be a string." }, 400);
  }
  if (authorized !== true) {
    return json({ error: "Please confirm you own this site or have permission to scan it." }, 400);
  }

  try {
    const host = parseTargetUrl(url).hostname.replace(/\.+$/, "");
    const perTarget = await rateLimit(`target:${host}`, TARGET_LIMIT, 10 * 60_000);
    if (!perTarget.ok) {
      return json(
        { error: `${host} has been scanned many times recently. Try again in ${perTarget.retryAfter}s.` },
        429,
        { "Retry-After": String(perTarget.retryAfter) },
      );
    }
    const report = await runScan(url);
    report.shareAvailable = signForSharing(report);
    return json(report, 200, { "X-RateLimit-Remaining": String(limit.remaining) });
  } catch (err) {
    if (err instanceof BlockedTargetError) return json({ error: err.message }, 400);
    if (err instanceof UnreachableError) return json({ error: err.message }, 502);
    if (err instanceof ScanBudgetError) return json({ error: err.message }, 504);
    console.error("[scan] unexpected error", err);
    // Never leak stack traces to the client.
    return json({ error: "The scan failed unexpectedly. Please try again." }, 500);
  }
}

export function GET() {
  return json({ error: "Use POST with JSON: { \"url\": \"example.com\", \"authorized\": true }" }, 405, { Allow: "POST" });
}
