import { NextResponse, type NextRequest } from "next/server";
import { BlockedTargetError, runScan, UnreachableError } from "@/lib/scanner";
import { rateLimit } from "@/lib/rateLimit";

export const runtime = "nodejs"; // needs node:tls, node:dns, node:http
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const LIMIT = Number(process.env.SCAN_RATE_LIMIT ?? 5);

function clientIp(req: NextRequest): string {
  // On Vercel the platform sets x-forwarded-for; its first entry is the real client.
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim() || req.headers.get("x-real-ip") || "unknown";
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });

export async function POST(req: NextRequest) {
  // Only accept JSON. This also blocks simple cross-site form posts (CSRF-style abuse).
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }

  const limit = rateLimit(clientIp(req), LIMIT);
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
    const report = await runScan(url);
    return json(report, 200, { "X-RateLimit-Remaining": String(limit.remaining) });
  } catch (err) {
    if (err instanceof BlockedTargetError) return json({ error: err.message }, 400);
    if (err instanceof UnreachableError) return json({ error: err.message }, 502);
    console.error("[scan] unexpected error", err);
    // Never leak stack traces to the client.
    return json({ error: "The scan failed unexpectedly. Please try again." }, 500);
  }
}

export function GET() {
  return json({ error: "Use POST with JSON: { \"url\": \"example.com\", \"authorized\": true }" }, 405, { Allow: "POST" });
}
