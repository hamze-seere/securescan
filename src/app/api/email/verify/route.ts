import { NextResponse, type NextRequest } from "next/server";
import { verifyEmail } from "@/lib/exposure";
import { clientIp } from "@/lib/rateLimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 20;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });

/** { action: "send", email } emails a one-time code; { action: "confirm", email, code } returns the exposure report. */
export async function POST(req: NextRequest) {
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }
  if (Number(req.headers.get("content-length") ?? 0) > 4096) return json({ error: "Request too large." }, 413);

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  const result = await verifyEmail(body, clientIp(req.headers));
  return json(result.body, result.status, result.headers);
}

export function GET() {
  return json({ error: "Use POST with JSON: { \"action\": \"send\", \"email\": \"you@example.com\" }" }, 405, { Allow: "POST" });
}
