import { NextResponse, type NextRequest } from "next/server";
import { checkEmail } from "@/lib/emailCheck";
import { clientIp } from "@/lib/rateLimit";

export const runtime = "nodejs"; // needs node:dns for the domain checks
export const dynamic = "force-dynamic";
export const maxDuration = 20;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });

export async function POST(req: NextRequest) {
  // Only accept JSON. This also blocks simple cross-site form posts.
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
  const result = await checkEmail(body, clientIp(req.headers));
  return json(result.body, result.status, result.headers);
}

export function GET() {
  return json({ error: "Use POST with JSON: { \"email\": \"you@example.com\", \"authorized\": true }" }, 405, { Allow: "POST" });
}
