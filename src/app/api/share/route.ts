import { NextResponse, type NextRequest } from "next/server";
import { clientIp, rateLimit } from "@/lib/rateLimit";
import { shareScan } from "@/lib/reports";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const json = (body: unknown, status = 200) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });

/** POST { report } -> turns a report this server signed in the last hour into a 30-day share link. */
export async function POST(req: NextRequest) {
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }
  const limit = await rateLimit(`share:${clientIp(req.headers)}`, 10);
  if (!limit.ok) return json({ error: `Too many requests. Try again in ${limit.retryAfter}s.` }, 429);

  if (Number(req.headers.get("content-length") ?? 0) > 1_000_000) {
    return json({ error: "This report is too large to share." }, 413);
  }
  let report: unknown;
  try {
    ({ report } = (await req.json()) as { report?: unknown });
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  if (!report || typeof report !== "object") return json({ error: "`report` is required." }, 400);

  try {
    const result = await shareScan(report);
    if (!result.ok) return json({ error: result.error }, result.status);
    return json({ url: `${req.nextUrl.origin}/r/${result.id}`, expiresAt: result.expiresAt });
  } catch (err) {
    console.error("[share] failed", err);
    return json({ error: "Could not create the share link. Please try again." }, 500);
  }
}
