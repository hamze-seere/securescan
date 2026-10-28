import { NextResponse, type NextRequest } from "next/server";
import { rateLimit } from "@/lib/rateLimit";
import { shareScan } from "@/lib/reports";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const json = (body: unknown, status = 200) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });

/** POST { id } -> turns a scan the server produced in the last hour into a 30-day share link. */
export async function POST(req: NextRequest) {
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return json({ error: "Content-Type must be application/json." }, 415);
  }
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
  const limit = rateLimit(`share:${ip}`, 10);
  if (!limit.ok) return json({ error: `Too many requests. Try again in ${limit.retryAfter}s.` }, 429);

  let id: unknown;
  try {
    ({ id } = (await req.json()) as { id?: unknown });
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  if (typeof id !== "string") return json({ error: "`id` is required." }, 400);

  try {
    const result = await shareScan(id);
    if (!result.ok) return json({ error: result.error }, result.status);
    return json({ url: `${req.nextUrl.origin}/r/${result.id}`, expiresAt: result.expiresAt });
  } catch (err) {
    console.error("[share] failed", err);
    return json({ error: "Could not create the share link. Please try again." }, 500);
  }
}
