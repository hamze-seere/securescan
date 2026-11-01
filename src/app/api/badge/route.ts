import type { NextRequest } from "next/server";
import { badgeSvg } from "@/lib/badge";
import { getSharedReport } from "@/lib/reports";

export const runtime = "nodejs";

/**
 * GET /api/badge?id=<shared report id> -> an SVG grade badge for a README.
 * Only shared reports have badges, and a shared report never changes, so the CDN can cache it.
 */
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id") ?? "";
  const report = await getSharedReport(id);
  return new Response(badgeSvg(report?.grade ?? null), {
    status: report ? 200 : 404,
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": report ? "public, max-age=3600, s-maxage=86400" : "public, max-age=60",
      // The SVG is static: no scripts, no external loads.
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
