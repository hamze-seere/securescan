import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cache } from "react";
import type { ScanReport } from "@/lib/scanner/types";
import { getStore, PENDING_TTL, REPORT_ID, sharedKey, SHARE_TTL } from "@/lib/store";

/**
 * Why share links can't be forged:
 * if the share endpoint accepted any report from the browser, anyone could POST a
 * fake "Grade F, .env exposed!" report for a site they don't like and get a
 * legitimate-looking link on our domain. Instead, the server signs every report it
 * produces (HMAC-SHA256 with a server-only secret) and "share" only publishes a report
 * whose signature matches, within an hour of the scan. Nothing is written to storage
 * until someone actually shares.
 */

const MAX_SHARE_BYTES = 1_000_000;

// Survives Next.js dev hot-reloads, so tokens stay valid while you edit.
const globalForSecret = globalThis as unknown as { __securescanShareSecret?: Buffer };

function shareSecret(): Buffer {
  if (process.env.SHARE_SECRET) return Buffer.from(process.env.SHARE_SECRET);
  // Derive one from the Redis token, which is already a server-only secret.
  const kvToken = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;
  if (kvToken) return createHmac("sha256", kvToken).update("securescan-share-v1").digest();
  return (globalForSecret.__securescanShareSecret ??= randomBytes(32));
}

/** The signed content: the whole report as JSON, minus the token itself. */
function signature(report: ScanReport): string {
  const { shareToken: _token, ...rest } = report;
  return createHmac("sha256", shareSecret()).update(JSON.stringify(rest)).digest("base64url");
}

/** Signs a fresh report so it can be shared later. Returns false when sharing isn't configured. */
export function signForSharing(report: ScanReport): boolean {
  if (!getStore()) return false;
  report.shareAvailable = true;
  report.shareToken = signature(report);
  return true;
}

export type ShareResult =
  | { ok: true; id: string; expiresAt: string }
  | { ok: false; status: number; error: string };

export async function shareScan(input: unknown, now = Date.now()): Promise<ShareResult> {
  const report = input as ScanReport | null;
  if (!report || typeof report !== "object" || typeof report.id !== "string" || !REPORT_ID.test(report.id)) {
    return { ok: false, status: 400, error: "Invalid report." };
  }
  const store = getStore();
  if (!store) return { ok: false, status: 503, error: "Sharing isn't configured on this server." };

  const token = typeof report.shareToken === "string" ? Buffer.from(report.shareToken) : Buffer.alloc(0);
  const expected = Buffer.from(signature(report));
  if (token.length !== expected.length || !timingSafeEqual(token, expected)) {
    return { ok: false, status: 403, error: "This report wasn't produced by this server, so it can't be shared." };
  }
  const age = now - Date.parse(report.scannedAt);
  if (!(age >= -60_000 && age <= PENDING_TTL * 1000)) {
    return { ok: false, status: 410, error: "This scan is more than an hour old. Run it again to share it." };
  }

  const { shareToken: _token, shareAvailable: _available, ...stored } = report;
  const raw = JSON.stringify(stored);
  if (raw.length > MAX_SHARE_BYTES) return { ok: false, status: 413, error: "This report is too large to share." };
  await store.set(sharedKey(report.id), raw, SHARE_TTL);
  return { ok: true, id: report.id, expiresAt: new Date(now + SHARE_TTL * 1000).toISOString() };
}

/** Wrapped in cache() so generateMetadata and the page share one store read per request. */
export const getSharedReport = cache(async (id: string): Promise<ScanReport | null> => {
  if (!REPORT_ID.test(id)) return null;
  const store = getStore();
  if (!store) return null;
  try {
    const raw = await store.get(sharedKey(id));
    return raw ? (JSON.parse(raw) as ScanReport) : null;
  } catch {
    return null;
  }
});
