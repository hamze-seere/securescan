import type { ScanReport } from "@/lib/scanner/types";
import { getStore, pendingKey, PENDING_TTL, REPORT_ID, sharedKey, SHARE_TTL } from "@/lib/store";

/**
 * Why reports are stored server-side:
 * if the share endpoint accepted a report from the browser, anyone could POST a
 * fake "Grade F, .env exposed!" report for a site they don't like and get a
 * legitimate-looking link on our domain. Instead, the server keeps every fresh scan
 * for an hour, and "share" only promotes a report the server itself produced.
 */

export async function rememberScan(report: ScanReport): Promise<boolean> {
  const store = getStore();
  if (!store) return false;
  try {
    await store.set(pendingKey(report.id), JSON.stringify(report), PENDING_TTL);
    return true;
  } catch (err) {
    console.error("[share] could not store scan", err);
    return false;
  }
}

export type ShareResult =
  | { ok: true; id: string; expiresAt: string }
  | { ok: false; status: number; error: string };

export async function shareScan(id: string): Promise<ShareResult> {
  if (!REPORT_ID.test(id)) return { ok: false, status: 400, error: "Invalid report id." };
  const store = getStore();
  if (!store) return { ok: false, status: 503, error: "Sharing isn't configured on this server." };

  const existing = await store.get(sharedKey(id));
  const raw = existing ?? (await store.get(pendingKey(id)));
  if (!raw) return { ok: false, status: 404, error: "This scan has expired. Run it again to share it." };

  await store.set(sharedKey(id), raw, SHARE_TTL);
  return { ok: true, id, expiresAt: new Date(Date.now() + SHARE_TTL * 1000).toISOString() };
}

export async function getSharedReport(id: string): Promise<ScanReport | null> {
  if (!REPORT_ID.test(id)) return null;
  const store = getStore();
  if (!store) return null;
  try {
    const raw = await store.get(sharedKey(id));
    return raw ? (JSON.parse(raw) as ScanReport) : null;
  } catch {
    return null;
  }
}
