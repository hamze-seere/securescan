import { getCounterStore } from "@/lib/store";

/**
 * Rate limiting.
 *
 * With Upstash Redis configured (production on Vercel), counts live in Redis so every
 * serverless instance sees the same numbers: a fixed window per key (INCR + EXPIRE).
 * Without it, or if Redis is unreachable, each instance falls back to an in-memory
 * sliding window, which still slows down a single abusive client.
 */

export interface RateLimitResult {
  ok: boolean;
  retryAfter: number;
  remaining: number;
}

const hits = new Map<string, number[]>();
const MAX_KEYS = 10_000;

export function memoryRateLimit(key: string, limit: number, windowMs = 60_000): RateLimitResult {
  const now = Date.now();
  const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);

  if (recent.length >= limit) {
    hits.set(key, recent);
    return { ok: false, retryAfter: Math.ceil((windowMs - (now - recent[0])) / 1000), remaining: 0 };
  }

  recent.push(now);
  hits.set(key, recent);

  // Keep memory bounded if we get hammered by many IPs.
  if (hits.size > MAX_KEYS) {
    for (const [k, times] of hits) {
      if (times.every((t) => now - t >= windowMs)) hits.delete(k);
    }
  }
  return { ok: true, retryAfter: 0, remaining: limit - recent.length };
}

export async function rateLimit(key: string, limit: number, windowMs = 60_000): Promise<RateLimitResult> {
  const store = getCounterStore();
  if (store) {
    try {
      const windowSeconds = Math.max(1, Math.ceil(windowMs / 1000));
      const { count, ttl } = await store.incr(`securescan:rl:${key}`, windowSeconds);
      return count > limit
        ? { ok: false, retryAfter: ttl > 0 ? ttl : windowSeconds, remaining: 0 }
        : { ok: true, retryAfter: 0, remaining: limit - count };
    } catch (err) {
      console.error("[rate-limit] Redis unavailable, using memory", err);
    }
  }
  return memoryRateLimit(key, limit, windowMs);
}

/** The caller's IP. On Vercel the platform sets x-forwarded-for; its first entry is the real client. */
export function clientIp(headers: Headers): string {
  return headers.get("x-forwarded-for")?.split(",")[0].trim() || headers.get("x-real-ip")?.trim() || "unknown";
}
