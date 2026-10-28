/**
 * Simple in-memory sliding-window rate limiter.
 *
 * Good enough for a single server / demo. On serverless platforms (Vercel) each
 * instance has its own memory, so for production swap this for a shared store
 * such as Upstash Redis (@upstash/ratelimit) - the interface stays the same.
 */
const hits = new Map<string, number[]>();
const MAX_KEYS = 10_000;

export function rateLimit(key: string, limit: number, windowMs = 60_000): { ok: boolean; retryAfter: number; remaining: number } {
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
