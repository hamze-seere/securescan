/**
 * Key-value storage for share links.
 *
 * - Production: Upstash Redis over its REST API (plain fetch, no SDK). On Vercel,
 *   add it from Storage -> Marketplace -> Upstash (Redis); the env vars are set for you.
 * - Development: an in-memory Map, so sharing works locally with zero setup.
 *
 * In production without Redis configured, sharing is disabled rather than silently
 * using memory (serverless instances don't share memory, so links would break).
 */

export interface KeyValueStore {
  readonly kind: "redis" | "memory";
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
}

function redisConfig(): { url: string; token: string } | null {
  const url = process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url: url.replace(/\/$/, ""), token } : null;
}

/** Counters for rate limiting. Only backed by Redis: memory counters live in rateLimit.ts. */
export interface CounterStore {
  /** Adds 1 to key (creating it with a ttl of ttlSeconds) and returns the new count and seconds left. */
  incr(key: string, ttlSeconds: number): Promise<{ count: number; ttl: number }>;
}

/** Runs several commands in one round trip (Upstash REST /pipeline). */
async function redisPipeline(url: string, token: string, commands: (string | number)[][]): Promise<unknown[]> {
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
    cache: "no-store",
  });
  const data = (await res.json()) as { result?: unknown; error?: string }[];
  if (!res.ok || !Array.isArray(data)) throw new Error(`Redis error: ${res.status}`);
  const failed = data.find((r) => r.error);
  if (failed) throw new Error(`Redis error: ${failed.error}`);
  return data.map((r) => r.result);
}

export function getCounterStore(): CounterStore | null {
  const redis = redisConfig();
  if (!redis) return null;
  return {
    incr: async (key, ttl) => {
      // EXPIRE NX only sets the window on the first hit, so it is a fixed window per key.
      const [count, , left] = await redisPipeline(redis.url, redis.token, [["INCR", key], ["EXPIRE", key, ttl, "NX"], ["TTL", key]]);
      return { count: Number(count), ttl: Number(left) };
    },
  };
}

function redisStore(url: string, token: string): KeyValueStore {
  async function command<T>(args: (string | number)[]): Promise<T> {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(args),
      cache: "no-store",
    });
    const data = (await res.json()) as { result?: T; error?: string };
    if (!res.ok || data.error) throw new Error(`Redis error: ${data.error ?? res.status}`);
    return data.result as T;
  }
  return {
    kind: "redis",
    get: (key) => command<string | null>(["GET", key]),
    set: async (key, value, ttl) => {
      await command(["SET", key, value, "EX", ttl]);
    },
  };
}

// Survives Next.js dev hot-reloads by living on globalThis.
const globalForStore = globalThis as unknown as { __securescanMemory?: Map<string, { value: string; expires: number }> };

function memoryStore(): KeyValueStore {
  const map = (globalForStore.__securescanMemory ??= new Map());
  return {
    kind: "memory",
    get: async (key) => {
      const hit = map.get(key);
      if (!hit) return null;
      if (Date.now() > hit.expires) {
        map.delete(key);
        return null;
      }
      return hit.value;
    },
    set: async (key, value, ttl) => {
      if (map.size > 500) {
        // keep dev memory bounded
        const now = Date.now();
        for (const [k, v] of map) if (v.expires < now) map.delete(k);
        if (map.size > 500) map.delete(map.keys().next().value!);
      }
      map.set(key, { value, expires: Date.now() + ttl * 1000 });
    },
  };
}

/** Returns the configured store, or null when sharing isn't available. */
export function getStore(): KeyValueStore | null {
  const redis = redisConfig();
  if (redis) return redisStore(redis.url, redis.token);
  if (process.env.NODE_ENV !== "production") return memoryStore();
  return null;
}

export const PENDING_TTL = 60 * 60; // a fresh scan can be shared for 1 hour after it ran
export const SHARE_TTL = 60 * 60 * 24 * 30; // shared links live 30 days
export const REPORT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const sharedKey = (id: string) => `securescan:report:${id}`;
