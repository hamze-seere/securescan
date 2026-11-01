/**
 * Email breach lookups.
 *
 * Two providers, chosen by configuration:
 *  - Have I Been Pwned, when HIBP_API_KEY is set (paid key, 10+ lookups a minute)
 *  - XposedOrNot otherwise (free, no key, about 100 lookups a day per server IP)
 *
 * Only the summary of each breach is kept: its name, site, date and the kinds of data that
 * leaked. The address itself is never logged or stored; see lib/emailCheck.ts.
 */

export type BreachSource = "hibp" | "xposedornot";

export interface Breach {
  name: string;
  /** Site the breach came from, when known (e.g. "linkedin.com"). */
  domain: string | null;
  /** "2016-05-17" from HIBP, "2016" from XposedOrNot. */
  date: string | null;
  /** Kinds of data exposed, e.g. ["Email addresses", "Passwords"]. */
  dataTypes: string[];
}

export interface BreachResult {
  source: BreachSource;
  /** Newest first, capped at MAX_BREACHES. */
  breaches: Breach[];
  /** How many breaches the provider reported, before the cap. */
  total: number;
}

/** The provider refused or failed. `retryAfter` is set when it rate-limited us. */
export class BreachProviderError extends Error {
  constructor(message: string, readonly retryAfter?: number) {
    super(message);
    this.name = "BreachProviderError";
  }
}

export const SOURCES: Record<BreachSource, { name: string; url: string }> = {
  hibp: { name: "Have I Been Pwned", url: "https://haveibeenpwned.com" },
  xposedornot: { name: "XposedOrNot", url: "https://xposedornot.com" },
};

const USER_AGENT = "SecureScan (+https://github.com/hamze-seere/securescan)";
const TIMEOUT_MS = 8000;
const MAX_BREACHES = 200;

export function breachSource(env: NodeJS.ProcessEnv = process.env): BreachSource {
  return env.HIBP_API_KEY ? "hibp" : "xposedornot";
}

/**
 * Lower-cases and validates an address. Deliberately simple: enough to reject junk before
 * it reaches a provider, without trying to implement all of RFC 5322.
 */
export function normalizeEmail(input: unknown): { email: string; domain: string } | null {
  if (typeof input !== "string") return null;
  const email = input.trim().toLowerCase();
  if (email.length > 254) return null;
  const m = email.match(/^([a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64})@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$/);
  if (!m || m[1].startsWith(".") || m[1].endsWith(".") || m[1].includes("..")) return null;
  return { email, domain: m[2] };
}

/** "hamze@example.com" -> "ha***@example.com", so results never echo the full address. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  return `${local.slice(0, Math.min(2, Math.max(1, local.length - 1)))}***${email.slice(at)}`;
}

type Fetch = typeof fetch;

export async function lookupBreaches(
  email: string,
  { env = process.env, fetchImpl = fetch }: { env?: NodeJS.ProcessEnv; fetchImpl?: Fetch } = {},
): Promise<BreachResult> {
  const source = breachSource(env);
  const breaches = source === "hibp" ? await hibp(email, env.HIBP_API_KEY!, fetchImpl) : await xposedOrNot(email, fetchImpl);
  breaches.sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
  return { source, breaches: breaches.slice(0, MAX_BREACHES), total: breaches.length };
}

async function get(fetchImpl: Fetch, url: string, headers: Record<string, string> = {}): Promise<Response> {
  try {
    return await fetchImpl(url, {
      headers: { "user-agent": USER_AGENT, accept: "application/json", ...headers },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      cache: "no-store",
    });
  } catch {
    throw new BreachProviderError("The breach database didn't respond. Try again in a minute.");
  }
}

function busy(res: Response): BreachProviderError {
  const retryAfter = Number(res.headers.get("retry-after"));
  return new BreachProviderError(
    "The breach database is busy right now. Try again later.",
    Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
  );
}

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);

interface HibpBreach { Title?: unknown; Name?: unknown; Domain?: unknown; BreachDate?: unknown; DataClasses?: unknown }

async function hibp(email: string, key: string, fetchImpl: Fetch): Promise<Breach[]> {
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const res = await get(fetchImpl, url, { "hibp-api-key": key });
  if (res.status === 404) return []; // HIBP's "not found in any breach"
  if (res.status === 429) throw busy(res);
  if (res.status === 401 || res.status === 403) throw new BreachProviderError("The breach lookup isn't configured correctly on this server.");
  if (!res.ok) throw new BreachProviderError("The breach database returned an error. Try again later.");
  const data = (await res.json().catch(() => null)) as HibpBreach[] | null;
  if (!Array.isArray(data)) throw new BreachProviderError("The breach database returned an unexpected answer.");
  return data.map((b) => ({
    name: str(b.Title) ?? str(b.Name) ?? "Unknown breach",
    domain: str(b.Domain),
    date: str(b.BreachDate),
    dataTypes: Array.isArray(b.DataClasses) ? b.DataClasses.filter((d): d is string => typeof d === "string") : [],
  }));
}

interface XonBreach { breach?: unknown; domain?: unknown; xposed_date?: unknown; xposed_data?: unknown }

async function xposedOrNot(email: string, fetchImpl: Fetch): Promise<Breach[]> {
  const res = await get(fetchImpl, `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`);
  if (res.status === 404) return [];
  if (res.status === 429) throw busy(res);
  if (!res.ok) throw new BreachProviderError("The breach database returned an error. Try again later.");
  const data = (await res.json().catch(() => null)) as { ExposedBreaches?: { breaches_details?: unknown } | null } | null;
  if (!data || typeof data !== "object") throw new BreachProviderError("The breach database returned an unexpected answer.");
  const list = data.ExposedBreaches?.breaches_details;
  if (!Array.isArray(list)) return []; // not found: every section is null
  return (list as XonBreach[]).map((b) => ({
    name: str(b.breach) ?? "Unknown breach",
    domain: str(b.domain),
    date: str(typeof b.xposed_date === "number" ? String(b.xposed_date) : b.xposed_date),
    dataTypes: (str(b.xposed_data) ?? "").split(";").map((d) => d.trim()).filter(Boolean),
  }));
}
