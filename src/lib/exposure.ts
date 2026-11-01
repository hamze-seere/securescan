import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import { lookupBreaches, maskEmail, normalizeEmail, BreachProviderError, type Breach, type BreachResult } from "@/lib/breach";
import { classifyAddress, isAddress, isPassword, isPhone, riskSummary, type RiskSummary } from "@/lib/emailInsights";
import { rateLimit } from "@/lib/rateLimit";
import { keyedHash } from "@/lib/reports";
import { getStore, type KeyValueStore } from "@/lib/store";

/**
 * The owner-only exposure report. Personal details (a public profile photo, which breaches leaked a
 * phone number or home address) are only shown after the visitor proves they own the address by
 * entering a one-time code sent to it. The public check never shows them, because a public site
 * can't tell who is typing an address.
 *
 *  - codes are 6 digits, live 10 minutes, are stored only as an HMAC and work once
 *  - 5 wrong tries per address per 10 minutes, then the address is locked out
 *  - sends are limited per visitor, per address and per day, so the form can't be used to spam
 *  - codes are sent with Resend (RESEND_API_KEY); without a key the feature is off
 *  - EMAIL_VERIFY_DEV_BYPASS=true returns the code in the response instead of emailing it, for
 *    local practice only: it's ignored when NODE_ENV is production
 */

const CODE_TTL = 10 * 60;
const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
const MAX_TRIES = 5;
const AVATAR_MAX_BYTES = 256 * 1024;
const TIMEOUT_MS = 6000;
const USER_AGENT = "SecureScan (+https://github.com/hamze-seere/securescan)";

type Fetch = typeof fetch;
const num = (v: string | undefined, fallback: number) => (v !== undefined && v !== "" && Number.isFinite(Number(v)) ? Number(v) : fallback);

export function verifyConfig(env: NodeJS.ProcessEnv = process.env, store: KeyValueStore | null = getStore()) {
  const devBypass = env.EMAIL_VERIFY_DEV_BYPASS === "true" && env.NODE_ENV !== "production";
  const resendKey = env.RESEND_API_KEY || null;
  return {
    available: !!store && (!!resendKey || devBypass),
    devBypass,
    resendKey,
    from: env.EMAIL_FROM || "SecureScan <onboarding@resend.dev>",
    sendsPerIp: num(env.EMAIL_VERIFY_RATE_LIMIT, 3),
    sendsPerAddress: num(env.EMAIL_VERIFY_TARGET_RATE_LIMIT, 3),
    sendsPerDay: num(env.EMAIL_VERIFY_DAILY_LIMIT, 50),
  };
}

export interface GravatarProfile {
  displayName: string | null;
  location: string | null;
  description: string | null;
  jobTitle: string | null;
  company: string | null;
  profileUrl: string | null;
  /** The photo as a data: URL, fetched by the server so the browser makes no third-party request. */
  avatar: string | null;
  /** Accounts the owner linked and verified on their Gravatar profile. */
  accounts: { service: string; url: string }[];
}

export interface LockDownStep {
  priority: "now" | "soon" | "consider";
  title: string;
  detail: string;
}

export interface ExposureReport {
  email: string;
  verifiedAt: string;
  profile: GravatarProfile | null;
  breachCount: number;
  risk: RiskSummary;
  /** Names of the breaches that leaked each kind of personal data. */
  personalData: { phone: string[]; address: string[]; names: string[]; birthdates: string[]; passwords: string[] };
  steps: LockDownStep[];
}

export interface ExposureDeps {
  env?: NodeJS.ProcessEnv;
  store?: KeyValueStore | null;
  fetchImpl?: Fetch;
  lookup?: (email: string) => Promise<BreachResult>;
  now?: () => number;
}

export type VerifyResult = { status: number; body: Record<string, unknown> | ExposureReport; headers?: Record<string, string> };

const tooMany = (error: string, retryAfter: number): VerifyResult =>
  ({ status: 429, body: { error }, headers: { "Retry-After": String(retryAfter) } });
const otpKey = (email: string) => `securescan:otp:${keyedHash("otp-key", email)}`;
const codeHash = (email: string, code: string) => keyedHash("otp", `${email}:${code}`);

export async function verifyEmail(body: unknown, ip: string, deps: ExposureDeps = {}): Promise<VerifyResult> {
  const env = deps.env ?? process.env;
  const store = deps.store === undefined ? getStore() : deps.store;
  const config = verifyConfig(env, store);
  if (!config.available || !store) {
    return { status: 503, body: { error: "Email verification isn't set up on this server." } };
  }
  const { action, email: rawEmail, code } = (body ?? {}) as { action?: unknown; email?: unknown; code?: unknown };
  const parsed = normalizeEmail(rawEmail);
  if (!parsed) return { status: 400, body: { error: "Enter a valid email address." } };
  if (action === "send") return sendCode(parsed.email, ip, config, store, deps);
  if (action === "confirm") return confirmCode(parsed.email, code, ip, store, deps);
  return { status: 400, body: { error: "action must be \"send\" or \"confirm\"." } };
}

async function sendCode(email: string, ip: string, config: ReturnType<typeof verifyConfig>, store: KeyValueStore, deps: ExposureDeps): Promise<VerifyResult> {
  if (classifyAddress(email).kind === "disposable") {
    return { status: 400, body: { error: "Throwaway inboxes can't be verified." } };
  }
  const perIp = await rateLimit(`otp-send:${ip}`, config.sendsPerIp, HOUR);
  if (!perIp.ok) return tooMany(`Too many codes requested. Try again in ${Math.ceil(perIp.retryAfter / 60)} min.`, perIp.retryAfter);
  const perAddress = await rateLimit(`otp-send-addr:${keyedHash("email", email)}`, config.sendsPerAddress, HOUR);
  if (!perAddress.ok) return tooMany("Several codes were already sent to this address. Try again later.", perAddress.retryAfter);
  const daily = await rateLimit("otp-send-daily", config.sendsPerDay, DAY);
  if (!daily.ok) return tooMany("The daily limit for verification emails has been reached. Try again tomorrow.", daily.retryAfter);

  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  await store.set(otpKey(email), codeHash(email, code), CODE_TTL);

  if (config.devBypass) {
    return { status: 200, body: { sent: true, email: maskEmail(email), devCode: code } };
  }
  const sent = await sendWithResend(email, code, config.resendKey!, config.from, deps.fetchImpl ?? fetch);
  if (!sent) return { status: 503, body: { error: "The verification email couldn't be sent. Try again later." } };
  return { status: 200, body: { sent: true, email: maskEmail(email) } };
}

async function sendWithResend(to: string, code: string, key: string, from: string, fetchImpl: Fetch): Promise<boolean> {
  try {
    const res = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({
        from,
        to: [to],
        subject: `${code} is your SecureScan code`,
        text: `Your SecureScan verification code is ${code}.\n\nIt expires in 10 minutes. If you didn't ask for it, you can ignore this email: nothing happens without the code.`,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) console.error("[verify] Resend refused the email:", res.status);
    return res.ok;
  } catch (err) {
    console.error("[verify] Resend unreachable:", (err as Error)?.name ?? "unknown");
    return false;
  }
}

async function confirmCode(email: string, code: unknown, ip: string, store: KeyValueStore, deps: ExposureDeps): Promise<VerifyResult> {
  const perIp = await rateLimit(`otp-try-ip:${ip}`, 20, HOUR);
  if (!perIp.ok) return tooMany("Too many attempts. Try again later.", perIp.retryAfter);
  if (typeof code !== "string" || !/^\d{6}$/.test(code.trim())) {
    return { status: 400, body: { error: "Enter the 6-digit code from the email." } };
  }
  const tries = await rateLimit(`otp-try:${keyedHash("email", email)}`, MAX_TRIES, CODE_TTL * 1000);
  if (!tries.ok) return tooMany("Too many wrong codes. Request a new code in a few minutes.", tries.retryAfter);

  const stored = await store.get(otpKey(email));
  const given = codeHash(email, code.trim());
  if (!stored || stored.length !== given.length || !timingSafeEqual(Buffer.from(stored), Buffer.from(given))) {
    return { status: 400, body: { error: "That code is wrong or has expired." } };
  }
  await store.set(otpKey(email), "used", 1); // one use only

  const daily = await rateLimit("email-daily", num((deps.env ?? process.env).EMAIL_DAILY_LIMIT, 90), DAY);
  if (!daily.ok) return tooMany("The daily limit for email checks has been reached. Try again tomorrow.", daily.retryAfter);

  const fetchImpl = deps.fetchImpl ?? fetch;
  const lookup = deps.lookup ?? ((e: string) => lookupBreaches(e, { env: deps.env ?? process.env, fetchImpl }));
  const [breaches, profile] = await Promise.all([
    lookup(email).then((r) => ({ ok: true as const, r }), (err: unknown) => ({ ok: false as const, err })),
    gravatarProfile(email, fetchImpl),
  ]);
  if (!breaches.ok) {
    const message = breaches.err instanceof BreachProviderError ? breaches.err.message : "The breach lookup failed. Please try again.";
    return { status: 503, body: { error: message } };
  }
  return { status: 200, body: buildReport(email, breaches.r, profile, deps.now?.() ?? Date.now()) };
}

export function buildReport(email: string, result: BreachResult, profile: GravatarProfile | null, now: number): ExposureReport {
  const names = (test: (t: string) => boolean) => result.breaches.filter((b: Breach) => b.dataTypes.some(test)).map((b) => b.name);
  const personalData = {
    phone: names(isPhone),
    address: names(isAddress),
    names: names((t) => /^names?$|full name/i.test(t)),
    birthdates: names((t) => /birth/i.test(t)),
    passwords: names(isPassword),
  };
  const risk = riskSummary(result.breaches, now);
  return {
    email,
    verifiedAt: new Date(now).toISOString(),
    profile,
    breachCount: result.total,
    risk,
    personalData,
    steps: lockDownSteps(email, risk, personalData, profile),
  };
}

export function lockDownSteps(email: string, risk: RiskSummary, data: ExposureReport["personalData"], profile: GravatarProfile | null): LockDownStep[] {
  const steps: LockDownStep[] = [];
  if (data.passwords.length) {
    steps.push({ priority: "now", title: "Change leaked passwords",
      detail: `Passwords leaked in ${data.passwords.length} breach${data.passwords.length > 1 ? "es" : ""} (${data.passwords.slice(0, 3).join(", ")}${data.passwords.length > 3 ? "…" : ""}). Change them there and anywhere you reused them. A password manager makes every password unique.` });
  }
  if (risk.level !== "none") {
    steps.push({ priority: "now", title: "Turn on two-factor authentication",
      detail: "Start with this email account, then banking and social accounts. Prefer an authenticator app or passkey over SMS codes." });
  }
  if (data.phone.length) {
    steps.push({ priority: "now", title: "Protect your phone number from SIM swaps",
      detail: `Your number leaked in ${data.phone.length} breach${data.phone.length > 1 ? "es" : ""}. Ask your carrier for a port-out PIN or SIM lock, and don't use SMS as the only way to recover important accounts. Expect scam texts and calls that know your name.` });
  }
  if (data.address.length) {
    steps.push({ priority: "soon", title: "Watch for scams that use your home address",
      detail: "Your postal address leaked. Be wary of letters, parcels or callers quoting it to seem legitimate, and consider a credit freeze if your date of birth leaked too." });
  }
  if (data.birthdates.length) {
    steps.push({ priority: "soon", title: "Don't use your birthday as a security answer",
      detail: "Your date of birth leaked, so treat it as public: change any security questions or PINs based on it." });
  }
  if (profile) {
    steps.push({ priority: "consider", title: "Review your public Gravatar profile",
      detail: `Anyone who knows this address can see the photo${profile.accounts.length ? " and linked accounts" : ""} shown below. Edit or hide them at gravatar.com if you don't want them public.` });
  }
  if (!classifyAddress(email).plusTag) {
    steps.push({ priority: "consider", title: "Use a different address per site",
      detail: "Plus-addressing (you+shop@…) or an alias service shows which site leaked or sold your address, and lets you filter it." });
  }
  steps.push({ priority: "consider", title: "Get alerts for new breaches",
    detail: "Subscribe your address to Have I Been Pwned's free notifications so you hear about the next breach quickly." });
  return steps;
}

// ---------- Gravatar ----------

const str = (v: unknown, max = 300): string | null => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
const httpsUrl = (v: unknown): string | null => {
  const s = str(v, 500);
  if (!s) return null;
  try {
    return new URL(s).protocol === "https:" ? s : null;
  } catch {
    return null;
  }
};

/** The public Gravatar profile for an address, or null if there is none. Never throws. */
export async function gravatarProfile(email: string, fetchImpl: Fetch = fetch): Promise<GravatarProfile | null> {
  const hash = createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
  const get = (url: string, accept: string) =>
    fetchImpl(url, { headers: { accept, "user-agent": USER_AGENT }, signal: AbortSignal.timeout(TIMEOUT_MS), cache: "no-store" });
  try {
    const [profileRes, avatar] = await Promise.all([
      get(`https://api.gravatar.com/v3/profiles/${hash}`, "application/json"),
      gravatarAvatar(hash, get),
    ]);
    if (!profileRes.ok) return avatar ? { displayName: null, location: null, description: null, jobTitle: null, company: null, profileUrl: null, avatar, accounts: [] } : null;
    const p = (await profileRes.json()) as Record<string, unknown>;
    const accounts = Array.isArray(p.verified_accounts) ? p.verified_accounts as Record<string, unknown>[] : [];
    return {
      displayName: str(p.display_name, 100),
      location: str(p.location, 100),
      description: str(p.description, 300),
      jobTitle: str(p.job_title, 100),
      company: str(p.company, 100),
      profileUrl: httpsUrl(p.profile_url),
      avatar,
      accounts: accounts
        .filter((a) => a.is_hidden !== true)
        .map((a) => ({ service: str(a.service_label, 40) ?? str(a.service_type, 40) ?? "Link", url: httpsUrl(a.url) }))
        .filter((a): a is { service: string; url: string } => !!a.url)
        .slice(0, 20),
    };
  } catch {
    return null;
  }
}

async function gravatarAvatar(hash: string, get: (url: string, accept: string) => Promise<Response>): Promise<string | null> {
  try {
    // d=404: no default image, so a missing photo is a 404 rather than a generic icon.
    const res = await get(`https://gravatar.com/avatar/${hash}?s=160&d=404`, "image/*");
    const type = res.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
    if (!res.ok || !/^image\/(png|jpeg|gif|webp)$/.test(type)) return null;
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length === 0 || bytes.length > AVATAR_MAX_BYTES) return null;
    return `data:${type};base64,${bytes.toString("base64")}`;
  } catch {
    return null;
  }
}
