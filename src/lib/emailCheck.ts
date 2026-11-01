import type { Finding } from "@/lib/scanner/types";
import { createDnsClient, type DnsClient } from "@/lib/scanner/dnsClient";
import { runEmailChecks } from "@/lib/scanner/checks/email";
import { breachSource, BreachProviderError, lookupBreaches, maskEmail, normalizeEmail, SOURCES, type Breach, type BreachResult } from "@/lib/breach";
import { rateLimit } from "@/lib/rateLimit";
import { keyedHash } from "@/lib/reports";
import { cachedDns, classifyAddress, domainAge, mailProvider, riskSummary, type AddressInfo, type DomainAge, type RiskSummary } from "@/lib/emailInsights";
import { verifyConfig } from "@/lib/exposure";

/**
 * The email check: known breaches for one address with a risk summary, what kind of address it
 * is and who hosts it, its domain's age, and how well the domain is protected against spoofing.
 *
 * Privacy rules, because this looks up an address that may not be the visitor's own:
 *  - the address is never logged, stored or put in a share link; the response echoes a masked copy
 *  - the per-address rate limit is keyed by an HMAC of the address, never the address itself
 *  - only breach names, dates and kinds of data are returned, never leaked records
 *  - tight limits per visitor, per address and for the whole site per day
 */

export interface EmailReport {
  /** Masked, e.g. "ha***@example.com". */
  email: string;
  domain: string;
  checkedAt: string;
  source: { name: string; url: string };
  breaches: Breach[];
  /** Number of breaches found; can be more than `breaches.length`, which is capped. */
  breachCount: number;
  /** SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI and MX for the address's domain. Empty if DNS didn't answer in time. */
  domainFindings: Finding[];
  address: AddressInfo;
  risk: RiskSummary;
  /** Whether the owner can verify the address with an emailed code to see the full exposure report. */
  verifyAvailable: boolean;
}

export interface EmailCheckDeps {
  env?: NodeJS.ProcessEnv;
  lookup?: (email: string) => Promise<BreachResult>;
  dns?: DnsClient;
  now?: () => number;
  /** How long the domain checks may take before they're left out. */
  domainTimeoutMs?: number;
  /** Registration date lookup; defaults to RDAP. */
  domainAge?: (domain: string) => Promise<DomainAge | null>;
}

export type EmailCheckResult = { status: number; body: EmailReport | { error: string }; headers?: Record<string, string> };

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
const DOMAIN_CHECK_MS = 8000;

const num = (v: string | undefined, fallback: number) => (v !== undefined && v !== "" && Number.isFinite(Number(v)) ? Number(v) : fallback);

export function emailLimits(env: NodeJS.ProcessEnv = process.env) {
  return {
    perIp: num(env.EMAIL_RATE_LIMIT, 3),
    perAddress: num(env.EMAIL_TARGET_RATE_LIMIT, 3),
    // XposedOrNot's free API allows about 100 lookups a day from one server, so stay under it.
    perDay: num(env.EMAIL_DAILY_LIMIT, breachSource(env) === "hibp" ? 2000 : 90),
  };
}

const tooMany = (error: string, retryAfter: number): EmailCheckResult =>
  ({ status: 429, body: { error }, headers: { "Retry-After": String(retryAfter) } });

const withTimeout = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> =>
  Promise.race([p.catch(() => fallback), new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms).unref?.())]);

export async function checkEmail(body: unknown, ip: string, deps: EmailCheckDeps = {}): Promise<EmailCheckResult> {
  const env = deps.env ?? process.env;
  const limits = emailLimits(env);

  const perIp = await rateLimit(`email:${ip}`, limits.perIp, HOUR);
  if (!perIp.ok) return tooMany(`Too many email checks. Try again in ${Math.ceil(perIp.retryAfter / 60)} min.`, perIp.retryAfter);

  const { email: rawEmail, authorized } = (body ?? {}) as { email?: unknown; authorized?: unknown };
  const parsed = normalizeEmail(rawEmail);
  if (!parsed) return { status: 400, body: { error: "Enter a valid email address." } };
  if (authorized !== true) {
    return { status: 400, body: { error: "Please confirm this is your email address or you have permission to check it." } };
  }

  const perAddress = await rateLimit(`email-addr:${keyedHash("email", parsed.email)}`, limits.perAddress, HOUR);
  if (!perAddress.ok) return tooMany("This address has been checked several times recently. Try again later.", perAddress.retryAfter);

  const daily = await rateLimit("email-daily", limits.perDay, DAY);
  if (!daily.ok) return tooMany("The daily limit for email checks has been reached. Try again tomorrow.", daily.retryAfter);

  const dns = cachedDns(deps.dns ?? createDnsClient());
  const lookup = deps.lookup ?? ((email: string) => lookupBreaches(email, { env }));
  const timeout = deps.domainTimeoutMs ?? DOMAIN_CHECK_MS;
  const kind = classifyAddress(parsed.email);
  const [breaches, domainFindings, mx, age] = await Promise.all([
    lookup(parsed.email).then((r) => ({ ok: true as const, r }), (err: unknown) => ({ ok: false as const, err })),
    withTimeout(runEmailChecks(parsed.domain, dns), timeout, [] as Finding[]),
    withTimeout(dns.mx(parsed.domain), timeout, []),
    // A free webmail domain's age says nothing about the address, so skip the lookup.
    kind.kind === "free" ? null : withTimeout((deps.domainAge ?? domainAge)(parsed.domain), timeout, null),
  ]);

  if (!breaches.ok) {
    if (breaches.err instanceof BreachProviderError) {
      const retry = breaches.err.retryAfter;
      return { status: 503, body: { error: breaches.err.message }, headers: retry ? { "Retry-After": String(retry) } : undefined };
    }
    // Log the error type only: messages from lower layers could contain the address.
    console.error("[email] breach lookup failed:", (breaches.err as Error)?.name ?? "unknown");
    return { status: 500, body: { error: "The email check failed unexpectedly. Please try again." } };
  }

  return {
    status: 200,
    headers: { "X-RateLimit-Remaining": String(perIp.remaining) },
    body: {
      email: maskEmail(parsed.email),
      domain: parsed.domain,
      checkedAt: new Date(deps.now?.() ?? Date.now()).toISOString(),
      source: SOURCES[breaches.r.source],
      breaches: breaches.r.breaches,
      breachCount: breaches.r.total,
      domainFindings,
      address: { ...kind, provider: mailProvider(mx), domainAge: age },
      risk: riskSummary(breaches.r.breaches, deps.now?.() ?? Date.now()),
      verifyAvailable: verifyConfig(env).available,
    },
  };
}
