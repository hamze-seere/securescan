import type { Breach } from "@/lib/breach";
import { orgDomain, type DnsClient } from "@/lib/scanner/dnsClient";

/**
 * What can be worked out about an address without any personal lookup: what kind of address it
 * is, who hosts its mail, how old its domain is, and a summary of its breaches. Everything here
 * comes from bundled lists, DNS, the public RDAP registry and the breach results already fetched.
 */

// ---------- Address type ----------

/** Throwaway inbox services. Not exhaustive: the well-known ones. */
export const DISPOSABLE_DOMAINS = new Set([
  "10minutemail.com", "10minutemail.net", "20minutemail.com", "33mail.com", "anonaddy.me", "burnermail.io",
  "byom.de", "discard.email", "dispostable.com", "dropmail.me", "emailondeck.com", "emailfake.com",
  "fakeinbox.com", "fakemail.net", "getairmail.com", "getnada.com", "guerrillamail.biz", "guerrillamail.com",
  "guerrillamail.de", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org", "guerrillamailblock.com",
  "harakirimail.com", "incognitomail.org", "inboxbear.com", "jetable.org", "mail-temp.com", "mail.tm",
  "mailcatch.com", "maildrop.cc", "mailinator.com", "mailinator.net", "mailinator2.com", "mailnesia.com",
  "mailpoof.com", "mailsac.com", "mintemail.com", "mohmal.com", "moakt.com", "mytemp.email", "nada.email",
  "sharklasers.com", "spam4.me", "spambox.us", "spamgourmet.com", "spamex.com", "tempail.com", "tempinbox.com",
  "tempmail.com", "tempmail.net", "tempmail.plus", "tempmailo.com", "temp-mail.io", "temp-mail.org",
  "tempr.email", "throwawaymail.com", "trashmail.com", "trashmail.de", "trashmail.net", "trbvm.com",
  "yopmail.com", "yopmail.fr", "yopmail.net", "grr.la", "pokemail.net", "spamherelots.com", "mailforspam.com",
  "emltmp.com", "tmpmail.org", "tmpmail.net", "tmail.ws", "wegwerfmail.de", "einrot.com", "cuvox.de",
  "dayrep.com", "fleckens.hu", "gustr.com", "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
  "armyspy.com", "1secmail.com", "1secmail.net", "1secmail.org", "linshiyouxiang.net", "minuteinbox.com",
  "inboxkitten.com", "luxusmail.org", "mailbox.in.ua", "fexpost.com", "fextemp.com", "zetmail.com",
]);

/** Free consumer mailbox providers. */
export const FREE_WEBMAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "live.com",
  "msn.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "ymail.com", "rocketmail.com", "aol.com", "icloud.com",
  "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.io", "zoho.com",
  "zohomail.com", "gmx.com", "gmx.net", "gmx.de", "web.de", "mail.com", "yandex.com", "yandex.ru", "mail.ru",
  "inbox.ru", "list.ru", "bk.ru", "qq.com", "163.com", "126.com", "sina.com", "naver.com", "daum.net",
  "fastmail.com", "hey.com", "rediffmail.com", "libero.it", "orange.fr", "laposte.net", "t-online.de",
  "seznam.cz", "wp.pl", "o2.pl", "interia.pl", "btinternet.com", "comcast.net", "verizon.net", "att.net",
]);

/** Local parts that belong to a team or function rather than a person. */
const ROLE_LOCALS = new Set([
  "admin", "administrator", "abuse", "billing", "contact", "hello", "help", "hostmaster", "info", "jobs",
  "mail", "marketing", "noc", "no-reply", "noreply", "office", "postmaster", "privacy", "sales", "security",
  "support", "team", "webmaster", "careers", "accounts", "finance", "hr", "legal", "media", "press",
]);

export type AddressKind = "disposable" | "free" | "custom";

export interface AddressInfo {
  /** disposable = throwaway inbox, free = consumer webmail, custom = an organisation's own domain. */
  kind: AddressKind;
  /** A shared/team address such as info@ or support@. */
  role: boolean;
  /** Uses plus-addressing (name+tag@), which helps trace who leaked or sold an address. */
  plusTag: boolean;
  /** Who hosts the mailbox, from the MX records, e.g. "Google Workspace / Gmail". */
  provider: string | null;
  domainAge: DomainAge | null;
}

export function classifyAddress(email: string): Pick<AddressInfo, "kind" | "role" | "plusTag"> {
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const org = orgDomain(domain);
  const kind: AddressKind = DISPOSABLE_DOMAINS.has(domain) || DISPOSABLE_DOMAINS.has(org)
    ? "disposable"
    : FREE_WEBMAIL.has(domain) ? "free" : "custom";
  const base = local.split("+")[0];
  return { kind, role: ROLE_LOCALS.has(base), plusTag: local.includes("+") && base.length > 0 };
}

// ---------- Mail provider ----------

const PROVIDERS: [RegExp, string][] = [
  [/(^|\.)(google\.com|googlemail\.com)$/, "Google Workspace / Gmail"],
  [/(^|\.)(outlook\.com|hotmail\.com|olc\.protection\.outlook\.com)$/, "Microsoft 365 / Outlook"],
  [/(^|\.)(protonmail\.ch|proton\.me)$/, "Proton Mail"],
  [/(^|\.)zoho(mail)?\.(com|eu|in|com\.au|jp)$/, "Zoho Mail"],
  [/(^|\.)yahoodns\.net$/, "Yahoo Mail"],
  [/(^|\.)icloud\.com$/, "Apple iCloud Mail"],
  [/(^|\.)messagingengine\.com$/, "Fastmail"],
  [/(^|\.)(tutanota\.de|tuta\.io)$/, "Tuta"],
  [/(^|\.)(gmx\.net|gmx\.com|web\.de)$/, "GMX / WEB.DE"],
  [/(^|\.)yandex\.(net|ru)$/, "Yandex Mail"],
  [/(^|\.)mail\.ru$/, "Mail.ru"],
  [/(^|\.)mimecast\.com$/, "Mimecast (security gateway)"],
  [/(^|\.)(pphosted\.com|ppe-hosted\.com)$/, "Proofpoint (security gateway)"],
  [/(^|\.)barracudanetworks\.com$/, "Barracuda (security gateway)"],
  [/(^|\.)mx\.cloudflare\.net$/, "Cloudflare Email Routing"],
  [/(^|\.)improvmx\.com$/, "ImprovMX (forwarding)"],
  [/(^|\.)forwardemail\.net$/, "Forward Email"],
  [/(^|\.)amazonaws\.com$/, "Amazon SES / WorkMail"],
  [/(^|\.)secureserver\.net$/, "GoDaddy"],
  [/(^|\.)privateemail\.com$/, "Namecheap Private Email"],
  [/(^|\.)(ionos\.[a-z.]+|1and1\.[a-z.]+)$/, "IONOS"],
  [/(^|\.)hostinger\.com$/, "Hostinger"],
  [/(^|\.)ovh\.net$/, "OVHcloud"],
];

/** Names the mail host from the lowest-priority (preferred) MX record. */
export function mailProvider(mx: { exchange: string; priority: number }[]): string | null {
  const hosts = [...mx].sort((a, b) => a.priority - b.priority).map((m) => m.exchange.toLowerCase().replace(/\.$/, ""));
  for (const host of hosts) {
    const hit = PROVIDERS.find(([re]) => re.test(host));
    if (hit) return hit[1];
  }
  return hosts.length && hosts[0] ? "Self-hosted or other provider" : null;
}

/** Memoises lookups so the domain checks and the provider lookup share one set of DNS queries. */
export function cachedDns(dns: DnsClient): DnsClient {
  const memo = new Map<string, Promise<unknown>>();
  const once = <T>(key: string, fn: () => Promise<T>): Promise<T> => {
    if (!memo.has(key)) memo.set(key, fn());
    return memo.get(key) as Promise<T>;
  };
  return {
    txt: (n) => once(`txt:${n}`, () => dns.txt(n)),
    mx: (n) => once(`mx:${n}`, () => dns.mx(n)),
    caa: (n) => once(`caa:${n}`, () => dns.caa(n)),
    dnssec: (n) => once(`ds:${n}`, () => dns.dnssec(n)),
  };
}

// ---------- Domain age (RDAP) ----------

export interface DomainAge {
  /** The registered domain that was looked up, e.g. "example.co.uk". */
  domain: string;
  /** ISO date of registration. */
  registered: string;
  days: number;
}

type Fetch = typeof fetch;
const RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json";
const RDAP_TIMEOUT_MS = 5000;
const DAY_MS = 24 * 60 * 60_000;

const rdapCache = globalThis as unknown as {
  __securescanRdapBootstrap?: { at: number; services: [string[], string[]][] };
  __securescanRdapAges?: Map<string, { at: number; value: DomainAge | null }>;
};

async function rdapBaseUrl(tld: string, fetchImpl: Fetch, now: number): Promise<string | null> {
  let boot = rdapCache.__securescanRdapBootstrap;
  if (!boot || now - boot.at > DAY_MS) {
    const res = await fetchImpl(RDAP_BOOTSTRAP, { signal: AbortSignal.timeout(RDAP_TIMEOUT_MS) });
    if (!res.ok) return null;
    const data = (await res.json()) as { services?: unknown };
    if (!Array.isArray(data.services)) return null;
    boot = rdapCache.__securescanRdapBootstrap = { at: now, services: data.services as [string[], string[]][] };
  }
  const service = boot.services.find(([tlds]) => Array.isArray(tlds) && tlds.includes(tld));
  return service?.[1]?.find((u) => typeof u === "string" && u.startsWith("https://")) ?? null;
}

/**
 * When the address's domain was registered, from the public RDAP registry (the modern WHOIS).
 * Very new domains are a common sign of phishing or throwaway senders. Returns null whenever the
 * registry has no answer: many country-code domains have no RDAP service.
 */
export async function domainAge(domain: string, { fetchImpl = fetch, now = Date.now() }: { fetchImpl?: Fetch; now?: number } = {}): Promise<DomainAge | null> {
  const org = orgDomain(domain);
  const cache = (rdapCache.__securescanRdapAges ??= new Map());
  const hit = cache.get(org);
  if (hit && now - hit.at < DAY_MS) return hit.value;

  let value: DomainAge | null = null;
  try {
    const base = await rdapBaseUrl(org.split(".").at(-1)!, fetchImpl, now);
    if (base) {
      const res = await fetchImpl(`${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(org)}`, {
        headers: { accept: "application/rdap+json, application/json" },
        signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
      });
      if (res.ok) {
        const data = (await res.json()) as { events?: { eventAction?: unknown; eventDate?: unknown }[] };
        const reg = data.events?.find((e) => e.eventAction === "registration")?.eventDate;
        const t = typeof reg === "string" ? Date.parse(reg) : NaN;
        if (Number.isFinite(t) && t <= now) {
          value = { domain: org, registered: new Date(t).toISOString().slice(0, 10), days: Math.floor((now - t) / DAY_MS) };
        }
      }
    }
  } catch {
    value = null;
  }
  if (cache.size > 500) cache.delete(cache.keys().next().value!);
  cache.set(org, { at: now, value });
  return value;
}

// ---------- Breach risk summary ----------

export type RiskLevel = "none" | "low" | "medium" | "high";

export interface RiskSummary {
  level: RiskLevel;
  /** Breaches that leaked passwords or password hashes. */
  passwordLeaks: number;
  /** Breaches that leaked phone numbers. The numbers themselves are never returned. */
  phoneLeaks: number;
  /** Breaches that leaked home or postal addresses. */
  addressLeaks: number;
  mostRecent: Breach | null;
  /** Breaches per year, oldest first. */
  byYear: { year: string; count: number }[];
  /** The most common kinds of leaked data, most frequent first. */
  dataTypes: { type: string; count: number }[];
}

export const isPassword = (t: string) => /password/i.test(t);
export const isPhone = (t: string) => /phone/i.test(t);
export const isAddress = (t: string) => /physical address|home address|postal address|^address/i.test(t);

/**
 * high   = a password leaked in the last 3 years, or passwords leaked 5+ times
 * medium = any password leak, or 5+ breaches
 * low    = some breaches, no passwords
 */
export function riskSummary(breaches: Breach[], now = Date.now()): RiskSummary {
  const has = (b: Breach, test: (t: string) => boolean) => b.dataTypes.some(test);
  const withPasswords = breaches.filter((b) => has(b, isPassword));
  const recentYear = new Date(now).getUTCFullYear() - 3;
  const recentPassword = withPasswords.some((b) => Number(b.date?.slice(0, 4)) >= recentYear);

  const years = new Map<string, number>();
  const types = new Map<string, number>();
  for (const b of breaches) {
    const y = b.date?.slice(0, 4);
    if (y && /^\d{4}$/.test(y)) years.set(y, (years.get(y) ?? 0) + 1);
    for (const t of new Set(b.dataTypes)) types.set(t, (types.get(t) ?? 0) + 1);
  }

  const level: RiskLevel = breaches.length === 0 ? "none"
    : recentPassword || withPasswords.length >= 5 ? "high"
    : withPasswords.length > 0 || breaches.length >= 5 ? "medium"
    : "low";

  return {
    level,
    passwordLeaks: withPasswords.length,
    phoneLeaks: breaches.filter((b) => has(b, isPhone)).length,
    addressLeaks: breaches.filter((b) => has(b, isAddress)).length,
    mostRecent: breaches.find((b) => b.date) ?? breaches[0] ?? null,
    byYear: [...years].sort(([a], [b]) => a.localeCompare(b)).map(([year, count]) => ({ year, count })),
    dataTypes: [...types].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8).map(([type, count]) => ({ type, count })),
  };
}
