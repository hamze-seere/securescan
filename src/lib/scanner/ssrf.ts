import net from "node:net";

/**
 * SSRF protection.
 *
 * A scanner that fetches user-supplied URLs is a textbook Server-Side Request
 * Forgery target: an attacker could ask it to fetch http://169.254.169.254/
 * (cloud metadata), http://localhost:6379 (Redis) or internal admin panels.
 *
 * Defences used here:
 *  1. Only http/https, only standard web ports, no embedded credentials.
 *  2. Every DNS answer is checked against private/reserved ranges *at connect
 *     time* (see httpClient.ts `lookup` hook). Checking at connect time - not just
 *     before the request - defeats DNS-rebinding tricks.
 *  3. Every redirect hop is re-validated with the same rules.
 */

export class BlockedTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlockedTargetError";
  }
}

const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

export function allowPrivateTargets(): boolean {
  return process.env.ALLOW_PRIVATE_TARGETS === "true" && process.env.NODE_ENV !== "production";
}

/** Normalises user input into a URL and applies the static (non-DNS) rules. */
export function parseTargetUrl(input: string): URL {
  const raw = input.trim();
  if (!raw) throw new BlockedTargetError("Please enter a URL.");
  if (raw.length > 2048) throw new BlockedTargetError("URL is too long.");

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new BlockedTargetError("That doesn't look like a valid URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new BlockedTargetError("Only http:// and https:// URLs can be scanned.");
  }
  if (url.username || url.password) {
    throw new BlockedTargetError("URLs with embedded credentials are not allowed.");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new BlockedTargetError("Only standard web ports (80, 443, 8080, 8443) can be scanned.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!allowPrivateTargets()) {
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
      throw new BlockedTargetError("Internal hostnames cannot be scanned.");
    }
    if (net.isIP(host) && isPrivateIp(host)) {
      throw new BlockedTargetError("Private, loopback and reserved IP addresses cannot be scanned.");
    }
    if (!net.isIP(host) && !host.includes(".")) {
      throw new BlockedTargetError("Please use a fully-qualified domain name (e.g. example.com).");
    }
  }

  url.hash = "";
  return url;
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

const IPV4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local + cloud metadata (169.254.169.254)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // 6to4 relay
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];

function isPrivateIpv4(ip: string): boolean {
  const addr = ipv4ToInt(ip);
  return IPV4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (addr & mask) === (ipv4ToInt(base) & mask);
  });
}

/** Expands an IPv6 address into 8 numeric groups. */
function expandIpv6(ip: string): number[] | null {
  let addr = ip.toLowerCase().split("%")[0];
  // Embedded IPv4 (e.g. ::ffff:127.0.0.1) -> convert tail to two hex groups
  const v4 = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = ipv4ToInt(v4[1]);
    addr = addr.replace(v4[1], `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`);
  }
  const [head, tail] = addr.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const missing = 8 - headParts.length - tailParts.length;
  if (addr.includes("::") ? missing < 1 : missing !== 0) return null;
  const parts = [...headParts, ...Array(addr.includes("::") ? missing : 0).fill("0"), ...tailParts];
  return parts.map((p) => parseInt(p, 16));
}

function isPrivateIpv6(ip: string): boolean {
  const g = expandIpv6(ip);
  if (!g || g.some((n) => Number.isNaN(n))) return true; // unparseable -> block
  const allZeroUntil = (i: number) => g.slice(0, i).every((n) => n === 0);

  if (allZeroUntil(8)) return true; // :: unspecified
  if (allZeroUntil(7) && g[7] === 1) return true; // ::1 loopback
  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d -> check the IPv4 part
  if (allZeroUntil(5) && (g[5] === 0xffff || g[5] === 0)) {
    const v4 = `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
    return isPrivateIpv4(v4);
  }
  if (g[0] === 0x64 && g[1] === 0xff9b) return true; // NAT64 64:ff9b::/96 (can reach internal v4)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // 2001:db8::/32 documentation
  if (g[0] === 0x2002) return true; // 6to4 (can embed private v4)
  return false;
}

/** True for any loopback, private, link-local, reserved or otherwise non-public IP. */
export function isPrivateIp(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) return isPrivateIpv4(ip);
  if (family === 6) return isPrivateIpv6(ip);
  return true; // not an IP at all -> refuse
}
