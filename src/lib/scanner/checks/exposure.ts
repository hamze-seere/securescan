import type { Finding, HttpResponseData, Severity } from "../types";

/**
 * Well-known files that should never be publicly reachable.
 * Each probe has a content signature so a "soft 404" (a site that returns 200
 * for every URL) does not produce false positives.
 */
export interface Probe {
  path: string;
  title: string;
  severity: Severity;
  why: string;
  matches: (body: string, contentType: string) => boolean;
}

export const PROBES: Probe[] = [
  {
    path: "/.env",
    title: "Environment file (.env) exposed",
    severity: "critical",
    why: "`.env` files usually contain database passwords, API keys and app secrets.",
    matches: (b, ct) => !/html/i.test(ct) && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(b),
  },
  {
    path: "/.git/HEAD",
    title: "Git repository exposed",
    severity: "critical",
    why: "An exposed `.git` folder lets anyone download your full source code and commit history, including secrets that were ever committed.",
    matches: (b) => /^ref:\s*refs\/heads\//.test(b.trim()) || /^[0-9a-f]{40}$/.test(b.trim()),
  },
  {
    path: "/.git/config",
    title: "Git config exposed",
    severity: "high",
    why: "Reveals repository remotes and sometimes credentials embedded in remote URLs.",
    matches: (b) => /\[core\]/.test(b) && /repositoryformatversion/.test(b),
  },
  {
    path: "/phpinfo.php",
    title: "phpinfo() page exposed",
    severity: "medium",
    why: "phpinfo() reveals PHP version, modules, paths and environment variables.",
    matches: (b) => /phpinfo\(\)|<title>PHP \d/i.test(b) && /PHP Version/i.test(b),
  },
  {
    path: "/server-status",
    title: "Apache server-status exposed",
    severity: "medium",
    why: "Shows live requests, client IPs and internal URLs being accessed.",
    matches: (b) => /Apache Server Status/i.test(b),
  },
  {
    path: "/.DS_Store",
    title: ".DS_Store file exposed",
    severity: "low",
    why: "macOS folder metadata that reveals the names of files in the directory, including hidden ones.",
    // Binary format: 4-byte header, then the "Bud1" magic.
    matches: (b) => b.slice(4, 8) === "Bud1",
  },
  {
    path: "/wp-config.php.bak",
    title: "WordPress config backup exposed",
    severity: "critical",
    why: "Backup copies of wp-config.php are served as plain text, revealing database credentials.",
    matches: (b) => /DB_PASSWORD/.test(b),
  },
  {
    path: "/backup.sql",
    title: "Database dump exposed",
    severity: "critical",
    why: "A public SQL dump leaks your entire database.",
    matches: (b, ct) => !/html/i.test(ct) && /(CREATE TABLE|INSERT INTO)/i.test(b),
  },
  {
    path: "/.env.local",
    title: "Local environment file exposed",
    severity: "critical",
    why: "`.env.local` holds local overrides, usually real API keys and passwords.",
    matches: (b, ct) => !/html/i.test(ct) && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(b),
  },
  {
    path: "/.env.production",
    title: "Production environment file exposed",
    severity: "critical",
    why: "`.env.production` contains the secrets of the live site.",
    matches: (b, ct) => !/html/i.test(ct) && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(b),
  },
  {
    path: "/.git/index",
    title: "Git index exposed",
    severity: "high",
    why: "The Git index lists every file in the repository, and tools can use it to rebuild the source code.",
    matches: (b) => b.startsWith("DIRC"),
  },
  {
    path: "/.svn/wc.db",
    title: "Subversion metadata exposed",
    severity: "high",
    why: "An exposed `.svn` folder lets anyone list and download the source code.",
    matches: (b) => b.startsWith("SQLite format 3"),
  },
  {
    path: "/.htpasswd",
    title: "Password file (.htpasswd) exposed",
    severity: "high",
    why: "`.htpasswd` holds usernames and password hashes for HTTP basic auth, which can be cracked offline.",
    matches: (b, ct) => !/html/i.test(ct) && /^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)/m.test(b),
  },
  {
    path: "/backup.zip",
    title: "Site backup archive exposed",
    severity: "critical",
    why: "A downloadable archive of the site usually includes source code, config files and credentials.",
    matches: (b) => b.startsWith("PK\x03\x04"),
  },
  {
    path: "/dump.sql",
    title: "Database dump exposed",
    severity: "critical",
    why: "A public SQL dump leaks your entire database.",
    matches: (b, ct) => !/html/i.test(ct) && /(CREATE TABLE|INSERT INTO)/i.test(b),
  },
  {
    path: "/docker-compose.yml",
    title: "docker-compose.yml exposed",
    severity: "medium",
    why: "Reveals the internal service layout and often contains passwords in environment variables.",
    matches: (b, ct) => !/html/i.test(ct) && /^services\s*:/m.test(b) && /^\s+(image|build)\s*:/m.test(b),
  },
  {
    path: "/actuator/env",
    title: "Spring Boot actuator exposed",
    severity: "high",
    why: "`/actuator/env` dumps the application's environment and configuration, often including secrets.",
    matches: (b, ct) => /json/i.test(ct) && /"(activeProfiles|propertySources)"/.test(b),
  },
  {
    path: "/.aws/credentials",
    title: "AWS credentials file exposed",
    severity: "critical",
    why: "Contains AWS access keys that give direct access to your cloud account.",
    matches: (b, ct) => !/html/i.test(ct) && /aws_access_key_id\s*=/i.test(b),
  },
];

export type ProbeFetcher = (path: string) => Promise<HttpResponseData | null>;

/** A path that cannot exist, used to learn what this site returns for "not found". */
export const SOFT_404_PATH = "/securescan-not-found-7c1e9a";

const normalise = (s: string) => s.replace(/\s+/g, " ").trim();

export async function runExposureChecks(fetchPath: ProbeFetcher): Promise<Finding[]> {
  // Fetched alongside the probes: if the site answers every path with the same page, a probe
  // that returns exactly that page is a soft 404, whatever its signature says.
  const baselinePromise = fetchPath(SOFT_404_PATH).catch(() => null);
  const results = await Promise.all(
    PROBES.map(async (probe) => {
      const res = await fetchPath(probe.path).catch(() => null);
      if (!res || res.status !== 200 || !res.body) return null;
      const ct = String(res.headers["content-type"] ?? "");
      if (!probe.matches(res.body, ct)) return null;
      const baseline = await baselinePromise;
      if (baseline?.status === 200 && normalise(baseline.body) === normalise(res.body)) return null;
      return probe;
    }),
  );

  const exposed = results.filter((p): p is Probe => p !== null);
  if (exposed.length === 0) {
    return [{
      id: "exposure-ok", category: "exposure", title: "Sensitive files",
      status: "pass", severity: "critical",
      description: `None of the ${PROBES.length} commonly leaked files (.env, .git, backups, phpinfo…) are publicly accessible.`,
    }];
  }
  return exposed.map((p) => ({
    id: `exposed-${p.path}`, category: "exposure" as const, title: p.title,
    status: "fail" as const, severity: p.severity, evidence: `GET ${p.path} → 200 (content matched)`,
    description: p.why,
    recommendation: `Block access to \`${p.path}\` in your web server config, move it outside the web root, and rotate any secrets it contained.`,
  }));
}

/**
 * @param res The /.well-known/security.txt response (after redirects), or the legacy /security.txt
 *   one when the first was missing.
 */
export function checkSecurityTxt(res: HttpResponseData | null, now = new Date()): Finding {
  const base = { id: "security-txt", category: "exposure" as const, title: "security.txt" };
  const recommendation = "Publish /.well-known/security.txt with `Contact:` and `Expires:` fields (see securitytxt.org).";
  const ct = String(res?.headers["content-type"] ?? "");
  const found = res?.status === 200 && !/html/i.test(ct) && /^\s*Contact:/im.test(res.body);
  if (!found) {
    return { ...base, status: "info", severity: "info", recommendation,
      description: "No /.well-known/security.txt. It's optional, but it gives security researchers a clear way to report issues to you." };
  }
  const location = new URL(res.url).pathname;
  const legacy = location !== "/.well-known/security.txt" ? ` It is served at \`${location}\`; RFC 9116 expects \`/.well-known/security.txt\`.` : "";
  const contact = res.body.match(/^\s*Contact:\s*(\S+)/im)?.[1];
  // Placeholder addresses left over from templates are as good as no contact at all.
  if (contact && /your-domain|example\.(com|org|net)\b/i.test(contact)) {
    return { ...base, status: "warn", severity: "low", evidence: `Contact: ${contact}`, recommendation,
      description: `security.txt still contains a placeholder contact (${contact}), so reports go nowhere.${legacy}` };
  }
  const expiresRaw = res.body.match(/^\s*Expires:\s*(.+)$/im)?.[1]?.trim();
  const expires = expiresRaw ? new Date(expiresRaw) : null;
  if (!expires || Number.isNaN(expires.getTime())) {
    return { ...base, status: "warn", severity: "low", evidence: expiresRaw ? `Expires: ${expiresRaw}` : undefined, recommendation,
      description: `security.txt has a contact but ${expiresRaw ? "an unreadable" : "no"} \`Expires:\` date, which RFC 9116 requires so stale files are not trusted.${legacy}` };
  }
  if (expires.getTime() < now.getTime()) {
    return { ...base, status: "warn", severity: "low", evidence: `Expires: ${expiresRaw}`,
      recommendation: "Update the `Expires:` date (keep it less than a year ahead) and check the contact details are still current.",
      description: `security.txt expired on ${expires.toISOString().slice(0, 10)}, so researchers should treat its contact details as out of date.${legacy}` };
  }
  return { ...base, status: "pass", severity: "low", evidence: `Contact: ${contact}\nExpires: ${expiresRaw}`,
    description: `A security.txt file tells researchers how to report vulnerabilities.${legacy}` };
}
