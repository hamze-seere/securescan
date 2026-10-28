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
    matches: (b) => b.includes("Bud1"),
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
];

export type ProbeFetcher = (path: string) => Promise<HttpResponseData | null>;

export async function runExposureChecks(fetchPath: ProbeFetcher): Promise<Finding[]> {
  const results = await Promise.all(
    PROBES.map(async (probe) => {
      const res = await fetchPath(probe.path).catch(() => null);
      if (!res || res.status !== 200) return null;
      const ct = String(res.headers["content-type"] ?? "");
      return probe.matches(res.body, ct) ? probe : null;
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

export function checkSecurityTxt(res: HttpResponseData | null): Finding {
  const base = { id: "security-txt", category: "exposure" as const, title: "security.txt" };
  const ok = res?.status === 200 && /^\s*Contact:/im.test(res.body);
  return ok
    ? { ...base, status: "pass", severity: "low", description: "A security.txt file tells researchers how to report vulnerabilities." }
    : { ...base, status: "info", severity: "info",
        description: "No /.well-known/security.txt. It's optional, but it gives security researchers a clear way to report issues to you.",
        recommendation: "Publish /.well-known/security.txt with `Contact:` and `Expires:` fields (see securitytxt.org)." };
}
