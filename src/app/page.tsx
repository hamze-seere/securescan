import Scanner from "@/components/Scanner";
import { GITHUB_URL, SiteFooter, SiteHeader } from "@/components/SiteChrome";

export default function Home() {
  return (
    <div className="mx-auto flex min-h-dvh max-w-5xl flex-col px-5 sm:px-8">
      <SiteHeader />
      <main className="flex-1">
        <Scanner />
        <HowItWorks />
        <CiSection />
      </main>
      <SiteFooter />
    </div>
  );
}

const CHECKS = [
  ["Transport", "Certificate validity and expiry, TLS version, HTTP→HTTPS redirect."],
  ["Security headers", "CSP quality, HSTS, clickjacking, MIME sniffing, Referrer- and Permissions-Policy."],
  ["Cookies", "Secure, HttpOnly and SameSite flags, judged more strictly for session cookies."],
  ["Exposed files", ".env, .git, SQL dumps, config backups, phpinfo(), with content signatures to avoid false positives."],
  ["Email security", "SPF strictness and lookup limits, DMARC policy and reporting, DKIM keys, mail servers."],
  ["DNS security", "CAA certificate-authority restrictions (with inheritance) and DNSSEC validation."],
  ["CORS", "Detects servers that reflect arbitrary origins, especially with credentials."],
  ["Content & leaks", "Mixed content, insecure form actions, server and framework version disclosure."],
];

function HowItWorks() {
  return (
    <section id="how" className="mt-28 scroll-mt-8">
      <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-signal">What gets checked</h2>
      <p className="mt-3 max-w-xl text-2xl font-semibold tracking-tight text-balance">
        Over 35 checks across web, email and DNS, each with an explanation and a fix.
      </p>
      <dl className="mt-10 grid gap-px overflow-hidden rounded-xl border border-ink-800 bg-ink-800 sm:grid-cols-2 lg:grid-cols-4">
        {CHECKS.map(([title, text]) => (
          <div key={title} className="bg-ink-900 p-5">
            <dt className="font-medium">{title}</dt>
            <dd className="mt-1.5 text-sm leading-relaxed text-ink-400">{text}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-10 rounded-xl border border-ink-800 bg-ink-900/60 p-5 text-sm leading-relaxed text-ink-300">
        <p className="font-medium text-ink-100">Built to be safe to run in public</p>
        <p className="mt-1.5">
          Scanners that fetch user-supplied URLs are classic SSRF targets. SecureScan validates every DNS answer at
          connect time (defeating DNS rebinding), blocks private, loopback and cloud-metadata ranges for IPv4 and IPv6,
          re-checks every redirect hop, caps response sizes (zip-bomb safe), and rate-limits the API. Shared reports are
          stored server-side, so nobody can forge a report under this domain.
        </p>
      </div>
    </section>
  );
}

const WORKFLOW = `# .github/workflows/security.yml
on:
  deployment_status:
  schedule:
    - cron: "0 6 * * 1"   # every Monday

jobs:
  security-scan:
    if: github.event_name == 'schedule' ||
        github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: hamze-seere/securescan@main
        with:
          url: https://your-site.com
          api-url: https://securescan-hamze.vercel.app
          min-grade: B`;

function CiSection() {
  return (
    <section id="ci" className="mt-24 mb-20 grid scroll-mt-8 gap-8 lg:grid-cols-[1fr_1.2fr] lg:items-start">
      <div>
        <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-signal">DevSecOps</h2>
        <p className="mt-3 text-2xl font-semibold tracking-tight text-balance">Fail the build when security slips.</p>
        <p className="mt-4 leading-relaxed text-ink-300">
          Add the SecureScan GitHub Action to your repository. Every deployment gets scanned automatically, the grade
          shows up in the workflow summary, and the check fails if the grade drops below the minimum you set.
        </p>
        <a href={`${GITHUB_URL}#github-action`} target="_blank" rel="noopener noreferrer" className="mt-6 inline-block text-sm font-medium text-signal hover:underline">
          Read the setup guide →
        </a>
      </div>
      <pre className="overflow-x-auto rounded-xl border border-ink-800 bg-ink-900 p-5 font-mono text-xs leading-relaxed text-ink-300">
        <code className="bg-transparent p-0">{WORKFLOW}</code>
      </pre>
    </section>
  );
}
