import Link from "next/link";
import Scanner from "@/components/Scanner";

export default function Home() {
  return (
    <div className="mx-auto flex min-h-dvh max-w-5xl flex-col px-5 sm:px-8">
      <header className="flex items-center justify-between py-6">
        <Link href="/" className="flex items-center gap-2.5 font-mono text-sm font-semibold tracking-tight">
          <Logo />
          securescan
        </Link>
        <nav className="flex items-center gap-5 text-sm text-ink-400">
          <a className="transition-colors hover:text-ink-100" href="#how">How it works</a>
          <a className="transition-colors hover:text-ink-100" href="https://github.com/" rel="noopener noreferrer" target="_blank">
            GitHub
          </a>
        </nav>
      </header>

      <main className="flex-1">
        <Scanner />
        <HowItWorks />
      </main>

      <footer className="flex flex-col gap-2 border-t border-ink-800 py-8 text-xs text-ink-400 sm:flex-row sm:justify-between">
        <p>Passive, non-intrusive checks only. Scan sites you own or are authorised to test.</p>
        <p className="font-mono">built with Next.js · SSRF-hardened · strict CSP</p>
      </footer>
    </div>
  );
}

function Logo() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2.5 4 5.5v6c0 5 3.4 8.9 8 10 4.6-1.1 8-5 8-10v-6l-8-3Z" stroke="#7cf0b4" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M8 12.2h8" stroke="#7cf0b4" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

const CHECKS = [
  ["Transport", "Certificate validity and expiry, TLS version, HTTP→HTTPS redirect."],
  ["Security headers", "CSP quality, HSTS, clickjacking, MIME sniffing, Referrer- and Permissions-Policy."],
  ["Cookies", "Secure, HttpOnly and SameSite flags, judged more strictly for session cookies."],
  ["Exposed files", ".env, .git, SQL dumps, config backups, phpinfo(), with content signatures to avoid false positives."],
  ["CORS", "Detects servers that reflect arbitrary origins, especially with credentials."],
  ["Content & leaks", "Mixed content, insecure form actions, server and framework version disclosure."],
];

function HowItWorks() {
  return (
    <section id="how" className="mt-28 mb-20 scroll-mt-8">
      <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-signal">What gets checked</h2>
      <p className="mt-3 max-w-xl text-2xl font-semibold tracking-tight text-balance">
        Over 25 checks in under ten seconds, each with an explanation and a fix.
      </p>
      <dl className="mt-10 grid gap-px overflow-hidden rounded-xl border border-ink-800 bg-ink-800 sm:grid-cols-2 lg:grid-cols-3">
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
          re-checks every redirect hop, caps response sizes (zip-bomb safe), and rate-limits the API.
        </p>
      </div>
    </section>
  );
}
