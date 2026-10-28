import Link from "next/link";

export const GITHUB_URL = "https://github.com/hamzeayuub-bot/securescan";

export function SiteHeader() {
  return (
    <header className="flex items-center justify-between py-6">
      <Link href="/" className="flex items-center gap-2.5 font-mono text-sm font-semibold tracking-tight">
        <Logo />
        securescan
      </Link>
      <nav className="flex items-center gap-5 text-sm text-ink-400">
        <Link className="transition-colors hover:text-ink-100" href="/#how">How it works</Link>
        <Link className="transition-colors hover:text-ink-100" href="/#ci">CI / GitHub Action</Link>
        <a className="transition-colors hover:text-ink-100" href={GITHUB_URL} rel="noopener noreferrer" target="_blank">
          GitHub
        </a>
      </nav>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="flex flex-col gap-2 border-t border-ink-800 py-8 text-xs text-ink-400 sm:flex-row sm:justify-between">
      <p>Passive, non-intrusive checks only. Scan sites you own or are authorised to test.</p>
      <p className="font-mono">built with Next.js · SSRF-hardened · strict CSP</p>
    </footer>
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
