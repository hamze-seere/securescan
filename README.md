# SecureScan 🛡️

**A website security posture scanner.** Enter a URL and get a graded report (A+ to F) covering TLS, security headers, cookies, exposed secrets, email spoofing protection (SPF/DMARC/DKIM), DNS security, CORS and mixed content, with a plain-English explanation and a concrete fix for every issue.

**🔗 Live demo:** https://securescan-hamze.vercel.app

[![CI](https://github.com/hamzeayuub-bot/securescan/actions/workflows/ci.yml/badge.svg)](https://github.com/hamzeayuub-bot/securescan/actions/workflows/ci.yml)
[![Security scan](https://github.com/hamzeayuub-bot/securescan/actions/workflows/security-scan.yml/badge.svg)](https://github.com/hamzeayuub-bot/securescan/actions/workflows/security-scan.yml)

![SecureScan report screenshot](docs/screenshot.png)

> Built with Next.js 16, React 19, TypeScript and Tailwind CSS v4. The scanner engine has **zero runtime dependencies**: it is written directly on Node's `http`, `https`, `tls` and `dns` modules.

---

## Features

| Area | Checks |
|---|---|
| **Transport** | HTTPS availability · certificate validity (self-signed, expired, wrong host, broken chain) · days to expiry · TLS protocol version and cipher · HTTP→HTTPS redirect |
| **Security headers** | HSTS (max-age, includeSubDomains, preload) · CSP *quality* analysis (`unsafe-inline`, `unsafe-eval`, wildcards, nonces, `strict-dynamic`) · clickjacking (XFO / `frame-ancestors`) · `nosniff` · Referrer-Policy · Permissions-Policy · COOP · deprecated X-XSS-Protection |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite`, judged more strictly for session/auth cookies |
| **Exposed files** | `.env`, `.git/HEAD`, `.git/config`, SQL dumps, `wp-config.php.bak`, `phpinfo.php`, `server-status`, `.DS_Store`, with **content signatures** so "soft-404" sites don't produce false positives |
| **Email security** | SPF (missing, `+all`, `?all`, duplicate records, >10 DNS lookups) · DMARC policy, `pct`, reporting, subdomain `sp=` inheritance · DKIM keys across 20 common selectors (revoked keys ignored) · MX records |
| **DNS security** | CAA certificate-authority restrictions (walks up the DNS tree, as the RFC requires) · DNSSEC validation via a validating DNS-over-HTTPS resolver |
| **CORS** | Detects servers that reflect arbitrary origins, especially combined with `Allow-Credentials: true` |
| **Content** | Active/passive mixed content · forms that submit over HTTP |
| **Disclosure** | Versioned `Server` headers · `X-Powered-By` and other stack fingerprints · `security.txt` presence |

Plus:
- **Shareable report links:** unlisted, 30-day links, stored server-side so they can't be forged (see the threat model)
- **PDF export:** a professional multi-page report generated in the browser
- **GitHub Action:** gate deployments on a minimum security grade ([setup below](#github-action))
- Scoring and grading, a severity breakdown, redirect chain, TLS details, raw headers, JSON export, copy as Markdown, and local scan history

## Quick start

```bash
npm install
cp .env.example .env.local
npm run dev        # http://localhost:3000
npm test           # 36 unit + integration tests
```

To scan a site running on your own machine (e.g. a XAMPP project), set `ALLOW_PRIVATE_TARGETS=true` in `.env.local`. This only works in development; the flag is ignored when `NODE_ENV=production`.

### API

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"example.com","authorized":true}'
```

### Deploy

Push to GitHub and import the repo on [Vercel](https://vercel.com). No configuration is needed. Then scan your own deployment: it should get an **A+**.

### Enable share links in production (free)

Locally, share links work out of the box (in-memory store). In production they need Redis:

1. Vercel dashboard → your project → **Storage** → **Create Database** → **Upstash for Redis** (free tier) → connect it to the project.
2. Vercel adds `KV_REST_API_URL` and `KV_REST_API_TOKEN` automatically. **Redeploy**.

Until then, the **Share link** button is simply hidden. Everything else works.

---

## GitHub Action

Use SecureScan as a security gate in any repository. The step fails if the grade drops below `min-grade`, writes a results table to the workflow summary, and (if sharing is enabled) links the full report.

```yaml
# .github/workflows/security.yml
on:
  deployment_status:            # after each deployment (Vercel, Netlify… report these to GitHub)
  schedule:
    - cron: "0 6 * * 1"         # and every Monday
  workflow_dispatch:

jobs:
  security-scan:
    if: github.event_name != 'deployment_status' || github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: hamzeayuub-bot/securescan@main
        id: scan
        with:
          url: https://your-site.com                       # a site you own
          api-url: https://securescan-hamze.vercel.app     # any SecureScan deployment
          min-grade: B                                     # A+, A, B, C, D or F
      - run: echo "Grade ${{ steps.scan.outputs.grade }} - ${{ steps.scan.outputs.report-url }}"
```

| Input | Required | Default | Description |
|---|---|---|---|
| `url` | ✅ | | Site to scan |
| `api-url` | ✅ | | Base URL of a SecureScan deployment |
| `min-grade` | | `B` | Fail below this grade |
| `share` | | `true` | Create a 30-day report link |

Outputs: `grade`, `score`, `report-url`.

This repository uses its own action: [`security-scan.yml`](.github/workflows/security-scan.yml) scans the live site after every production deployment and weekly, and [`ci.yml`](.github/workflows/ci.yml) runs tests, the production build and `npm audit` on every push.

---

## Security design & threat model

A tool that fetches arbitrary user-supplied URLs from a server is itself an attack surface. This section documents the threats and how each one is mitigated.

### 1. Server-Side Request Forgery (SSRF), the main threat
An attacker submits `http://169.254.169.254/latest/meta-data/` (cloud credentials), `http://localhost:6379` (Redis) or an internal admin panel, and uses the scanner as a proxy into the private network.

**Mitigations** (`src/lib/scanner/ssrf.ts`, `httpClient.ts`):
- **Allow-list of schemes and ports:** only `http`/`https` on 80, 443, 8080 and 8443. No `file://`, `gopher://` or credentials in URLs.
- **IP range block-list for IPv4 and IPv6:** loopback, RFC 1918, link-local/metadata, CGNAT, multicast, reserved, unique-local, IPv4-mapped IPv6 (`::ffff:127.0.0.1`), NAT64 and 6to4.
- **Encoding tricks** (`http://2130706433`, `0x7f000001`, `0177.0.0.1`) are normalised by the WHATWG URL parser before the check (covered by tests).
- **DNS rebinding defence:** validation happens inside a custom `lookup` hook *at socket-connect time*, so the IP we validate is the IP we connect to. A hostname that resolves to a public IP during a pre-check and a private IP afterwards cannot get through.
- **Every redirect hop is re-validated**, so a public site can't `302` us into `http://localhost`.

### 2. Denial of service and resource exhaustion
- Per-IP **rate limiting** (5 scans/min by default) on `/api/scan`, returning `429` with `Retry-After`.
- **Timeouts** on every request (8s for the page, 6s for probes) and a cap of 5 redirects.
- **Response size caps** applied *after* decompression (512 KB for the page, 64 KB for probes), which protects against gzip/brotli zip bombs.

### 3. Abuse as an attack tool
- Checks are **passive and non-intrusive**: a handful of `GET` requests for well-known paths. No fuzzing, injection payloads or brute force.
- Users must confirm they **own or are authorised** to test the target, and the API enforces this.
- The scanner identifies itself honestly in its `User-Agent`.

### 4. Cross-site scripting through scan results
Scan results contain attacker-controlled data (headers, cookie names, URLs). Everything is rendered through React, which escapes output. There is no `dangerouslySetInnerHTML` anywhere. As a second layer, the app ships a **nonce-based CSP with `strict-dynamic`** (`src/proxy.ts`).

### 5. Forged reports via share links
If the share endpoint accepted a report from the browser, anyone could publish a fake "Grade F, `.env` exposed!" report about a site they dislike, on a legitimate-looking link under our domain.

**Mitigation** (`src/lib/reports.ts`): the server stores every scan it produces for 1 hour, and `/api/share` only takes a report **id**. It can only publish reports the server itself generated. IDs are random UUIDv4s (122 bits, unguessable) validated with a strict regex (no key injection), shared pages are `noindex`, and links expire after 30 days. Covered by tests.

### 6. Information leakage
- Unexpected errors are logged server-side; clients only get a generic message, never stack traces.
- `poweredByHeader: false` and a full set of security headers (`next.config.ts`).
- Scan history is stored only in the user's own browser (`localStorage`), not on the server.

### Known limitations
- The in-memory rate limiter is per-instance. On serverless platforms, use a shared store such as Upstash Redis.
- TLS checks report the negotiated protocol only. They don't enumerate every supported cipher suite (use `testssl.sh` for that).
- Content checks analyse the initial HTML, not JavaScript-rendered DOM.
- DKIM can only be confirmed for common selector names; custom selectors can't be discovered from DNS.
- Organisational-domain detection (for DMARC/CAA fallback) covers common two-level suffixes (`co.uk`, `edu.so`…) but isn't the full Public Suffix List.
- PDF exports are generated client-side. For an authoritative record, share the server-stored link.

## Project structure

```
src/
├── app/
│   ├── api/scan/route.ts     # POST endpoint: validation, rate limit, error mapping
│   ├── api/share/route.ts    # turns a server-produced scan into a 30-day link
│   ├── r/[id]/page.tsx       # shared report page (noindex)
│   ├── layout.tsx / page.tsx
│   └── globals.css           # Tailwind v4 theme tokens
├── components/               # Scanner (form + history), Report, GradeBadge, SiteChrome
├── lib/
│   ├── rateLimit.ts
│   ├── store.ts              # Upstash Redis REST client / dev memory store
│   ├── reports.ts            # anti-forgery share flow
│   ├── pdf.ts                # PDF report builder (pdf-lib)
│   └── scanner/
│       ├── ssrf.ts           # URL + IP validation
│       ├── httpClient.ts     # hardened HTTP client (safe lookup, size caps, TLS info)
│       ├── dnsClient.ts      # DNS + DNSSEC (DoH) lookups, injectable for tests
│       ├── checks/           # one module per category
│       ├── score.ts          # scoring and grading
│       └── index.ts          # runScan() orchestrator
└── proxy.ts                  # per-request nonce CSP
action.yml + action/          # the GitHub Action
.github/workflows/            # CI and scheduled self-scan
tests/                        # node:test suites incl. an end-to-end scan of an insecure server
```

## Scoring

Each finding has a severity weight (critical 30, high 15, medium 8, low 3). A failed check costs its full weight and a warning costs half. Any **critical** failure (invalid certificate, no HTTPS, exposed `.env`/`.git`/database dump) caps the grade at **F**. An **A+** requires a score of 95 or more, valid HSTS and a strong CSP, and no high or medium failures.

## Ethics

Only scan systems you own or have explicit permission to test. Unauthorised testing may be illegal in your jurisdiction.

## License

MIT
