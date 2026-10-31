# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/hamze-seere/securescan/security/advisories/new),
not in a public issue.

Include what you found, how to reproduce it, and what an attacker could do with it.
You should get a reply within a few days.

## Scope

- The SecureScan web app and its API (`/api/scan`, `/api/share`, `/api/badge`)
- The GitHub Action (`action.yml`, `action/check.mjs`) and the CLI

Of particular interest: anything that makes the scanner reach an internal or private
address (SSRF), forged share links, and ways around the rate limits.

Please don't scan sites you don't own with the public instance while testing.
