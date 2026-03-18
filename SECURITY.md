# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.1.x (latest release) | Yes |
| older releases | No |

Always update to the latest release: `innerwarden upgrade`

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/InnerWarden/innerwarden/security/advisories/new) to report securely.

Include:

- InnerWarden version (`innerwarden status`)
- Steps to reproduce
- Impact (what an attacker can do)
- Whether responder was enabled (`dry_run = true` or `false`)

## What We Do

- Acknowledge within 48 hours
- Validate and assess severity
- Fix and release a patched version
- Credit the reporter (unless they prefer anonymity)

## Security Features

Inner Warden includes:

- **Dependency auditing** — cargo-deny runs on every push (RustSec advisories + license compliance)
- **Secrets scanning** — gitleaks + GitHub secret scanning with push protection
- **Automated dependency updates** — Dependabot weekly
- **GitHub Actions pinned to SHA** — prevents supply chain attacks
- **Branch protection** — CI + Security checks required before merge
- **Append-only audit trail** — every decision logged to JSONL, immutable
- **Safe defaults** — dry_run = true, responder disabled, confidence threshold above max on install
