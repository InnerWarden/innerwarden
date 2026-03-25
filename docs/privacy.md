# Privacy and Data Protection

This document describes what personal data Inner Warden collects, how it is processed, how long it is retained, and how data subject rights can be exercised.

Inner Warden is a security monitoring tool. It processes personal data as part of its legitimate interest in protecting servers from unauthorized access and attacks.

---

## Data categories

| Category | Examples | Source | Purpose | Retention |
|----------|----------|--------|---------|-----------|
| IP addresses | Source IPs of SSH connections, HTTP requests, network scans | auth.log, nginx, eBPF, journald | Threat detection, blocking, enrichment | 7 days (events), 30 days (incidents) |
| Usernames | SSH login attempts, sudo commands, system users | auth.log, exec_audit, journald | Privilege abuse detection, incident correlation | 7 days (events), 30 days (incidents) |
| Shell commands | Commands executed via bash, sudo, cron | exec_audit (opt-in), eBPF execve | Reverse shell detection, execution guard | 7 days (events) |
| User agents | HTTP client identifiers | nginx access logs | Bot detection, scanner identification | 7 days (events) |
| SSH public keys | Key fingerprints from authentication | auth.log | Key injection detection | 7 days (events) |
| Process metadata | PID, PPID, executable path, arguments | eBPF tracepoints, /proc | Process tree analysis, kill chain detection | 7 days (events) |
| Network connections | Destination IP, port, protocol | eBPF connect tracepoint | C2 callback detection, data exfiltration | 7 days (events) |
| Container IDs | Docker container names and IDs | Docker events, cgroup_id | Container escape detection | 7 days (events) |
| Operator identity | Unix username of admin performing actions | CTL commands, dashboard login | Admin action audit trail | 90 days (admin-actions) |

### Data minimization

- Shell command auditing is **opt-in only** and requires explicit operator consent before activation
- Internal/private IP addresses are filtered from incident generation (no alerts for 127.0.0.1, 10.0.0.0/8, etc.)
- Event details are capped at 16KB per event
- Forensic reports redact environment variables matching KEY, SECRET, TOKEN, PASSWORD patterns
- AI provider prompts sanitize incident data (control characters removed, whitespace collapsed)

---

## Data flows to third parties

| Service | Data sent | Purpose | When | Configurable |
|---------|-----------|---------|------|-------------|
| **AbuseIPDB** | Attacker IP + attack category | Community threat intelligence reporting | On block decision (if enabled) | Yes, opt-in via `abuseipdb.api_key` |
| **Cloudflare** | Attacker IP | Edge-level WAF blocking | On block decision (if enabled) | Yes, opt-in via `cloudflare.api_token` |
| **AI providers** | Incident summary (sanitized) | Confidence-scored triage recommendation | On incident (if AI enabled) | Yes, opt-in via `ai.enabled` |
| **GeoIP service** | Attacker IP | Country/ISP geolocation for enrichment | On incident (if enabled) | Yes, opt-in via `geoip.enabled` |
| **CrowdSec** | Attacker IP | Community reputation check | On incident (if enabled) | Yes, opt-in via `crowdsec.api_key` |
| **Telegram** | Incident summary (no raw PII) | Operator notification | On incident (if configured) | Yes, opt-in via `telegram.bot_token` |
| **Slack** | Incident summary (no raw PII) | Operator notification | On incident (if configured) | Yes, opt-in via `slack.webhook_url` |
| **Webhook** | Incident JSON payload | Integration with external systems | On incident (if configured) | Yes, opt-in via `webhook.url` |

All third-party integrations are **disabled by default**. No data leaves the server unless explicitly configured.

AI providers receive sanitized incident summaries, not raw logs. The AI never sees full shell commands, passwords, or private keys.

---

## Retention schedule

| Data type | File pattern | Default retention | Configurable |
|-----------|-------------|-------------------|-------------|
| Raw events | `events-YYYY-MM-DD.jsonl` | 7 days | `data.events_keep_days` |
| Incidents | `incidents-YYYY-MM-DD.jsonl` | 30 days | `data.incidents_keep_days` |
| Decisions (audit trail) | `decisions-YYYY-MM-DD.jsonl` | 90 days | `data.decisions_keep_days` |
| Admin actions (audit trail) | `admin-actions-YYYY-MM-DD.jsonl` | 90 days | Same as decisions |
| Telemetry | `telemetry-YYYY-MM-DD.jsonl` | 30 days | `data.telemetry_keep_days` |
| Reports | `trial-report-YYYY-MM-DD.*` | 90 days | `data.reports_keep_days` |
| Forensic snapshots | `forensics-*.json` | 30 days | `data.incidents_keep_days` |
| Daily narratives | `summary-YYYY-MM-DD.md` | 7 days | `narrative.keep_days` |

Retention is enforced automatically by the agent on startup and daily. Files older than the configured retention period are permanently deleted.

---

## Data subject rights

Inner Warden provides CLI commands to support GDPR data subject rights.

### Right of access (export)

Export all records associated with an IP address or username:

```bash
innerwarden gdpr export --entity 203.0.113.10
innerwarden gdpr export --entity john --output /tmp/john-data.jsonl
```

This searches all JSONL files (events, incidents, decisions, admin-actions, telemetry) and outputs matching records.

### Right to erasure

Erase all records associated with an IP address or username:

```bash
innerwarden gdpr erase --entity 203.0.113.10
innerwarden gdpr erase --entity john --yes  # skip confirmation
```

This rewrites JSONL files excluding matching records. Hash chains in decision and admin-action files are recomputed after erasure. An audit trail entry is written recording the erasure action.

### Right to rectification

Individual records can be corrected by:
1. Exporting the record (`innerwarden gdpr export --entity ...`)
2. Erasing the original (`innerwarden gdpr erase --entity ...`)
3. The corrected data would need to be re-ingested through the normal pipeline

### Right to restrict processing

Add an entity to the allowlist to prevent future processing:

```bash
innerwarden allowlist add --ip 203.0.113.10
innerwarden allowlist add --user john
```

Allowlisted entities are excluded from AI triage and response actions.

---

## Legal basis

Inner Warden processes personal data under **legitimate interest** (GDPR Article 6(1)(f)) for the purpose of:

- Protecting computer systems from unauthorized access
- Detecting and responding to security incidents
- Maintaining audit trails for compliance and forensic investigation
- Sharing threat intelligence with community databases (when explicitly configured)

The processing is proportionate: only security-relevant data is collected, retention is bounded, and data subjects can exercise their rights via the GDPR commands.

---

## Audit trail integrity

Decision and admin-action logs use SHA-256 hash chaining for tamper detection. Each entry includes the hash of the previous entry, creating a cryptographic chain that breaks if any historical record is modified. This ensures the integrity of the audit trail for compliance purposes.

---

## Configuration for compliance

For GDPR-compliant deployments, consider:

```toml
[data]
events_keep_days = 7          # minimize raw event retention
incidents_keep_days = 30
decisions_keep_days = 90      # audit trail — adjust per regulation
```

- Disable unnecessary third-party integrations
- Enable shell audit only with documented consent
- Review allowlist regularly
- Run `innerwarden gdpr export` before retention cleanup if you need longer-term records
- Document your data processing activities in your organization's Record of Processing Activities (ROPA)

---

## Data Processing Agreement

For enterprise customers requiring a formal Data Processing Agreement (DPA), contact the Inner Warden team. Since Inner Warden runs entirely on your infrastructure with no cloud component, the DPA scope is limited to third-party integrations you choose to enable.
