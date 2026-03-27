# ISO 27001 Compliance Mapping

## Overview

Inner Warden maps to 13 ISO 27001:2022 Annex A controls through its automated detection, response, and audit capabilities. The mapping is computed at runtime by the `/api/compliance` endpoint and displayed in the dashboard Compliance tab, reflecting the current configuration state. Updated for v0.5.0 with kill chain detection, IPv6 XDP blocking, EFI runtime monitoring, and Telegram hardening.

Controls are evaluated as **Met** or **Not Met** based on which features are enabled. Enabling additional capabilities (AI triage, execution guard, sudo protection, guard mode) increases the number of satisfied controls without code changes.

---

## Control Mapping Table

| Control ID | Control Name | Inner Warden Feature | Status Condition | Evidence |
|------------|-------------|----------------------|------------------|----------|
| A.5.1 | Information security policies | Automated response policy defined in `[responder]` config section | Always met when agent is running | `agent.toml` responder configuration; decisions JSONL audit trail |
| A.6.1 | Organization of information security | AI-driven triage via configured provider (OpenAI, Anthropic, Ollama, etc.) | Met when `ai_enabled = true` | AI decision entries in `decisions-YYYY-MM-DD.jsonl` with provider, model, confidence |
| A.8.1 | Asset management | Sensor inventory tracking 15 collectors (auth_log, journald, docker, nginx x2, exec_audit, eBPF [23 hooks], suricata, wazuh, osquery, syslog_firewall, firmware_integrity, cloudtrail, macos_log, falco_log) | Always met | `/api/sensors` endpoint; Sensors HUD in dashboard |
| A.9.1 | Access control | Sudo protection detector monitors privilege escalation attempts | Met when `sudo_protection_enabled = true` | Incidents with detector `sudo_abuse`; eBPF setuid/commit_creds hooks |
| A.10.1 | Cryptography | SHA-256 hash chain on the decision audit trail; each entry includes `prev_hash` linking to the preceding record | Met when at least one decision has been recorded | `decisions-YYYY-MM-DD.jsonl` with `prev_hash` field; `/api/compliance` hash chain verification |
| A.12.1 | Operations security | Automated response via responder (block-ip, suspend-user, kill-process, block-container, honeypot) | Met when `responder.enabled = true` | Decision entries with `action` and `execution_result` fields |
| A.12.4 | Logging and monitoring | 39+ stateful detectors, 23 eBPF kernel hooks (incl. EFI runtime kprobe for firmware integrity monitoring), continuous collection from all enabled sources | Always met | `events-YYYY-MM-DD.jsonl`, `incidents-YYYY-MM-DD.jsonl`; `/api/sensors`; `firmware.efi_call` events |
| A.12.6 | Technical vulnerability management | Execution guard performs shell command AST analysis via tree-sitter-bash to detect exploit payloads; kill chain detection identifies 8 multi-stage exploitation patterns (REVERSE_SHELL, BIND_SHELL, CODE_INJECT, EXPLOIT_SHELL, INJECT_SHELL, EXPLOIT_C2, FULL_EXPLOIT, DATA_EXFIL) via eBPF syscall correlation | Met when `execution_guard_enabled = true` | Incidents with detector `execution_guard`; `/api/agent/check-command` endpoint; kill chain incidents with `evidence[0].kind = "kill_chain"` |
| A.13.1 | Network security management | Automated IP blocking at multiple layers: XDP (wire-speed, IPv4 + IPv6), iptables/ufw/nftables/pf, Cloudflare WAF; DATA_EXFIL kill chain pattern detects unauthorized data transfer over network sockets; IPv6 XDP blocking via `BLOCKLIST_V6`/`ALLOWLIST_V6` BPF HashMaps | Met when responder is enabled and not in dry-run mode (`enabled = true`, `dry_run = false`) | Decision entries with `action = "block-ip"`; XDP blocklist at `/sys/fs/bpf/innerwarden/blocklist` and `/sys/fs/bpf/innerwarden/blocklist_v6` |
| A.13.2 | Information transfer | DATA_EXFIL kill chain pattern detects unauthorized data transfer by correlating `sensitive_read` syscalls (access to `/etc/shadow`, `/etc/passwd`, private keys) with outbound `socket` connections; `kill-chain-response` skill performs atomic containment (kill process tree, block C2 IP, capture forensics) | Met when eBPF kill chain detection is active | Kill chain incidents with pattern `DATA_EXFIL`; forensic snapshots in `/proc/{pid}/` |
| A.16.1 | Incident management | Full pipeline: detection (39+ detectors) -> correlation (cross-detector confidence boost) -> AI triage -> automated response -> notification (Telegram with hardened delivery: 4000-char limit, 50ms rate limiting, bot token sanitization, callback IP validation, startup config validation; Slack, webhook, Web Push) | Always met | `incidents-YYYY-MM-DD.jsonl`; `decisions-YYYY-MM-DD.jsonl`; notification logs |
| A.18.1 | Compliance | Audit trail retained with configurable retention period (default 90 days for decisions) | Met when `decisions_keep_days >= 90` | `[data]` section in `agent.toml`; data retention enforcement in `data_retention.rs` |
| A.18.2 | Information security reviews | Daily automated security reports with telemetry aggregation | Always met | `report-YYYY-MM-DD.json` files; `/api/report` endpoint; telemetry JSONL |

---

## Data Retention Schedule

All retention periods are configurable in the `[data]` section of `agent.toml`. The data retention module runs on the agent's slow loop (every 30 seconds) and removes files older than the configured thresholds.

| Data Type | Default Retention | Configurable | TOML Key |
|-----------|------------------|--------------|----------|
| Events | 7 days | Yes | `[data] events_keep_days` |
| Incidents | 30 days | Yes | `[data] incidents_keep_days` |
| Decisions (audit trail) | 90 days | Yes | `[data] decisions_keep_days` |
| Telemetry | 14 days | Yes | `[data] telemetry_keep_days` |
| Reports | 30 days | Yes | `[data] reports_keep_days` |

For ISO 27001 A.18.1 compliance, `decisions_keep_days` must be set to 90 or higher. The `/api/compliance` endpoint evaluates this condition at runtime.

---

## Audit Trail

### Hash-chained decisions

Every automated decision is appended to `decisions-YYYY-MM-DD.jsonl`. Each entry contains a `prev_hash` field holding the SHA-256 digest of the preceding entry's serialized JSON. This forms a tamper-evident chain: modifying or deleting any entry breaks the chain from that point forward.

The `/api/compliance` endpoint verifies chain integrity by reading the current day's decisions file and checking that each `prev_hash` matches the computed hash of the previous entry. The response includes:

- `hash_chain.intact` - boolean, whether the chain is unbroken
- `hash_chain.length` - number of entries in today's chain
- `hash_chain.last_hash` - SHA-256 of the most recent entry

### Hash-chained admin actions

Administrative actions (enable, disable, configure, block, allowlist, mesh operations) are recorded in `admin-actions-YYYY-MM-DD.jsonl` with the same SHA-256 hash chain structure. Each entry includes the operator identity and operation parameters.

### Session management

The dashboard supports session-based authentication:

- `POST /api/auth/login` - authenticate with Basic Auth credentials, receive a Bearer token
- `POST /api/auth/logout` - invalidate an active session
- `GET /api/auth/sessions` - list active sessions (tokens are not exposed)

Session configuration:

| Parameter | Default | TOML Key |
|-----------|---------|----------|
| Session timeout | 480 minutes (8 hours) | `[dashboard] session_timeout_minutes` |
| Max concurrent sessions | 5 | `[dashboard] max_sessions` |

Expired sessions are cleaned up automatically every 60 seconds. Login and logout events are recorded in the admin actions audit trail.

### Security controls on the dashboard

- Login rate limiting: 5 failed attempts within 15 minutes triggers IP-level lockout (HTTP 429)
- Actions blocked over insecure HTTP when auth is configured on non-localhost
- Security headers on all responses: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`
- SSE connection limit: max 50 concurrent streams (HTTP 429 on overflow)
- Constant-time username comparison to prevent timing attacks

---

## Dashboard Compliance Tab

The Compliance tab in the embedded dashboard provides a unified view of the organization's compliance posture. It is accessible at the `/compliance` view in the SPA and loads data from multiple endpoints in parallel.

### KPI cards

Four summary cards are displayed at the top:

1. **Active Sessions** - current authenticated session count
2. **Admin Actions** - number of admin actions recorded today
3. **ISO 27001 Controls** - score in the format `N / 13` (controls met out of total)
4. **Hash Chain** - integrity status (`Intact` or `Broken`)

### Sections

1. **Audit Trail Hash Chain** - displays chain length, last hash value, and verification result from `/api/compliance`
2. **Data Retention Policy** - shows configured retention periods for each data type
3. **ISO 27001 Control Mapping** - table of 13 controls with met/not-met status and the specific reason or required action
4. **Admin Actions** - recent entries from today's `admin-actions-YYYY-MM-DD.jsonl`
5. **Trusted Advisor Cache** - current advisory recommendations cache
6. **Active Sessions** - list of authenticated sessions (tokens not displayed)

### API endpoint

`GET /api/compliance` returns a JSON object:

```json
{
  "hash_chain": {
    "intact": true,
    "length": 47,
    "last_hash": "a1b2c3..."
  },
  "retention": {
    "events_days": 7,
    "incidents_days": 30,
    "decisions_days": 90,
    "telemetry_days": 14,
    "reports_days": 30
  },
  "iso_27001": {
    "controls": [
      { "id": "A.5.1", "name": "Information security policies", "met": true, "reason": "..." },
      ...
    ],
    "met": 11,
    "total": 13
  },
  "version": "0.5.0"
}
```

This endpoint requires dashboard authentication (Basic Auth or Bearer token) when authentication is configured.

---

## GDPR Data Subject Rights

Inner Warden provides CLI commands for GDPR compliance (Art. 15 right of access, Art. 17 right to erasure).

### Export

```
innerwarden gdpr export --entity <ip-or-user>
innerwarden gdpr export --entity <ip-or-user> --output /path/to/export.jsonl
```

Scans all data files (events, incidents, decisions, admin-actions, telemetry) for records referencing the specified IP address or username. Matching lines are written to stdout or the specified output file in JSONL format.

### Erase

```
innerwarden gdpr erase --entity <ip-or-user>
innerwarden gdpr erase --entity <ip-or-user> --yes
```

Removes all records matching the specified entity from JSONL data files via atomic rewrite. Hash-chained files (decisions, admin-actions) are recomputed after erasure to maintain chain integrity. The `--yes` flag skips the confirmation prompt.

The erasure operation itself is recorded in the admin-actions audit trail with the operator identity and the erased entity identifier.

---

## Auditor Notes

1. **Control status is dynamic.** The 13 controls reflect the current agent configuration. An auditor should verify the running configuration via `GET /api/compliance` or the dashboard Compliance tab rather than relying on static documentation.

2. **Hash chain verification is automated.** The `/api/compliance` endpoint performs cryptographic verification of the decision audit trail on every call. A `hash_chain.intact = false` result indicates potential tampering and should be investigated.

3. **Retention enforcement is automatic.** The agent's data retention module deletes files older than the configured thresholds. No manual intervention is required. Retention periods can be verified via the API or the `[data]` section of `agent.toml`.

4. **GDPR operations produce audit records.** Both export and erase operations are logged. Erase operations recompute hash chains to maintain audit trail integrity after data removal.

5. **Evidence files** are stored in the agent's data directory (default: `/var/lib/innerwarden/data/`):
   - `decisions-YYYY-MM-DD.jsonl` - hash-chained automated decisions
   - `admin-actions-YYYY-MM-DD.jsonl` - hash-chained administrative actions
   - `incidents-YYYY-MM-DD.jsonl` - detected security incidents
   - `events-YYYY-MM-DD.jsonl` - raw security events
   - `report-YYYY-MM-DD.json` - daily security reports
