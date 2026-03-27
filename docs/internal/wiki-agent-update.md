# Agent Capabilities Wiki - New Sections (v0.5.0)

Sections below should be added to the [Agent Capabilities](https://github.com/InnerWarden/innerwarden/wiki/Agent-Capabilities) wiki page.

---

## Kill Chain Integration (v0.5.0)

### Kill Chain Response Skill

New `kill-chain-response` skill performs atomic response when kernel LSM blocks an attack chain:
1. Kills process tree (`pkill -9 -P {pid}`, `kill -9 {pid}`)
2. Blocks C2 IP via XDP (`bpftool map update`)
3. Captures forensics (`ss -tunp`, `/proc/{pid}/` snapshot)

Applicable to: `kill_chain` incidents.

### AI Kill Chain Intelligence

When incidents contain kill chain evidence (`evidence[0].kind` containing "kill_chain"), the AI prompt includes a `KILL CHAIN INTELLIGENCE` section with:
- Pattern name (REVERSE_SHELL, BIND_SHELL, DATA_EXFIL, etc.)
- C2 IP and port
- Process details (PID, UID, comm)
- Syscall timeline
- Confidence assessment

### 8 Kill Chain Patterns

| # | Pattern | Bits | Detection |
|---|---------|------|-----------|
| 1 | REVERSE_SHELL | socket + dup(stdin) + dup(stdout) | Classic reverse shell |
| 2 | BIND_SHELL | bind + listen + dup(stdin) + dup(stdout) | Bind shell |
| 3 | CODE_INJECT | ptrace + mprotect(RWX) | Shellcode injection |
| 4 | EXPLOIT_SHELL | mprotect(RWX) + dup(stdin) + dup(stdout) | Exploit → shell |
| 5 | INJECT_SHELL | ptrace + dup(stdin) | Inject → shell |
| 6 | EXPLOIT_C2 | mprotect(RWX) + socket | Shellcode phone home |
| 7 | FULL_EXPLOIT | mprotect(RWX) + ptrace + socket | Full chain |
| 8 | DATA_EXFIL | sensitive_read + socket | Data exfiltration |

### IPv6 XDP Blocking

XDP now parses both IPv4 (0x0800) and IPv6 (0x86DD). Separate BPF HashMaps:
- `BLOCKLIST` / `ALLOWLIST`: u32 key (IPv4)
- `BLOCKLIST_V6` / `ALLOWLIST_V6`: [u8; 16] key (IPv6)

The `block-ip-xdp` skill auto-detects IP version.

### EFI Runtime Monitoring (EXPERIMENTAL)

Kprobe on `efi_call_rts` monitors UEFI Runtime Services calls. Establishes behavioral baseline of normal firmware/OS interaction. Events tagged as `firmware.efi_call` with severity Debug.

### Telegram Hardening

- 4000-char message limit enforced on all message types
- Rate limiting: 50ms gap between sends (~20 msg/sec)
- Bot token sanitized from log output
- Callback IP validation on quick:block actions
- Config validation at startup (bot_token, chat_id, daily_summary_hour)

### Dashboard

- Kill chain timeline visualization for incidents with chain evidence
- Kill chain metrics card in integrations grid
- `/api/status` includes `kill_chain` counters

---

## Dashboard Updates (v0.4.5)

### Version Badge

The dashboard header displays the current agent version from `CARGO_PKG_VERSION`. The same version string is also returned by `/api/status` and `/api/action/config`.

### Sensor Collectors (15)

The Sensors HUD displays all 15 collectors with live status (detected/active), event count, and kind (native/external).

| # | ID | Display Name | Kind | Description |
|---|-----|-------------|------|-------------|
| 1 | `auth_log` | SSH / Auth Log | native | Parses `/var/log/auth.log` for SSH failures, logins, sudo |
| 2 | `journald` | systemd Journal | native | Tails journald (sshd, sudo, kernel) via `journalctl --follow` |
| 3 | `docker` | Docker Events | native | Docker lifecycle events + privilege escalation detection |
| 4 | `nginx_access` | nginx Access Log | native | nginx access log - search abuse, UA scanner detection |
| 5 | `nginx_error` | nginx Error Log | native | nginx error log - web scanner and probe detection |
| 6 | `exec_audit` | Shell Audit (auditd) | native | auditd EXECVE events - execution guard and shell command trail |
| 7 | `ebpf` | eBPF Kernel | native | 23 kernel hooks: 19 tracepoints + 2 kprobes (privesc + EFI) + LSM (exec block) + XDP (wire-speed IP block) |
| 8 | `suricata_eve` | Suricata IDS | external | Suricata network IDS alerts (alert, dns, http, tls, anomaly) |
| 9 | `wazuh_alerts` | Wazuh HIDS | external | Wazuh HIDS/FIM/compliance alerts |
| 10 | `osquery_log` | osquery | external | osquery differential results (ports, users, crontabs, processes) |
| 11 | `syslog_firewall` | Syslog Firewall | native | iptables/nftables DROP logs from `/var/log/syslog` or `kern.log` |
| 12 | `firmware_integrity` | Firmware Integrity | native | UEFI/EFI boot partition monitoring - detects unauthorized binaries |
| 13 | `cloudtrail` | AWS CloudTrail | external | AWS CloudTrail JSON logs - IAM changes, S3 access, API calls |
| 14 | `macos_log` | macOS Unified Log | native | macOS unified log stream - auth events, process exec, network |
| 15 | `falco_log` | Falco Runtime Security | external | Falco kernel-level runtime security alerts (container + host) |

Collectors 11-15 were added in v0.4.5. The eBPF description was corrected from "6 kernel programs" to "22 kernel hooks". Updated to 23 hooks in v0.5.0 (added EFI kprobe).

### Integration Cards (21)

The Health tab displays 21 integration cards in a 2-column grid. Each card shows ON/OFF badge, NATIVE/EXTERNAL kind, cost note, and a copy-to-clipboard enable/disable command where applicable.

| # | Name | Kind | Description |
|---|------|------|-------------|
| 1 | AI Analysis | native | Analyzes threats and selects the best response action |
| 2 | IP Blocker | native | Automatically blocks IPs via UFW/iptables when AI decides |
| 3 | Honeypot | native | Decoy server that captures and logs attacker behavior |
| 4 | GeoIP | native | Adds country/ISP info to every threat (ip-api.com, 45 req/min) |
| 5 | AbuseIPDB | external | IP reputation + delayed community reporting (5min grace) |
| 6 | XDP Firewall | native | Wire-speed IP blocking at network driver (10M+ pps drop rate) |
| 7 | Telegram | external | Real-time alerts + inline approval buttons |
| 8 | Slack | external | Incident notifications to a Slack team channel |
| 9 | Cloudflare | external | Pushes blocked IPs to Cloudflare edge after block-ip fires |
| 10 | CrowdSec | external | Community threat intelligence - known-bad IP lookup on incident |
| 11 | Prometheus | native | Metrics endpoint at `/metrics` - always available when dashboard is active |
| 12 | PagerDuty | external | On-call alerts via PagerDuty Events API v2 |
| 13 | Opsgenie | external | On-call alerts via Opsgenie Alert API |
| 14 | Sudo Protection | native | Detects privilege abuse and suspends sudo access (11 threat categories) |
| 15 | Execution Guard | native | Structural AST analysis of shell commands via tree-sitter-bash |
| 16 | Mesh Network | native | Collaborative defense - peers exchange block signals with trust scoring |
| 17 | Web Push | native | VAPID-based browser push notifications without Telegram/Slack |
| 18 | Fail2ban Sync | external | Sync blocked IPs with fail2ban jails for unified ban management |
| 19 | Shield (DDoS) | native | Packet flood detection + Cloudflare edge push for volumetric attacks |
| 20 | Threat DNA | native | Attacker fingerprinting and behavioral correlation across sessions (dna_enabled: true; kill chain feeds into DNA) |
| 21 | Kill Chain | native | 8-pattern attack chain detection with atomic response (kill process tree + XDP block + forensic capture) |

Cards 16-20 were added in v0.4.5. Card 21 (Kill Chain) added in v0.5.0. The Integration Advisor now also recommends enabling Mesh.

### Compliance Tab

Redesigned in v0.4.5 with three new sections above the existing admin actions, advisories, and sessions.

**ISO 27001 Control Mapping** - Maps 13 ISO 27001 Annex A controls to current configuration state. Each control shows met/unmet status and the reason. Controls evaluated:

| Control | Name | Condition for "met" |
|---------|------|---------------------|
| A.5.1 | Information security policies | Always met (security agent with automated response policy) |
| A.6.1 | Organization of information security | `ai_enabled = true` |
| A.8.1 | Asset management | Always met (sensor inventory tracks all log sources) |
| A.9.1 | Access control | `sudo_protection_enabled = true` |
| A.10.1 | Cryptography | `chain_length > 0` (decision audit trail uses SHA-256 hash chain) |
| A.12.1 | Operations security | `enabled = true` (automated response enabled) |
| A.12.4 | Logging and monitoring | Always met (39+ detectors, 23 eBPF hooks incl. EFI kprobe, and audit trail) |
| A.12.6 | Technical vulnerability management | `execution_guard_enabled = true` (includes 8 kill chain patterns) |
| A.13.1 | Network security management | `enabled = true && dry_run = false` (guard mode, IPv4 + IPv6 XDP) |
| A.13.2 | Information transfer | eBPF kill chain detection active (DATA_EXFIL pattern) |
| A.16.1 | Incident management | Always met (automated detection, correlation, and response; hardened Telegram delivery) |
| A.18.1 | Compliance | `retention_decisions_days >= 90` |
| A.18.2 | Information security reviews | Always met (daily automated security reports) |

**SHA-256 Hash Chain Verification** - Reads today's `decisions-YYYY-MM-DD.jsonl`, verifies each entry's `prev_hash` matches the SHA-256 digest of the preceding entry. Displays chain length, last hash, and intact/broken status.

**Data Retention Policy Display** - Shows configured retention periods: events (default 7d), incidents (default 30d), decisions (default 90d), telemetry (default 14d), reports (default 30d). Includes GDPR export/erase commands.

All compliance data (admin actions, advisories, sessions, compliance API) is loaded in parallel via `Promise.all`.

---

## API Updates (v0.4.5)

### `GET /api/compliance`

Returns hash chain verification, data retention config, and ISO 27001 control checklist in a single call. Requires authentication.

**Response:**

```json
{
  "hash_chain": {
    "intact": true,
    "length": 42,
    "last_hash": "a1b2c3d4e5f6..."
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
      {
        "id": "A.5.1",
        "name": "Information security policies",
        "met": true,
        "reason": "Security agent with automated response policy"
      }
    ],
    "met": 10,
    "total": 13
  },
  "version": "0.5.0"
}
```

- `hash_chain.intact` - `true` if every entry's `prev_hash` matches the SHA-256 of its predecessor; `false` if any link is broken.
- `hash_chain.length` - number of entries in today's decisions file.
- `hash_chain.last_hash` - SHA-256 hex digest of the last entry (or `"none"` if no decisions today).
- `iso_27001.met` / `iso_27001.total` - count of controls satisfied vs. total evaluated.

### `GET /api/status` - new fields

The following fields were added to the existing `/api/status` response:

```json
{
  "integrations": {
    "mesh": false,
    "web_push": false,
    "shield": false,
    "dna": false,
    "kill_chain": true
  },
  "kill_chain": {
    "patterns_loaded": 8,
    "chains_detected": 0,
    "responses_executed": 0
  },
  "retention": {
    "events_days": 7,
    "incidents_days": 30,
    "decisions_days": 90,
    "telemetry_days": 14,
    "reports_days": 30
  },
  "version": "0.5.0"
}
```

- `integrations.mesh` - whether Mesh collaborative defense is enabled.
- `integrations.web_push` - whether VAPID-based Web Push notifications are configured.
- `integrations.shield` - whether Shield DDoS detection module is enabled.
- `integrations.dna` - whether Threat DNA fingerprinting is enabled.
- `integrations.kill_chain` - whether kill chain detection and response is enabled.
- `kill_chain.patterns_loaded` - number of kill chain patterns loaded (8).
- `kill_chain.chains_detected` - total kill chains detected since agent start.
- `kill_chain.responses_executed` - total kill-chain-response skill executions.
- `retention.*` - configured data retention periods in days.
- `version` - agent version from `CARGO_PKG_VERSION`.

### `GET /api/action/config` - new field

Added `version` field to the response:

```json
{
  "enabled": true,
  "dry_run": false,
  "block_backend": "ufw",
  "allowed_skills": ["block_ip", "monitor_ip"],
  "ai_enabled": true,
  "ai_provider": "openai",
  "ai_model": "gpt-4o-mini",
  "mode": "guard",
  "version": "0.5.0"
}
```

- `version` - agent version string from `CARGO_PKG_VERSION`. Matches the value shown in the dashboard header badge.
