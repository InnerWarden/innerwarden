# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.4.0] — 2026-03-23

### New detectors
- **Fileless malware** — detects execution via memfd_create, /proc/self/fd, deleted binaries
- **Log tampering** — detects unauthorized access to auth.log, syslog, wtmp, btmp
- **DNS tunneling** — Shannon entropy analysis on subdomains + eBPF fallback for port 53 beaconing (works without Suricata)
- **Lateral movement** — detects internal SSH scanning, port scanning, and sensitive service probing on private networks

### Agent improvements
- **Adaptive blocking** — repeat offenders get escalating TTL (1h → 4h → 24h → 7d)
- **Local IP reputation** — per-IP scoring persisted to disk, exposed in live-feed API
- **Automated forensics** — captures /proc/{pid}/ data (cmdline, exe, fds, network, memory maps) on High/Critical incidents with PID
- **Configurable AI gate** — `ai.min_severity` setting: "high" (default, conservative) or "medium" (aggressive, more API calls)
- **Honeypot always-on mode** — SSH honeypot with AI-powered fake shell, accepts password auth to lure attackers
- **Live feed API** — real daily totals (total_today, total_blocked, total_high), honeypot sessions endpoint, server-side GeoIP proxy

### Hardening advisor
- **TLS/SSL check** — audits nginx, apache, and OpenSSL configs for deprecated protocols, weak ciphers, missing HSTS
- **Crontab audit** — scans for suspicious entries (download+execute, reverse shells, base64)
- **Kernel modules** — detects known rootkits (diamorphine, reptile, etc)
- **Accepted risks** — `/etc/innerwarden/harden-ignore.toml` for environment-specific exceptions
- **Accuracy fixes** — excludes Inner Warden/Docker services from findings, uses `sudo ufw status verbose`

### Security fixes
- Path validation for ip-reputation and sensors API (CodeQL CWE-22 #37, #38)

---

## [0.3.1] — 2026-03-22

### Hardening advisor + live threat feed

- **`innerwarden harden`** — security hardening advisor that scans SSH, firewall, kernel params, file permissions, pending updates, Docker config, and exposed services. Prints actionable fix commands with severity scoring (0-100). Advisory only — never applies changes.
- **Live threat feed API** — public `/api/live-feed` and `/api/live-feed/stream` (SSE) endpoints with CORS for real-time incident display on external sites. Includes `/api/live-feed/geoip` proxy for server-side GeoIP batch lookups.
- **Dashboard bind fix** — `tower-http` CORS layer added to agent for cross-origin live feed access.

---

## [0.3.0] — 2026-03-21

### Deep kernel security + intelligent response

- **XDP wire-speed firewall** — blocks IPs at the network driver level (10M+ pps drop rate). Pinned BPF map at `/sys/fs/bpf/innerwarden/blocklist` managed by agent via bpftool.
- **kprobe privilege escalation** — hooks kernel `commit_creds` function to detect real-time uid transitions from non-root to root through unexpected paths.
- **LSM execution blocking** — BPF LSM hook on `bprm_check_security` blocks binary execution from /tmp, /dev/shm, /var/tmp. Policy-gated, off by default, auto-enables on high-severity threats.
- **XDP allowlist** — operator IPs never dropped, checked before blocklist in kernel.
- **Layered blocking** — single block decision triggers XDP + firewall + Cloudflare + AbuseIPDB in one action.
- **Cross-detector correlation** — same IP in multiple detectors boosts AI confidence (1.15x for 2, 1.30x for 3, 1.50x for 4+).
- **LSM auto-enable** — agent automatically activates kernel execution blocking when it detects download+execute or reverse shell incidents.
- **Smart honeypot routing** — suspicious_login attackers (brute-force followed by success) redirected to honeypot; 20% of new attackers sampled; rest blocked via XDP.
- **AbuseIPDB delayed reporting** — reports queued 5 minutes before sending to allow false-positive correction.
- **Block rate limiter** — max 20 blocks per minute to prevent false-positive cascades.
- **XDP TTL** — blocked IPs auto-expire after 24 hours.
- **LSM process allowlist** — package managers (dpkg, apt, dnf), compilers (gcc, cargo), and system processes always allowed to execute from /tmp.
- **Sensor HUD dashboard** — new default home page with Chart.js area timeline, threat gauge, polar area detector chart. Design matches innerwarden.com (surface-card, cyber-gradient-text, JetBrains Mono).
- **Removed Falco integration** — superseded by native eBPF (kprobe + LSM deeper than Falco's tracepoints).
- **Deprecated Fail2ban** — native detectors + XDP firewall are faster and smarter.

19 detectors, 11 skills, 6 eBPF kernel programs, 692 tests.

---

## [0.2.0] — 2026-03-21

### Phase 2 — eBPF Deep Visibility

- **eBPF kernel tracing** — 3 tracepoints running in production (execve, connect, openat) via Aya framework on kernel 6.8
- **Container awareness** — `cgroup_id` captured in kernel space via `bpf_get_current_cgroup_id()`, container IDs resolved from `/proc/<pid>/cgroup` (Docker, Podman, k8s)
- **Process tree tracking** — ppid resolved via `/proc/<pid>/status`, full parent-child chain in event details
- **C2 callback detector** — beaconing analysis (coefficient of variation), C2 port monitoring, data exfiltration detection (10+ unique IPs from one process)
- **Process tree detector** — 26 suspicious lineage patterns: web server → shell, database → shell, Java/Node.js RCE, container runtime escape
- **Container escape detector** — nsenter, chroot, mount, modprobe from containers; Docker socket access, /proc/kcore reads, host sensitive file access
- **File access monitoring** — real-time sensitive path monitoring via openat tracepoint with kernel-space filtering (/etc/, /root/.ssh/, /home/*/.ssh/)
- **18 detectors** total (up from 14), 699 tests passing, sensor at 29MB RAM with all tracepoints active

---

## [0.1.6] — 2026-03-20

### Telegram personality overhaul

- **Hacker-partner voice** — all Telegram messages now speak with the personality of a skilled security operator, not a robotic monitoring system
- **Guard mode quips** — incident alerts in GUARD and DRY-RUN modes now include context-aware one-liners per threat type
- **Action reports** — post-kill messages use confidence-scaled quips: "Clean kill. Zero doubt." / "Textbook containment."
- **Mode descriptions** — GUARD: "Threats get neutralized on sight. You get the report." / WATCH: "I flag everything, you make the call."
- **/threats** — visual severity icons, relative time (3h ago), cleaner spacing
- **/decisions** — action-specific icons (block/suspend/honeypot/monitor/kill), confidence + mode display
- **/blocked** — "Kill list" header with count
- **AbuseIPDB auto-block** — "Instant kill — AbuseIPDB reputation gate" / "Dropped on sight — known threat, no AI needed."
- **Honeypot** — "Live target acquired" / "trap them or drop them?" / session debrief with "Their playbook:" heading

### Fixed

- **CrowdSec rate-limit** — cap new blocks per sync to 50 (configurable via `max_per_sync`), preventing OOM when CAPI returns 10k+ IPs. Trim `known_ips` at 10k to prevent unbounded memory growth.
- **Last Portuguese strings removed** — honeypot buttons (Bloquear/Monitorar/Ignorar), toast messages, and monitoring callback all translated to English

---

## [0.1.5] — 2026-03-20

### Security hardening (red team response)

- **Config self-monitoring** — integrity detector always monitors `/etc/innerwarden/*`, detects config tampering
- **Protected IP ranges** — AI can never block RFC1918/loopback IPs, decisions downgraded to ignore
- **Hash-chained audit trail** — each decision includes SHA-256 of the previous, tampering breaks the chain
- **Minimal sudoers** — ufw/iptables/nftables rules restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** — operator actions disabled when auth is configured on non-localhost without TLS
- **Telegram destructive command warnings** — `/enable` and `/disable` show warning before execution
- **Prompt sanitization on all AI providers** — Anthropic provider now sanitizes attacker-controlled fields (was OpenAI/Ollama only)
- **Disk exhaustion protection** — events file capped at 200MB/day
- **Constant-time auth** — dashboard username comparison prevents timing attacks
- **Ed25519 binary signatures** — `innerwarden upgrade` verifies release signatures when `.sig` sidecars are present
- **Minimal sudoers** — ufw/iptables/nftables restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** — operator actions disabled when auth configured on non-localhost without TLS

---

## [0.1.4] — 2026-03-19

### New commands
- **`innerwarden backup`** — archive configs to tar.gz for safe upgrades
- **`innerwarden metrics`** — events per collector, incidents per detector, AI latency, uptime

### Security hardening
- **Disk exhaustion protection** — events file capped at 200MB/day, auto-pauses writes
- **Constant-time auth** — dashboard username comparison prevents timing attacks
- **Prompt sanitization on all providers** — Anthropic provider now sanitizes attacker-controlled strings (was OpenAI/Ollama only)

### Performance
- **Dashboard 15x faster** — overview loads in 0.2s instead of 3s by counting lines instead of parsing 165MB of events JSON

### New detector
- **osquery anomaly** — promotes High/Critical osquery events (sudoers, SUID, authorized_keys, crontab) to incidents

### Fixes
- **install.sh preserves configs** — detects existing installation and skips config overwrite on upgrade
- **Dashboard protection-first UX** — hero shows "Server Protected" with containment rate, resolved incidents faded

---

## [0.1.3] — 2026-03-19

### Security hardening

- **Dashboard login rate limiting** — after 5 failed login attempts within 15 minutes, the IP is blocked from trying again. Returns HTTP 429. Prevents brute-force on the dashboard itself.
- **Ban escalation for repeat offenders** — when an IP is blocked more than once, the decision reason is annotated with "repeat offender (blocked N times)". Flows through to Telegram, audit trail, and AbuseIPDB reports.
- **Dashboard HTTPS warning** — warns when the dashboard runs with auth on a non-localhost address over HTTP. Credentials would be sent in plaintext.
- **AI prompt injection sanitization** — attacker-controlled strings (usernames, paths, summaries) are sanitized before injection into the AI prompt. Control characters stripped, whitespace normalized.

### CrowdSec integration

- CrowdSec installed and enrolled on production server. Community blocklist flowing — known bad IPs are blocked preventively before they attack.

### Other

- Data retention enabled (7-day auto-cleanup of JSONL files)
- Watchdog cron (10-min health check, auto-restart + Telegram alert)
- OpenClaw skill published on ClawHub (innerwarden-security v1.0.3, "Benign" verdict)

---

## [0.1.2] — 2026-03-19

### NPM log support
- **Nginx Proxy Manager format** — the nginx_access collector now auto-detects and parses NPM log format (`[Client IP]` style). Sites behind Docker NPM are now protected by search_abuse, user_agent_scanner, and web_scan detectors.

### Bot detection
- **Known good bot whitelist** — 25+ legitimate crawlers (Google, Bing, DuckDuckGo, etc.) excluded from abuse detection.
- **rDNS verification** — for major search engine bots, the sensor verifies the IP via reverse DNS. Fake Googlebots (spoofed user-agent) are tagged `bot:spoofed` and treated as attackers.

### OpenClaw integration
- **innerwarden-security skill** — OpenClaw skill that installs Inner Warden, validates commands, monitors health, and fixes issues. Auto-detects AI provider. Prompt injection defense built in.

### Fixes
- **All strings in English** — removed all Portuguese from dashboard, Telegram, and agent messages.
- **max_completion_tokens** — auto-detects newer OpenAI models (gpt-5.x, o1, o3) that require the new parameter.
- **systemd dependency** — agent no longer dies when sensor restarts (Requires → Wants).

---

## [0.1.1] — 2026-03-18

### New detectors

- **Suricata IDS detector** — repeated alerts from same source IP → incident → block-ip
- **Docker anomaly detector** — rapid container restarts / OOM kills → incident → block-container
- **File integrity detector** — any change to monitored files (passwd, shadow, sudoers) → Critical incident

### Telegram follow-up

- **Fail2ban block notifications** — when fail2ban blocks an IP, Telegram now sends a follow-up message confirming the block or reporting failures. Previously only the initial "Live threat" alert was sent.

### Dashboard

- **Incident outcome field** — API now returns `outcome` (blocked/suspended/open) and `action_taken` for each incident by cross-referencing decisions.

### Fixes

- **install.sh: remove NoNewPrivileges from agent service** — the flag prevented sudo from working, breaking all response skills (ufw, iptables, sudoers). Sensor keeps the restriction.
- **Falco and osquery docs** — honest "Current Limitations" sections explaining they provide context but don't trigger automated actions yet.

---

## [0.1.0] — 2026-03-18

First public release.

### Detection (8 detectors)

- SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- `execution_guard` — shell command AST analysis via tree-sitter-bash
- `web_scan` — HTTP error floods per IP
- `user_agent_scanner` — 20+ known scanner signatures (Nikto, sqlmap, Nuclei, etc.)

### Collection (15 collectors)

- auth_log, journald, Docker, file integrity, nginx access/error, exec audit
- macOS unified log, syslog/kern.log firewall
- Falco, Suricata EVE, osquery, Wazuh alerts
- AWS CloudTrail (IAM changes, root usage, audit tampering)

### Response skills (8 skills)

- Block IP (ufw / iptables / nftables / pf)
- Suspend user sudo (TTL-based, auto-cleanup)
- Rate limit nginx (HTTP 403 deny with TTL)
- Monitor IP (bounded tcpdump capture)
- Kill process (pkill by user, TTL metadata)
- Block container (docker pause with auto-unpause)
- Honeypot — SSH/HTTP decoy with LLM-powered shell, always-on mode, IOC extraction

### AI decision engine

- 12 providers: OpenAI, Anthropic, Groq, DeepSeek, Mistral, xAI/Grok, Google Gemini, Ollama, Together, MiniMax, Fireworks, OpenRouter — plus any OpenAI-compatible API
- Dynamic model discovery — wizard fetches available models from the provider API
- `innerwarden configure ai` — interactive wizard or direct CLI
- Algorithm gate, decision cooldown, confidence threshold, blocklist
- DDoS protection: auto-block threshold, max AI calls per tick, circuit breaker

### Collective defense

- AbuseIPDB enrichment + report-back — blocked IPs reported to global database
- Cloudflare WAF — blocks pushed to edge automatically
- GeoIP enrichment
- Fail2ban sync
- CrowdSec community threat intel

### Operator tools

- Telegram bot: alerts + approve/deny + conversational AI (/status, /incidents, /blocked, /ask)
- Slack notifications, webhook, browser push (VAPID/RFC 8291)
- Dashboard: investigation UI, SSE live push, operator actions, entity search, honeypot tab, attacker path viewer
- `innerwarden test` — pipeline test (synthetic incident → decision verification)

### Agent API for AI agents

- `GET /api/agent/security-context` — threat level and recommendation
- `GET /api/agent/check-ip?ip=X` — IP reputation check
- `POST /api/agent/check-command` — command safety analysis (reverse shells, download+execute, obfuscation, persistence, destructive ops)

### Control plane CLI

- enable/disable, setup wizard, doctor diagnostics, self-upgrade (SHA-256)
- scan advisor, incidents, decisions, entity timeline, block/unblock, export, tail, report, tune, watchdog
- Structured allowlists (IP/CIDR + users)
- `innerwarden configure ai` / `innerwarden configure responder`

### Module system

- 20 built-in modules with manifest, validate, install/uninstall, publish
- `openclaw-protection` module for AI agent environments

### Security CI

- cargo-deny: dependency advisories + license compliance
- gitleaks: secrets scanning
- Dependabot: weekly dependency updates

### Platform

- Linux (x86_64 + arm64) + macOS (x86_64 + arm64)
- 577 tests across four crates
