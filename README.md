# Inner Warden

[![CI](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml)
[![Security](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/InnerWarden/innerwarden?label=release&color=blue)](https://github.com/InnerWarden/innerwarden/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/InnerWarden/innerwarden)](https://github.com/InnerWarden/innerwarden/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/InnerWarden/innerwarden)](https://github.com/InnerWarden/innerwarden/commits/main)

![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![eBPF Hooks](https://img.shields.io/badge/eBPF%20hooks-40-blueviolet)
![Detectors](https://img.shields.io/badge/detectors-49-blue)
![Correlation Rules](https://img.shields.io/badge/correlation%20rules-30-purple)
![Tests](https://img.shields.io/badge/tests-1943-brightgreen)
![MITRE Coverage](https://img.shields.io/badge/MITRE%20ATT%26CK-65%20mappings-red)
![Sigma Rules](https://img.shields.io/badge/Sigma%20rules-208-blueviolet)
![Memory](https://img.shields.io/badge/memory-~150MB%20(full%20stack)-green)
![AI Optional](https://img.shields.io/badge/AI-optional-lightgrey)

Inner Warden is an autonomous security agent for Linux and macOS. Full-stack visibility from Ring -2 (firmware) to Ring 3 (userspace). 40 eBPF kernel hooks. 49 detectors. 22 collectors. 30 cross-layer correlation rules. 65 MITRE ATT&CK technique mappings (40% validated via Caldera adversary emulation). 208 Sigma community rules. Autoencoder anomaly detection. Behavioral DNA attacker fingerprinting. Baseline anomaly detection. JA3/JA4 TLS fingerprinting. YARA + Sigma rule engines. Automated playbook response. Monthly threat reports. AI agent protection (Agent Guard + 71 ATR rules). Mesh collaborative defense. No cloud. No dependencies. Just two Rust daemons and a CLI.

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

Installs in 10 seconds. Starts in observe-only mode. You decide when to go live.

---

## Who this is for

Inner Warden is built for **system administrators, DevOps engineers, and security professionals** who manage Linux or macOS servers and want host-level threat detection and response.

You should be comfortable with:
- Managing firewall rules (ufw, iptables, nftables, or pf)
- Reading system logs and understanding security events
- Configuring services via TOML files and systemd/launchd
- Evaluating whether automated responses are appropriate for your environment

This is **not** a plug-and-play consumer security product. Misconfigured response skills can lock out legitimate users or disrupt services. If you are unfamiliar with Linux system administration, start with the observe-only mode and study the logs before enabling any response capabilities.

<p align="center">
  <a href="https://innerwarden.com/live">
    <img src="docs/images/live-attack.png" alt="Live threat feed" width="820">
  </a>
  <br>
  <sub><a href="https://innerwarden.com/live"><strong>Test the tool in real time</strong></a> &nbsp;·&nbsp; <a href="https://vimeo.com/1175992244">Watch the explainer video</a></sub>
</p>


https://github.com/user-attachments/assets/b55967a6-a2d0-4158-9007-05e689d5bf0c


https://github.com/user-attachments/assets/6ea1e124-52c2-48fe-8600-4b2f3d670116

<p align="center">
  <img src="docs/images/dashboard-sensors.png" alt="Dashboard: sensor HUD with eBPF activity, threat gauge, and detector charts" width="820">
</p>
<p align="center">
  <img src="docs/images/dashboard-threats.png" alt="Dashboard: real-time threat overview" width="820">
</p>
<p align="center">
  <img src="docs/images/dashboard-investigate.png" alt="Dashboard: IP investigation view" width="820">
</p>

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      FIRMWARE / BIOS (Ring -2)                      │
│  MSR write guard (LSTAR/SMRR) | ACPI method monitoring | ESP hash   │
│  SPI controller probing | eBPF weaponization detection (VoidLink)   │
└─────────────────────────────────────────────┬───────────────────────┘
                                              │
┌─────────────────────────────────────────────┼───────────────────────┐
│                      HYPERVISOR (Ring -1)   │                       │
│  VM introspection | KVM monitoring | VM exit analysis               │
└─────────────────────────────────────────────┼───────────────────────┘
                                              │
┌─────────────────────────────────────────────┼──────────────────────┐
│                           KERNEL (Ring 0)   │                      │
│                                                                    │
│  ┌───────────── ─┐  ┌───────────┐  ┌─────────┐  ┌───────────────┐  │
│  │23 tracepoints │  │ 5 kprobes │  │  3 LSM  │  │      XDP      │  │
│  │ execve,       │  │ creds,    │  │ exec    │  │  wire-speed   │  │
│  │ connect,      │  │ MSR, ACPI │  │ file    │  │  IP blocking  │  │
│  │ openat,       │  │ timestomp │  │ bpf     │  │  10M+ pps     │  │
│  │ mount, clone, │  │ truncate  │  │ + kill  │  │  allowlist +  │  │
│  │ ptrace, ...   │  │           │  │ chain   │  │  blocklist    │  │
│  └──────┬─────── ┘  └─────┬─────┘  └───┬─────┘  └──────┬────────┘  │
│         └─ ───────┬───────┘            │               │           │
│                  ▼                     │               │           │
│           ┌─────────────┐              │               │           │
│           │ Ring Buffer │              │               │           │
│           │ (1MB epoll) │              │               │           │
│           └──────┬──────┘              │               │           │
└──────────────────┼────────────── ──────┼───────────────┼───────────┘
                   │                     │               │
                   ▼                     │               │
┌────────────────────────────────────────────────────────────────── ┐
│                         SENSOR                                    │
│                                                                   │
│  ┌─────────┐ ┌─────────┐ ┌────────┐ ┌────────────────────────┐    │
│  │auth.log │ │journald │ │ Docker │ │    eBPF collector      │◄─┘ |
│  │nginx    │ │syslog   │ │ cgroup │ │    (40 hooks)          │    |
│  └────┬────┘ └────┬────┘ └──┬──── ┘ └───────────┬────────────┘    │
│       │           │         │                   │                 │
│  ┌────┴────┐ ┌────┴─────┐ ┌─┴──────────────┐    │                 │
│  │DNS/HTTP │ │TLS/JA3   │ │kernel_integrity│    │                 │
│  │capture  │ │JA4       │ │proc_maps       │    │                 │
│  │(native) │ │(native)  │ │fanotify        │    │                 │
│  └────┬────┘ └────┬─────┘ └───────┬────────┘    │                 │
│       └───────────┴───────────────┴─────────────┘                 │
│                          │                                        │
│                    ┌─────▼──────┐                                 │
│                    │48 detectors│ + 8 YARA + 8 Sigma              │
│                    │ stateful   │                                 │
│                    └─────┬──────┘                                 │
│                          │                                        │
│              ┌───────────▼───────────┐                            │
│              │  events + incidents   │                            │
│              │      (JSONL)          │                            │
│              └───────────┬───────────┘                            │
└──────────────────────────┼────────────────────────────────────────┘
                           │
┌──────────────────────────┼────────────────────────────────────────┐
│                   AGENT  │                                        │
│                          ▼                                        │
│     ┌──────────────────────────────────────────────┐              │
│     │  30 Cross-Layer Correlation Rules            │              │
│     │  + Kill Chain Tracker (7 stages per entity)  │              │
│     └────────────────────┬─────────────────────────┘              │
│                          ▼                                        │
│                ┌──────────────────┐                               │
│                │  Algorithm Gate  │  skip low-sev, private IP     │
│                └────────┬─────────┘                               │
│                         ▼                                         │
│              ┌────────────────────┐                               │
│              │ Enrich: AbuseIPDB, │                               │
│              │ GeoIP, CrowdSec    │                               │
│              └────────┬──────── ──┘                               │
│                       ▼                                           │
│              ┌─────────────────┐                                  │
│              │ AI Triage (opt) │  OpenAI / Anthropic / Ollama     │
│              └────────┬────────┘                                  │
│                       ▼                                           │
│              ┌─────────────────┐     ┌──────────────┐             │
│              │ Skill Executor  │────►│ LSM enforce  │             │
│              │ block_ip (5)    │     │ XDP block    │             │
│              │ kill_process    │     └──────────────┘             │
│              │ suspend_sudo    │     ┌──────────────┐             │
│              │ honeypot        │────►│ Cloudflare   │             │
│              │ playbooks (20)  │     │ AbuseIPDB    │             │
│              └────────┬────────┘     └──────────────┘             │
│                       │                                           │
│          ┌────────────┼────────────┬──────────────┐               │
│          ▼            ▼            ▼              ▼               │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐         │
│   │ Telegram │ │  Slack   │ │ Webhook  │ │ Mesh Network │         │
│   │   bot    │ │          │ │ (any)    │ │ peer defense │         │
│   └──────────┘ └──────────┘ └──────────┘ └──────────────┘         │
│                                                                   │
│   ┌───────────────────────────────────────────────────────────┐   │
│   │ Dashboard: HUD, threats, investigation, attacker intel,   │   │
│   │ MITRE ATT&CK map, monthly reports, baseline learning,     │   │
│   │ ISO 27001 compliance, hash chain, live SSE, audit trail   │   │
│   └───────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

---

## What it does

1. **Watches**: 20+ collectors across all layers — eBPF syscall tracing (40 kernel hooks including timestomp and log truncation), firmware integrity (ESP, UEFI, ACPI, MSR, SPI), memory forensics (/proc/maps RWX detection), native network capture (DNS queries, HTTP requests, JA3/JA4 TLS fingerprinting — no Suricata needed), filesystem real-time monitoring, cgroup resource abuse, kernel integrity (syscall table + eBPF inventory), plus auth.log, journald, Docker, nginx, osquery, CloudTrail
2. **Detects**: 48 stateful detectors + 8 YARA malware rules + 8 Sigma log rules identify brute-force, credential stuffing, port scans, C2 callbacks, privilege escalation, container escapes, reverse shells (eBPF syscall sequence — impossible to evade), ransomware (entropy analysis), rootkits, DNS tunneling, data exfiltration (sensitive file read → outbound connect by PID), timestomping, log tampering, discovery bursts, and more. **65 MITRE ATT&CK techniques covered** across 14 tactics.
3. **Correlates**: 30 cross-layer rules connect Firmware × Kernel × Userspace × Network × Honeypot events. Detects multi-stage attacks no single detector can see: firmware tampering → rootkit install, recon → brute force → data exfil, honeypot engagement → real attack on same IP. Kill chain tracker follows 7 attack stages per entity (IP, user, container).
4. **Learns**: baseline anomaly detection trains for 7 days then alerts on deviations — event rate drops (silence = compromise), new process lineages (nginx→sh), unusual login times, unknown network destinations. No rules needed.
5. **Blocks at the kernel**: LSM enforcement stops reverse shells and /tmp execution before they run. XDP drops attack traffic at wire speed. 8 kill chain patterns detected and blocked without signatures. Blocks propagate to mesh peers.
6. **Responds automatically**: 20 built-in playbooks covering every detector — ransomware, reverse shell, data exfil, malware, privilege escalation, kernel module load, process injection, persistence (SSH key, crontab, systemd), container escape, crypto miner, DNS tunneling, lateral movement, web shell, discovery burst, and more. Response sequences: kill process, block IP, suspend sudo, quarantine file, isolate network, capture forensics, pcap, notify, escalate
7. **Fingerprints attackers**: behavioral DNA (SHA-256 of detectors + tools + targets + timing patterns), campaign detection via IOC clustering, recurrence tracking, risk scoring 0-100, monthly threat reports with MITRE heatmap

Everything is local, audited, and reversible.

---

## What happens when your server is attacked

```
00:00  SSH brute-force begins from 203.0.113.10
00:45  Detector fires: 8 failed logins, 5 usernames, one IP

       AI evaluates: "coordinated brute-force"
       Confidence: 0.94
       Recommended action: block_ip

00:46  Firewall rule added: ufw deny from 203.0.113.10
00:46  Telegram alert lands on your phone
00:46  Decision logged to audit trail

       Threat contained.
```

No human needed when auto-execution is enabled. Otherwise, you approve via Telegram or the dashboard. Full audit trail. Every action reversible.

---

## Response skills

When a threat is confirmed, Inner Warden picks the right tool.

| Skill | What it does |
|-------|-------------|
| **Block IP (XDP)** | Wire-speed drop at the network driver, 10M+ packets/sec, zero CPU overhead |
| **Block IP (firewall)** | Deny via ufw, iptables, nftables, or pf (macOS). Persists across reboots. |
| **Suspend sudo** | Revokes sudo for a user via sudoers drop-in. Auto-expires after TTL. |
| **Kill process** | Terminates all processes for a compromised user. TTL-bounded. |
| **Block container** | Pauses a Docker container. Auto-unpauses after TTL. |
| **Deploy honeypot** | SSH/HTTP decoy with LLM-powered interactive shell that captures credentials and behavior |
| **Rate limit nginx** | Blocks abusive HTTP traffic at the nginx layer with TTL |
| **Monitor IP** | Bounded tcpdump capture for forensic analysis |
| **Block IP (Cloudflare)** | Edge-level blocking via Cloudflare API, stops traffic before it reaches your server |
| **Report to AbuseIPDB** | Shares attacker IPs with community threat intelligence |
| **Kill chain response** | Kills process tree + blocks C2 IP via XDP + captures forensics (ss, /proc) |

Blocking is **layered**: a single block decision triggers XDP (instant kernel drop) + firewall (persists reboot) + mesh broadcast (peer nodes block too) + Cloudflare edge (stops traffic upstream) + AbuseIPDB report (community intelligence). Kill chain incidents trigger the `kill-chain-response` skill: kill process tree + block C2 via XDP + capture forensics. All skills are bounded, audited, and reversible.

---

## What it detects

48 stateful detectors + 8 YARA rules + 8 Sigma rules covering the full attack lifecycle. Highlights:

| Detector | Threat | MITRE |
|----------|--------|-------|
| `ssh_bruteforce` | Repeated SSH failures from one IP | T1110.001 |
| `credential_stuffing` | Many usernames tried from one IP | T1110.004 |
| `distributed_ssh` | Coordinated botnet scan: many IPs, few attempts each | T1110 |
| `suspicious_login` | Brute-force followed by successful login = compromise | T1110 |
| `port_scan` | Rapid unique-port probing | T1595 |
| `reverse_shell` | Reverse/bind shell detection via eBPF + behavioral analysis | T1059 |
| `execution_guard` | Suspicious shell commands via AST analysis | T1059 |
| `process_tree` | Suspicious parent-child: web server → shell, Java RCE | T1059 |
| `privesc` | Real-time privilege escalation via eBPF kprobe on `commit_creds` | T1068 |
| `rootkit` | Kernel module and userland rootkit detection | T1014 |
| `ransomware` | Rapid file encryption, ransom note creation, extension changes | T1486 |
| `c2_callback` | Beaconing, C2 port connections, data exfiltration patterns | T1071 |
| `dns_tunneling` | Encoded DNS queries for covert data transfer | T1071.004 |
| `container_escape` | nsenter, Docker socket access, host file reads from container | T1611 |
| `lateral_movement` | SSH pivoting, credential reuse across hosts | T1021 |
| `crypto_miner` | CPU abuse from mining processes | T1496 |
| `web_scan` | HTTP error floods, path traversal, LFI probing | T1190 |
| `web_shell` | Web shell upload and command execution | T1505.003 |
| `data_exfiltration` | Large outbound transfers, DNS exfil, staging patterns | T1048 |
| `fileless` | In-memory execution, /proc/self/mem writes | T1055 |
| `log_tampering` | Log deletion, truncation, timestomping | T1070 |
| `kernel_module_load` | Unauthorized kernel module insertion | T1547.006 |
| `sudo_abuse` | Burst of privileged commands by a user | T1548 |
| `integrity_alert` | Changes to /etc/passwd, /etc/shadow, sudoers, SSH keys | T1098 |
| `packet_flood` | DDoS / volumetric attack detection | - |
| `user_agent_scanner` | Known scanner signatures (Nikto, sqlmap, Nuclei, 20+) | T1595.002 |

Plus: `docker_anomaly`, `osquery_anomaly`, `suricata_alert`, `search_abuse`, `credential_harvest`, `ssh_key_injection`, `user_creation`, `crontab_persistence`, `systemd_persistence`, `process_injection`, `outbound_anomaly`, `data_exfil_ebpf` (sensitive file read → outbound connect by PID), `yara_scan` (8 built-in rules: XMRig, webshells, Cobalt Strike, Metasploit, rootkits), `sigma_rule` (8 built-in rules: cron modification, /tmp execution, shadow access, docker.sock), `cgroup_abuse` (CPU/memory resource abuse), `io_uring_anomaly`, `container_drift`, `host_drift`, `sensitive_write`.

`execution_guard` parses commands structurally using tree-sitter-bash. It catches `curl | sh` pipelines, `/tmp` execution, reverse shell patterns, and staged download-chmod-execute sequences.

`c2_callback` uses coefficient-of-variation analysis to detect beaconing: regular-interval connections to the same IP that indicate a compromised process phoning home.

`privesc` hooks the kernel's `commit_creds` function via kprobe. When a non-root process gains root through an unexpected path (not sudo/su/login), a Critical incident fires instantly, before any log is written.

---

## How it works

**Sensor**: deterministic signal collection. No AI, no HTTP. 20 collectors (auth.log, journald, Docker events, file integrity, firmware integrity, nginx access/error, shell audit, macOS unified log, syslog firewall, eBPF syscall tracing with 38 kernel hooks, JA3/JA4 TLS fingerprinting, memory forensics via /proc/maps, real-time filesystem monitoring with entropy analysis, kernel integrity monitoring, cgroup resource abuse detection). Optional: Suricata, osquery, Wazuh, AWS CloudTrail. Events flow through JSONL files or Redis Streams to the agent. Syslog CEF output for SIEM integration.

**eBPF**: 38 kernel hooks running inside Linux (5.8+, CO-RE/BTF portable):
- **23 tracepoints**: execve, connect, openat, ptrace, setuid, bind, mount, memfd_create, init_module, dup2/dup3, listen, mprotect, clone, unlinkat, renameat2, kill, prctl, accept4, sched_process_exit, ioperm, iopl, io_uring_submit, io_uring_create
- **3 kprobes**: `commit_creds` (privilege escalation), `native_write_msr` (firmware MSR tampering), `acpi_evaluate_object` (ACPI rootkit detection)
- **3 LSM hooks**: `bprm_check_security` (exec blocking + kill chain with 8 attack patterns), `file_open` (sensitive path write protection), `bpf` (eBPF weaponization / VoidLink defense)
- **4 kprobe/kretprobe pairs** (Trace of the Times): iterate_dir, filldir64, tcp4_seq_show, proc_pid_readdir — timing-based rootkit detection
- **XDP program**: wire-speed IP blocking at the network driver (10M+ pps drop rate)
- **Phase 2 firmware hooks**: MSR write guard (LSTAR/SMRR), I/O port access (SPI controller probing), ACPI method execution monitoring

> **Looking for the eBPF source code?** All 38 kernel programs live in a single file: [`crates/sensor-ebpf/src/main.rs`](crates/sensor-ebpf/src/main.rs).

**Kernel-level noise filters** keep overhead near zero: COMM_ALLOWLIST (137 trusted processes like sshd, systemd, docker), CGROUP_ALLOWLIST, PID_RATE_LIMIT, and PID_CHAIN. Tail call dispatcher routes events through a single attach point to N handlers via ProgramArray. Ring buffer with epoll wakeup delivers events in microseconds.

**DDoS defense**: 4-layer adaptive protection. XDP kernel drop (wire speed) + Shield module (dynamic rate limiting) + Cloudflare auto-failover (edge blocking) + Nginx rate limit. Rate limits tighten dynamically under attack.

**Mesh network**: collaborative defense between nodes. Attack one server, all others block the IP automatically. Ed25519 signed signals, game-theory trust model (tit-for-tat), staging pool with TTL-based auto-reversal. No signal causes immediate action. Everything is scored and staged.

```bash
innerwarden mesh enable
innerwarden mesh add-peer https://peer-server:8790
```

Container-aware via cgroup ID. Zero performance overhead.

**Agent**: reads incidents from JSONL or Redis Streams. Fast loop (2s): algorithm gate → enrichment (AbuseIPDB, GeoIP, CrowdSec, threat feeds) → VirusTotal hash check on YARA matches → AI triage → playbook evaluation → skill execution → pcap capture on High/Critical → audit trail. Slow loop (30s): cross-layer correlation (30 rules) → baseline learning → attacker intelligence consolidation (DNA + campaigns) → monthly report generation → narrative summary.

Two Rust daemons. No external dependencies. ~150 MB RAM with all features active (sensor 32MB + agent 89MB + DNA 11MB + shield 9MB + killchain 7MB). Dashboard with 10 views: Sensors HUD, Threats investigation, Report, Health, Honeypot, Compliance (ISO 27001), Intelligence (Profiles, Campaigns, Chains, Baseline, Playbooks), Monthly Report. Live SSE feed, MITRE ATT&CK mapping, 20 integration cards. Sleeps after 15 min of inactivity.

---

## AI is optional and controlled

Inner Warden detects and logs threats without any AI provider. Add AI when you want:

- **Confidence-scored recommendations**: not binary yes/no, but 0.0-1.0 scored decisions
- **Policy-gated execution**: AI recommends, your policy decides if it runs
- **Full transparency**: every AI decision recorded in append-only JSONL with reasoning
- **Twelve providers**: OpenAI, Anthropic, Ollama (local), OpenRouter, Groq, Together, Mistral, DeepSeek, Fireworks, Cerebras, Google Gemini, xAI Grok

AI is advisory unless you explicitly enable auto-execution. You set the confidence threshold.

---

## Operator in the loop

Not everything should be automatic.

- **Telegram**: every High/Critical incident pushed to your phone. Approve or deny with inline buttons. Sensitivity control: quiet/normal/verbose.
- **Slack**: incident notifications via incoming webhook
- **Webhook**: HTTP POST to any endpoint. Works with PagerDuty, Opsgenie, Discord, Microsoft Teams, Google Chat, DingTalk, Feishu/Lark, WeCom, n8n, Zapier, Make, Home Assistant.
- **Dashboard**: local authenticated UI with sensor HUD, investigation timeline, entity search, operator actions, live SSE feed, attack map, MITRE ATT&CK mapping, attacker path viewer, 20 integration cards, ISO 27001 compliance tab with hash chain verification

---

## Safe defaults

Inner Warden ships with the safest possible posture. On first run, **nothing is blocked, killed, or modified**. The system only observes and logs.

| Default | Meaning |
|---------|---------|
| `responder.enabled = false` | No actions taken. Observe only. |
| `dry_run = true` | Logs what it *would* do, without doing it. |
| `execution_guard` in observe mode | Detects suspicious commands, does not block. |
| Shell audit opt-in | Requires explicit privacy consent. |
| AI optional | Detection and logging work without any provider. |
| Append-only audit trail | Every decision in `decisions-YYYY-MM-DD.jsonl`. |

You must explicitly change **two settings** before any response action can fire: enable the responder and disable dry-run. Neither happens automatically.

## Start in observe mode. Always.

Before enabling automatic responses, run Inner Warden in observe-only mode for a period that makes sense for your environment (days to weeks). During this time:

1. **Review the logs**: check `events-*.jsonl` and `incidents-*.jsonl` in your data directory to understand what the detectors are flagging.
2. **Check for false positives**: make sure legitimate traffic (CI/CD systems, monitoring probes, your own scripts) is not being misidentified.
3. **Configure your allowlist**: add trusted IPs and users so they are never acted upon:
   ```bash
   innerwarden allowlist add --ip 10.0.0.0/8
   innerwarden allowlist add --user deploy
   ```
4. **Enable dry-run first**: when you enable the responder, keep `dry_run = true` so you can see what *would* happen without any actual effect:
   ```bash
   innerwarden configure responder --enable
   ```
5. **Go live only when you trust what you see**:
   ```bash
   innerwarden configure responder --enable --dry-run false
   ```

There is no rush. The system is designed to be useful in observe-only mode indefinitely.

---

## Modules

Enable what you need.

| Module | Threat | Response |
|--------|--------|----------|
| `ssh-protection` | SSH brute-force + credential stuffing | Block IP |
| `network-defense` | Port scanning | Block IP |
| `sudo-protection` | Sudo privilege abuse | Suspend user sudo |
| `execution-guard` | Malicious shell commands (AST) | Kill process / observe |
| `search-protection` | HTTP endpoint abuse | Rate limit nginx |
| `file-integrity` | Unauthorized file changes | Alert |
| `container-security` | Docker lifecycle anomalies | Block container / observe |
| `threat-capture` | Active threat investigation | Honeypot + traffic capture |
| `nginx-error-monitor` | HTTP error floods, path traversal | Block IP |
| `slack-notify` | Incident notifications | Slack webhook |
| `cloudflare-integration` | L7 DDoS / botnet IPs | Block at Cloudflare edge |
| `abuseipdb-enrichment` | IP reputation context | Enriched AI prompt |
| `geoip-enrichment` | Country/ISP geolocation | Enriched AI prompt |
| `fail2ban-integration` | Sync active fail2ban bans | Block enforcement |
| `crowdsec-integration` | CrowdSec community intel | Block enforcement (experimental) |
| `suricata-integration` | Network IDS alerts (optional) | Incident passthrough |
| `osquery-integration` | Host state queries | Enriched events |
| `wazuh-integration` | Wazuh HIDS alerts | Incident passthrough |

```bash
innerwarden enable block-ip
innerwarden enable ssh-protection
innerwarden enable shell-audit       # prompts for privacy consent
```

Community modules:
```bash
innerwarden module install <url>     # SHA-256 verified
innerwarden module search <term>     # search the registry
```

---

## Protecting AI agents

If you run OpenClaw, n8n, Langchain, or any autonomous AI agent on your server, Inner Warden can watch what it does and stop it if something goes wrong.

```bash
innerwarden enable openclaw-protection
```

This enables real-time monitoring of every command your agent executes, using structural analysis (tree-sitter AST) instead of regex. Download-and-execute pipelines, reverse shells, staged attacks, and obfuscated commands are caught before they can do damage.

### Let your agent ask before acting

Inner Warden exposes an API that AI agents can query:

```bash
# "Is my server safe right now?"
curl -s http://localhost:8787/api/agent/security-context
# → {"threat_level": "low", "recommendation": "safe to proceed"}

# "Is this command safe to run?"
curl -s -X POST http://localhost:8787/api/agent/check-command \
  -H "Content-Type: application/json" \
  -d '{"command": "curl https://example.com/setup.sh | bash"}'
# → {"risk_score": 40, "recommendation": "review", "signals": ["download_and_execute"]}

# "Is this IP safe to connect to?"
curl -s "http://localhost:8787/api/agent/check-ip?ip=203.0.113.10"
# → {"known_threat": true, "blocked": true, "recommendation": "avoid"}
```

Your agent calls `check-command` before executing. If the recommendation is `deny`, it stops. No changes to the agent runtime needed, just an HTTP call.

See [AI Agent Protection docs](modules/openclaw-protection/docs/README.md) for full integration guide.

---

## Hardening advisor

Scan your system and get actionable security recommendations without changing anything.

```
$ innerwarden harden

  ✓ SSH
    ⚠  Password authentication is enabled [high]
       → Set 'PasswordAuthentication no' in /etc/ssh/sshd_config
    ⚠  Root login via SSH is permitted [high]
       → Set 'PermitRootLogin no' in /etc/ssh/sshd_config

  ✓ Firewall
    ✓ 2 check(s) passed

  ! Kernel
    ⚠  ICMP redirects accepted (MITM risk) [medium]
       → Run: sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

  ✓ Permissions
    ✓ 3 check(s) passed

  ! Updates
    ⚠  3 security update(s) pending (8 total) [high]
       → Run: sudo apt update && sudo apt upgrade -y

  ✓ Docker
    ✓ 3 check(s) passed

  ✓ Services
    ✓ 2 check(s) passed

  Score: 68/100 (Fair)
  ██████████████████████░░░░░░░░░
```

Checks SSH config, firewall, kernel params (ASLR, SYN cookies, IP forwarding), file permissions (SUID, world-writable), pending updates, Docker (privileged containers, socket), and exposed services. Advisory only, never applies changes.

---

## Live threat feed

See Inner Warden responding to real attacks in real time: [innerwarden.com/live](https://innerwarden.com/live)

The agent exposes public read-only endpoints for live monitoring:

```bash
# Last 20 incidents with decisions
curl https://live.innerwarden.com/api/live-feed

# Real-time SSE stream
curl https://live.innerwarden.com/api/live-feed/stream
```

---

## Scan advisor

Let your server tell you what it needs.

```
$ innerwarden scan

  sshd       running  → ssh-protection       ESSENTIAL    [NATIVE]
  docker     running  → container-security    RECOMMENDED  [NATIVE]
  nginx      running  → search-protection     RECOMMENDED  [NATIVE]
  fail2ban   running  → fail2ban-integration  RECOMMENDED  [NATIVE]

  Conflicts detected:
    fail2ban-integration + abuseipdb-enrichment: both auto-block IPs; enable one

  Activation sequence:
    1. innerwarden enable block-ip
    2. innerwarden enable ssh-protection
    3. innerwarden enable fail2ban-integration
```

**NATIVE** = reads existing logs, zero external deps. **EXTERNAL** = requires separate tool install.

---

## Install

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

No API key required. What it does:
- Creates a dedicated `innerwarden` service user
- Downloads SHA-256 verified binaries for your architecture (x86_64 / aarch64)
- Writes config to `/etc/innerwarden/`, creates data directory
- Starts sensor + agent via systemd (Linux) or launchd (macOS)
- Safe posture: detection active, no response skills enabled, `dry_run = true`

With external integrations:
```bash
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --with-integrations
```

Build from source:
```bash
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://innerwarden.com/install | sudo bash
```

### Configure AI

AI triage is optional. Add it when you want confidence-scored decisions.

**OpenAI:**
```bash
# /etc/innerwarden/agent.env
OPENAI_API_KEY=sk-...
```

**Anthropic:**
```bash
# /etc/innerwarden/agent.env
ANTHROPIC_API_KEY=sk-ant-...
```
```toml
# /etc/innerwarden/agent.toml
[ai]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
```

**Ollama (local, no key):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh && ollama pull llama3.2
```
```toml
# /etc/innerwarden/agent.toml
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
```

After changing config:
```bash
sudo systemctl restart innerwarden-agent          # Linux
sudo launchctl kickstart -k system/com.innerwarden.agent  # macOS
```

Run `innerwarden doctor` to validate your provider.

### Daily mode (simple commands)

For day-to-day operations, use the simplified command group:

```bash
innerwarden daily status
innerwarden daily threats --live
innerwarden daily actions
innerwarden daily report
innerwarden daily doctor
innerwarden daily test

# aliases
innerwarden quick status
innerwarden day threats
```

Agent connection is also available in daily mode and does not require PID:

```bash
innerwarden daily agent scan
innerwarden daily agent connect          # auto-detect + choose
innerwarden daily agent connect 1234     # explicit PID (optional)
```

### After install

```bash
innerwarden status     # verify services are running
innerwarden doctor     # diagnose issues with fix hints
innerwarden test       # inject a synthetic incident and verify the full pipeline responds
innerwarden list       # see capabilities and modules
```

Enable response skills when ready:
```bash
innerwarden enable block-ip          # IP blocking (ufw default, or iptables/nftables)
innerwarden enable sudo-protection   # detect + respond to sudo abuse
innerwarden enable shell-audit       # shell command trail via auditd
```

### Configure notifications

```bash
innerwarden notify telegram          # interactive wizard
innerwarden notify slack --webhook-url https://hooks.slack.com/...
innerwarden notify web-push --subject mailto:you@example.com
innerwarden notify webhook --url https://hooks.example.com/notify
innerwarden notify test              # verify all channels
```

### Go live

After enabling skills, the responder is active but still in `dry_run = true`. When you trust the decisions:

```bash
innerwarden configure responder --enable --dry-run false
```

### Updates

```bash
innerwarden upgrade          # fetch + install latest (SHA-256 verified)
innerwarden upgrade --check  # check without installing
```

### Control plane

```bash
innerwarden list                                    # capabilities + modules
innerwarden status                                  # services + active capabilities
innerwarden doctor                                  # diagnostics with fix hints
innerwarden enable block-ip                         # activate
innerwarden enable block-ip --param backend=iptables
innerwarden disable block-ip                        # deactivate and clean up
innerwarden --dry-run enable block-ip               # preview
innerwarden scan                                    # detect + recommend
innerwarden harden                                  # security hardening advisor
innerwarden harden --verbose                        # show all passed checks too
innerwarden allowlist add --ip 10.0.0.0/8           # skip AI for trusted ranges
innerwarden allowlist add --user deploy             # skip AI for trusted users
innerwarden configure ai                            # interactive AI provider setup (12 providers)
innerwarden configure responder --enable --dry-run false
innerwarden backup                                  # archive configs to tar.gz
innerwarden metrics                                 # events, decisions, AI latency, uptime
innerwarden test                                    # verify full pipeline end-to-end
innerwarden daily                                   # simplified day-to-day command set
innerwarden daily agent connect                     # connect running agents without PID lookup
```

---

## Supported environments

- **Linux**: Ubuntu 22.04+, any systemd-based distro. Full feature set with 22 eBPF kernel hooks (tracepoints, kprobes, LSM, XDP), kill chain enforcement, wire-speed blocking.
- **macOS**: Ventura and later (launchd, pf firewall, unified log). Detection and response work fully, but eBPF kernel programs are Linux-only. macOS uses log-based collectors instead.

Pre-built binaries: `x86_64` and `aarch64` for both platforms.

---

## Build and test

```bash
make test       # 1010+ tests
make build      # debug build (sensor + agent + ctl)
make replay-qa  # end-to-end integration test
```

Run locally:
```bash
make run-sensor   # writes to ./data/
make run-agent    # reads from ./data/
```

---

## FAQ

**Is this an EDR?**
No. It is a self-contained defense agent with bounded response skills and full audit trails. No cloud, no phone-home, runs entirely on your host.

**Does it block by default?**
No. Starts in observe-only mode. You enable response skills and disable dry-run when ready.

**Do I need an AI provider?**
No. Detection, logging, dashboard, and reports all work without AI. AI adds confidence-scored triage for autonomous response and is entirely optional.

**How is this different from Fail2ban?**
Fail2ban blocks IPs based on regex patterns. Inner Warden has 36 detectors, 22 eBPF kernel hooks with kill chain enforcement, a collaborative defense mesh network, 10 response skills (including sudo suspension, process kill, container pause, honeypots, and traffic capture), twelve AI providers, 4-layer DDoS defense, Telegram bot, AbuseIPDB intelligence sharing, and a full investigation dashboard with MITRE ATT&CK mapping.

**How is this different from other HIDS tools?**
Most host intrusion detection systems only observe. They write alerts for a human to act on. Inner Warden observes AND blocks. LSM hooks stop reverse shells at the kernel's execve before the process runs. XDP drops attack traffic at wire speed. Kill chain detection blocks 7 generic exploit patterns without CVE signatures, catching zero-day exploits by behavior rather than known hashes.

**Can I add custom detectors or skills?**
Yes. See [module authoring guide](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring).

---

## Disclaimer

> **Warning**
> Inner Warden is an **experimental** security agent that can **block IP addresses, kill processes, suspend user privileges, pause containers, and modify firewall rules** on your system. These are powerful, potentially disruptive actions. Read this document carefully before deploying. Always start in observe-only mode and review behavior before enabling automatic responses.

Inner Warden is provided as-is, without warranty. It is experimental software that interacts with your system's firewall, process table, and user permissions. Automated security responses carry inherent risk. A false positive can block a legitimate user or disrupt a production service.

**You are responsible for:**
- Testing thoroughly in observe/dry-run mode before enabling responses
- Configuring allowlists to protect trusted IPs, users, and services
- Monitoring the audit trail and adjusting thresholds for your environment
- Understanding the response skills you enable and their effects

The authors are not responsible for downtime, data loss, or service disruption caused by misconfiguration or false positives. Use good judgment and test in a staging environment first.

---

## Links

- [Website](https://www.innerwarden.com)
- [Live attack feed](https://innerwarden.com/live)
- [Blog](https://innerwarden.com/blog)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Documentation](https://github.com/InnerWarden/innerwarden/wiki)
- [Module authoring](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring)

## License

Apache License 2.0. See [LICENSE](LICENSE).
