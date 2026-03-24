# Sensor Capabilities

`innerwarden-sensor` — deterministic event collection and detection. Zero AI, zero HTTP. Fail-open.

## Collectors

### NATIVE (built-in, no external tools required)

**auth_log** — tail `/var/log/auth.log`; full SSH parser (failures, logins, invalid users)

**journald** — subprocess `journalctl --follow --output=json`; units: sshd, sudo, kernel

**exec_audit** — tail `/var/log/audit/audit.log`; `type=EXECVE` + optional `type=TTY` (high privacy impact, gated by config)

**docker** — subprocess `docker events`; privilege escalation detection via `docker inspect` on `container.start`:
- Detects `--privileged`, docker.sock mount (`HostConfig.Binds` + `Mounts`), dangerous `CapAdd` (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`)
- Emits `container.privileged` (High), `container.sock_mount` (High), `container.dangerous_cap` (Medium)
- 10 tests

**integrity** — SHA-256 polling of configured paths, configurable interval:
- SSH key tampering: when modified file is `authorized_keys`, emits `ssh.authorized_keys_changed` (High) instead of `file.changed`; extracts username from path; MITRE T1098.004; 8 tests
- Cron tampering: when `/etc/crontab`, `/etc/cron.d/*`, cron.{hourly,daily,weekly,monthly}`, or `/var/spool/cron/crontabs/<user>` changes, emits `cron.tampering` (High); MITRE T1053.003; 7 tests

**nginx_access** — tail nginx access log (Combined Log Format); emits `http.request`

**nginx_error** — tail nginx error.log; emits `http.error` (warn/error/crit with client IP); skips debug/notice; 8 tests

**syslog_firewall** — tail `/var/log/syslog` (or `/var/log/kern.log`); parses iptables/nftables/UFW DROP (`SRC=`, `DPT=`, `PROTO=`, `IN=`); emits `network.connection_blocked` (Low) feeding port_scan detector; supports UFW `[UFW BLOCK]`, iptables LOG, nftables; ignores ICMP; byte-offset cursor with resume; 10 tests

**macos_log** — subprocess `log stream` (macOS only); reuses SSH parser; emits `sudo.command`; restart loop; 3 tests

**ebpf_syscall** — eBPF ring buffer consumer; loads 22 kernel programs via Aya; CO-RE/BTF relocations; epoll-based wakeup; emits events for all SyscallKind variants (see eBPF Subsystem section below)

**cloudtrail** — tail AWS CloudTrail log directory (JSONL); parses API calls, user identity, source IP; emits events per CloudTrail record

### EXTERNAL (requires separate tool installation)

**falco_log** — tail `/var/log/falco/falco.log` (JSONL); maps priority → Severity; extracts entities from `output_fields` (IP, user, container, pod); incident passthrough for High/Critical; 12 tests

**suricata_eve** — tail `/var/log/suricata/eve.json` (JSONL); configurable event_types (alert, dns, http, tls, anomaly by default); inverse Suricata severity mapping (1→Critical, 2→High, 3→Medium); incident passthrough for alert severity 1+2; builders per type; 10 tests

**wazuh_alerts** — tail `/var/ossec/logs/alerts/alerts.json` (JSONL); severity by `rule.level` (0-2→Debug, 3-6→Low, 7-9→Medium, 10-11→High, 12-15→Critical); kind from `rule.groups[0]` with `wazuh.` prefix; extracts `data.srcip`, `data.dstuser`, `agent.name`; incident passthrough for High/Critical; 12 tests

**osquery_log** — tail `/var/log/osquery/osqueryd.results.log` (JSONL); differential results (added/snapshot, skips removed); severity by query name prefix (sudoers→High, listening_ports/crontab→Medium, processes/users→Low); filters private IPs; extracts remote IP, path, user (prefers decorations); contextual summaries by query slug; 9 tests

## Detectors (37)

**ssh_bruteforce** — sliding window by IP, configurable threshold and window

**credential_stuffing** — distinct usernames per IP within window (spray attack detection)

**port_scan** — unique destination ports per IP from firewall logs

**sudo_abuse** — burst of suspicious privileged commands per user within window

**search_abuse** — sliding window by IP+path from nginx `http.request` events

**web_scan** — sliding window by IP from nginx `http.error` events; detects scanners/probes; 6 tests

**execution_guard** — structural AST analysis via `tree-sitter-bash` + argv scoring + sequence correlation per user (download→chmod→execute in sliding window); emits `suspicious_execution` with score, signals, evidence; observe mode (detects, does not block)

**user_agent_scanner** — immediate detection of known security scanners by User-Agent in `http.request` events; 20 signatures (Nikto, sqlmap, Nuclei, Masscan, Zgrab, wfuzz, DirBuster, Gobuster, ffuf, Acunetix, w3af, AppScan, OpenVAS, Nessus, Burp Suite, Metasploit, Nmap, python-requests, go-http-client, plus variants); dedup by `(ip, scanner)` in 10-minute window; MITRE T1595, T1595.002; 11 tests

**c2_callback** — detects command-and-control callback patterns (beaconing, periodic connections)

**container_escape** — privileged container breakout detection (mount, capabilities, docker.sock)

**distributed_ssh** — coordinated SSH brute-force from multiple source IPs

**suspicious_login** — anomalous login detection (unusual time, location, user)

**process_tree** — process lineage analysis; detects suspicious parent-child relationships

**docker_anomaly** — abnormal Docker container behavior detection

**integrity_alert** — file integrity monitoring alerts (hash changes on critical files)

**privesc** — privilege escalation detection from eBPF commit_creds events

**osquery_anomaly** — anomalous osquery differential results

**suricata_alert** — Suricata IDS alert passthrough with severity mapping

**crypto_miner** — cryptocurrency mining detection (process names, CPU patterns, mining pool connections)

**credential_harvest** — credential harvesting and dumping detection (mimikatz, /etc/shadow access, proc/maps)

**crontab_persistence** — cron-based persistence mechanism detection (new cron entries, crontab writes)

**data_exfiltration** — data exfiltration detection (large outbound transfers, archive creation + upload)

**dns_tunneling** — DNS tunneling detection (high-entropy subdomains, excessive query volume, TXT record abuse)

**fileless** — fileless malware detection (memfd_create, /proc/self/mem writes, /dev/shm execution)

**kernel_module_load** — kernel module loading detection (insmod, modprobe, init_module syscall)

**lateral_movement** — lateral movement detection (SSH to internal hosts, credential reuse, RDP)

**log_tampering** — log tampering and evidence destruction detection (log deletion, truncation, history clearing)

**outbound_anomaly** — anomalous outbound network traffic detection (unusual destinations, data volume spikes)

**packet_flood** — DDoS / packet flood detection (SYN flood, UDP flood, ICMP flood, amplification)

**process_injection** — process injection detection (ptrace attach, /proc/pid/mem writes, LD_PRELOAD)

**ransomware** — ransomware detection (mass file encryption, ransom note creation, shadow copy deletion)

**reverse_shell** — reverse shell detection (fd redirection, bind+listen, /dev/tcp, named pipes)

**rootkit** — rootkit detection (hidden processes, kernel module hiding, /proc anomalies, syscall hooking)

**ssh_key_injection** — SSH authorized_keys injection detection (unauthorized key additions)

**systemd_persistence** — systemd-based persistence detection (new services, timer units, generator scripts)

**user_creation** — unauthorized user account creation detection (useradd, /etc/passwd writes)

**web_shell** — web shell detection (PHP/JSP/ASP shell patterns, suspicious web-accessible scripts)

## eBPF Subsystem

22 kernel programs loaded via Aya, compiled as `#![no_std]` targeting `bpfel-unknown-none`. CO-RE/BTF relocations for cross-kernel portability. Ring buffer with epoll-based wakeup for low-latency event delivery.

### Tracepoints (18)

| Hook | Syscall | SyscallKind | Detection purpose |
|------|---------|-------------|-------------------|
| sys_enter_execve | execve | Execve | Process execution |
| sys_enter_connect | connect | Connect | Outbound connections |
| sys_enter_openat | openat | FileOpen | Sensitive file access |
| sched_process_exit | exit | ProcessExit | Process lifecycle (rootkit detection) |
| sys_enter_ptrace | ptrace | Ptrace | Process injection (ATTACH/POKETEXT) |
| sys_enter_setuid | setuid/setgid/setresuid/setresgid | SetUid | Privilege change to root |
| sys_enter_bind | bind | SocketBind | Reverse shell setup |
| sys_enter_mount | mount | Mount | Container escape |
| sys_enter_memfd_create | memfd_create | MemfdCreate | Fileless malware |
| sys_enter_init_module | init_module/finit_module | InitModule | Rootkit / kernel module loading |
| sys_enter_dup | dup2/dup3 | Dup | Reverse shell fd redirection |
| sys_enter_listen | listen | Listen | Backdoor / reverse shell confirmation |
| sys_enter_mprotect | mprotect | Mprotect | Shellcode (RWX transitions) |
| sys_enter_clone | clone/clone3 | Clone | Fork bombs, process tree |
| sys_enter_unlink | unlink/unlinkat | Unlink | Evidence destruction, log wipe |
| sys_enter_rename | rename/renameat | Rename | Binary replacement, config tampering |
| sys_enter_kill | kill/tkill | Kill | Killing security processes |
| sys_enter_prctl | prctl | Prctl | Name spoofing, no_new_privs bypass |
| sys_enter_accept | accept/accept4 | Accept | Incoming connection accepted |

### Kprobe (1)

| Hook | Function | Detection purpose |
|------|----------|-------------------|
| commit_creds | commit_creds | Privilege escalation (uid non-root → root) |

### LSM (1)

| Hook | Detection purpose |
|------|-------------------|
| bprm_check_security | Blocks execution from /tmp, /dev/shm (policy-gated) |

### XDP (1)

| Program | Detection purpose |
|---------|-------------------|
| innerwarden_xdp | Wire-speed IP blocking at network driver level |

### Tail Call Dispatcher (1)

| Program | Detection purpose |
|---------|-------------------|
| innerwarden_dispatcher | raw_tracepoint/sys_enter entry; reads syscall number and tail-calls to handler via ProgramArray |

### Event structs (`crates/sensor-ebpf-types/`)

ExecveEvent, ConnectEvent, FileOpenEvent, PrivEscEvent, ProcessExitEvent, PtraceEvent, SetUidEvent, SocketBindEvent, MountEvent, MemfdCreateEvent, ModuleLoadEvent, DupEvent, ListenEvent, MprotectEvent, CloneEvent, UnlinkEvent, RenameEvent, KillEvent, PrctlEvent, AcceptEvent

All structs are `#[repr(C)]` for cross-boundary compatibility. Container-aware via `cgroup_id` field. Kernel-side filtering reduces userspace load (e.g., only dangerous ptrace operations, only sensitive path opens, only uid→root transitions).

## Output

- JSONL append-only with automatic daily rotation
- Optional Redis Streams sink (`redis_url` config) — events and incidents published to `innerwarden:events` / `innerwarden:incidents` streams with `MAXLEN ~` trimming
- Fail-open: I/O errors in collectors are logged, never crash the daemon
- Dual flush: by count (50 events) + by time (5s interval)
- Graceful shutdown (SIGINT/SIGTERM) with cursor persistence

## Architecture

```
[auth_log] [journald] [docker] [integrity] [nginx] [ebpf] [suricata] ...
     ↓           ↓          ↓         ↓          ↓       ↓         ↓
                        mpsc::channel(1024)
                               ↓
              [ssh_bruteforce] [rootkit] [ransomware] ...  ← 37 Detectors (stateful)
                               ↓
                    events-YYYY-MM-DD.jsonl     ← JSONL sink
                    incidents-YYYY-MM-DD.jsonl
                               ↓ (optional)
                    Redis Streams               ← redis_stream sink
                    innerwarden:events
                    innerwarden:incidents
```
