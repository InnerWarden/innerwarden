//! MITRE ATT&CK technique hunter — command-pattern detection for 10 techniques.
//!
//! This detector watches `shell.command_exec` and `sudo.command` events for
//! specific command patterns that map to MITRE ATT&CK techniques not covered
//! by other dedicated detectors.
//!
//! Each technique match emits an incident with a unique `incident_id` prefix
//! that maps to a specific MITRE technique in `mitre.rs`.
//!
//! Techniques detected:
//!   T1053.002 (At Jobs)           — at, atq, atrm, batch
//!   T1222.002 (File Perms Mod)    — chmod +s, chattr, chown root
//!   T1564.001 (Hidden Files)      — mv/cp/mkdir to hidden path
//!   T1219     (Remote Access)     — ngrok, anydesk, teamviewer, etc.
//!   T1489     (Service Stop)      — systemctl stop on security services
//!   T1529     (Shutdown/Reboot)   — shutdown, reboot, poweroff, halt
//!   T1040     (Network Sniffing)  — tcpdump, tshark, wireshark, etc.
//!   T1036.005 (Masquerading)      — system binary name from attacker-writable path
//!   T1560     (Archive Data)      — tar/zip of sensitive directories
//!   T1090     (Proxy/Tunneling)   — ssh -D/-L/-R, socat, chisel, etc.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

// ─── Pattern constants ─────────────────────────────────────────────────────

/// T1053.002 — Scheduled Task/Job: At
const AT_COMMANDS: &[&str] = &["at", "atq", "atrm", "batch"];

/// T1219 — Remote Access Software
const REMOTE_ACCESS_TOOLS: &[&str] = &[
    "ngrok",
    "anydesk",
    "teamviewer",
    "rustdesk",
    "bore",
    "rathole",
    "cloudflared",
    "localtunnel",
    "serveo",
    "pagekite",
];

/// T1489 — Security services whose stop/disable is suspicious
const SECURITY_SERVICES: &[&str] = &[
    "sshd",
    "auditd",
    "fail2ban",
    "innerwarden",
    "apparmor",
    "ufw",
    "firewalld",
    "iptables",
    "nftables",
    "crowdsec",
    "ossec",
    "wazuh",
    "clamd",
    "clamav",
    "aide",
    "tripwire",
    "snort",
    "suricata",
    "falco",
    "osqueryd",
    "syslog",
    "rsyslog",
    "syslog-ng",
    "journald",
];

/// T1529 — System Shutdown/Reboot
const SHUTDOWN_COMMANDS: &[&str] = &["shutdown", "reboot", "poweroff", "halt"];

/// T1040 — Network Sniffing tools
const SNIFFING_TOOLS: &[&str] = &[
    "tcpdump",
    "tshark",
    "wireshark",
    "dumpcap",
    "ngrep",
    "ettercap",
    "bettercap",
    "dsniff",
    "arpspoof",
    "mitmproxy",
];

/// T1036.005 — System binaries commonly impersonated by malware
const SYSTEM_BINARIES: &[&str] = &[
    "ls",
    "ps",
    "cat",
    "cp",
    "mv",
    "rm",
    "sh",
    "bash",
    "dash",
    "top",
    "grep",
    "find",
    "awk",
    "sed",
    "curl",
    "wget",
    "ssh",
    "scp",
    "tar",
    "gzip",
    "mount",
    "kill",
    "netstat",
    "ss",
    "ip",
    "iptables",
    "systemctl",
    "journalctl",
    "cron",
    "sshd",
    "sudo",
    "su",
    "login",
    "passwd",
    "useradd",
    "chown",
    "chmod",
];

/// T1036.005 — Legitimate system binary paths (if binary runs from here, not masquerading)
const SYSTEM_PATHS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",
    "/snap/",
    "/nix/store/",
];

/// T1036.005 — Attacker-writable paths where masquerading binaries appear
const ATTACKER_PATHS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",
    "/root/",
];

/// T1090 — Proxy/tunneling tools
const PROXY_TOOLS: &[&str] = &[
    "socat",
    "proxychains",
    "proxychains4",
    "chisel",
    "frpc",
    "frps",
    "gost",
    "iodine",
    "dns2tcp",
    "revsocks",
    "ligolo",
];

/// T1560 — Sensitive directories that should not be archived by arbitrary processes
const SENSITIVE_ARCHIVE_TARGETS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssh",
    "/etc/sudoers",
    ".ssh/",
    ".aws/",
    ".gnupg/",
    ".kube/",
    "/home/",
    "/root/",
    "/var/log/",
    "/etc/",
];

/// T1222.002 — Dangerous chmod/chattr patterns (checked against full argv joined)
const SUID_PATTERNS: &[&str] = &[
    "chmod +s",
    "chmod u+s",
    "chmod g+s",
    "chmod 4",
    "chmod 2",
    "chmod 6",
    "chattr +i",
    "chattr -i",
    "chattr +a",
];

// ─── Detector ──────────────────────────────────────────────────────────────

/// Detects command patterns mapped to specific MITRE ATT&CK techniques.
pub struct MitreHuntDetector {
    host: String,
    cooldown: Duration,
    /// Cooldown tracker: "prefix:entity" → last alert time.
    alerted: HashMap<String, DateTime<Utc>>,
}

impl MitreHuntDetector {
    pub fn new(host: impl Into<String>, cooldown_secs: i64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_secs),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" | "sudo.command" => self.analyze(event),
            "process.prctl" => self.check_prctl_rename(event),
            _ => None,
        }
    }

    fn analyze(&mut self, event: &Event) -> Option<Incident> {
        let argv = extract_argv(event);
        if argv.is_empty() {
            return None;
        }

        // Resolve wrapper commands: timeout, nice, nohup, env, strace wrap
        // the real command. Skip the wrapper + its flags to find the actual binary.
        let (argv0, argv0_base) = resolve_wrapper(&argv);
        let argv_joined = argv.join(" ");
        let now = event.ts;

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let user = event
            .details
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Try each technique in priority order (highest severity first).
        // Return the first match — a single command rarely maps to multiple.

        // T1036.005 — Masquerading (Critical)
        if let Some(inc) = self.check_masquerading(&argv0, &argv0_base, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1529 — System Shutdown/Reboot (Critical)
        if let Some(inc) = self.check_shutdown(&argv0_base, &argv, pid, uid, user, now, event) {
            return Some(inc);
        }

        // T1489 — Service Stop (High)
        if let Some(inc) =
            self.check_service_stop(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1222.002 — File Permissions Modification (High)
        if let Some(inc) =
            self.check_file_permission_mod(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1219 — Remote Access Software (High)
        if let Some(inc) = self.check_remote_access(&argv0_base, pid, uid, user, now, event) {
            return Some(inc);
        }

        // T1560 — Archive Collected Data (High)
        if let Some(inc) =
            self.check_data_archive(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1090 — Proxy/Tunneling (High)
        if let Some(inc) =
            self.check_proxy_tunnel(&argv0_base, &argv, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1053.002 — At Jobs (Medium)
        if let Some(inc) = self.check_at_job(&argv0_base, pid, uid, user, now, event) {
            return Some(inc);
        }

        // T1564.001 — Hidden Files (Medium)
        if let Some(inc) =
            self.check_hidden_artifact(&argv0_base, &argv, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1040 — Network Sniffing (Medium)
        if let Some(inc) = self.check_network_sniffing(&argv0_base, pid, uid, user, now, event) {
            return Some(inc);
        }

        // T1485 — Destructive DD (High)
        if let Some(inc) =
            self.check_destructive_dd(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1552.004 — Private Key Search (Medium)
        if let Some(inc) =
            self.check_private_key_search(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1560 — Suspicious Archive/Compression (Medium)
        if let Some(inc) =
            self.check_suspicious_archive(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        // T1562.006 — Logging Configuration Changes (High)
        if let Some(inc) =
            self.check_logging_config_change(&argv0_base, &argv_joined, pid, uid, user, now, event)
        {
            return Some(inc);
        }

        None
    }

    // ── T1036.005: Masquerading ────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_masquerading(
        &mut self,
        argv0: &str,
        argv0_base: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        // Only flag if the binary name matches a known system binary
        if !SYSTEM_BINARIES.contains(&argv0_base) {
            return None;
        }
        // Only flag if running from an attacker-writable path
        let from_attacker_path = ATTACKER_PATHS.iter().any(|p| argv0.starts_with(p));
        if !from_attacker_path {
            return None;
        }
        // Verify it's NOT a legitimate path (defense in depth)
        let from_system_path = SYSTEM_PATHS.iter().any(|p| argv0.starts_with(p));
        if from_system_path {
            return None;
        }

        self.emit(
            "masquerading",
            Severity::Critical,
            format!(
                "Masquerading: '{argv0_base}' executed from suspicious path {argv0} \
                 (pid={pid}, uid={uid}, user={user})"
            ),
            format!(
                "Binary '{argv0_base}' is a common system utility but was executed from \
                 '{argv0}', an attacker-writable location. Legitimate '{argv0_base}' \
                 should run from /usr/bin or /sbin. This may indicate a trojanized binary."
            ),
            serde_json::json!([{
                "kind": "masquerading",
                "binary": argv0,
                "expected_path": format!("/usr/bin/{argv0_base}"),
                "comm": argv0_base,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Verify binary: file {argv0} && sha256sum {argv0}"),
                format!(
                    "Compare with system binary: diff <(xxd /usr/bin/{argv0_base}) <(xxd {argv0})"
                ),
                format!("Check process tree: ps -ef --forest | grep {pid}"),
                format!("Kill suspicious process: kill -9 {pid}"),
            ],
            &["masquerading", "defense_evasion", "trojan"],
            vec![EntityRef::path(format!("/proc/{pid}"))],
            user,
            now,
            event,
        )
    }

    // ── T1529: System Shutdown/Reboot ──────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_shutdown(
        &mut self,
        argv0_base: &str,
        argv: &[String],
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if !SHUTDOWN_COMMANDS.contains(&argv0_base) {
            // Also check `init 0` / `init 6`
            if argv0_base == "init" {
                let has_halt_arg = argv.iter().any(|a| a == "0" || a == "6");
                if !has_halt_arg {
                    return None;
                }
            } else {
                return None;
            }
        }

        self.emit(
            "system_shutdown",
            Severity::Critical,
            format!("System shutdown/reboot initiated: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) initiated a system shutdown \
                 or reboot. If unexpected, this may indicate a destructive attack or \
                 an attacker covering their tracks."
            ),
            serde_json::json!([{
                "kind": "system_shutdown",
                "command": argv0_base,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "Verify if shutdown was authorized".to_string(),
                format!("Check who triggered it: last -x | head"),
                "Review auth.log for recent suspicious activity".to_string(),
            ],
            &["shutdown", "impact"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1489: Service Stop ────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_service_stop(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if argv0_base != "systemctl" && argv0_base != "service" {
            return None;
        }

        let is_stop_action = argv_joined.contains(" stop ")
            || argv_joined.contains(" disable ")
            || argv_joined.contains(" mask ");

        if !is_stop_action {
            return None;
        }

        let target_service = SECURITY_SERVICES
            .iter()
            .find(|svc| argv_joined.contains(**svc));

        let target_service = match target_service {
            Some(svc) => *svc,
            None => return None,
        };

        // Skip admin restarts of InnerWarden services (deploy, upgrade).
        // uid=0 stopping innerwarden-* is normal operations.
        if uid == 0 && target_service == "innerwarden" {
            return None;
        }

        self.emit(
            "service_stop",
            Severity::High,
            format!(
                "Security service stopped: {target_service} via {argv0_base} \
                 (pid={pid}, user={user})"
            ),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) stopped or disabled \
                 security service '{target_service}'. Attackers commonly disable \
                 security tooling before lateral movement or data exfiltration."
            ),
            serde_json::json!([{
                "kind": "service_stop",
                "service": target_service,
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Check service status: systemctl status {target_service}"),
                format!("Restart service: systemctl start {target_service}"),
                format!("Check who stopped it: journalctl -u {target_service} --since '5 min ago'"),
            ],
            &["service_stop", "impact", "defense_evasion"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1222.002: File Permissions Modification ───────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_file_permission_mod(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if argv0_base != "chmod" && argv0_base != "chattr" && argv0_base != "chown" {
            return None;
        }

        // chmod: only flag SUID/SGID or world-writable patterns
        if argv0_base == "chmod" || argv0_base == "chattr" {
            let is_dangerous = SUID_PATTERNS.iter().any(|pat| argv_joined.contains(pat));
            if !is_dangerous {
                return None;
            }
        }

        // chown: only flag ownership change to root
        if argv0_base == "chown" {
            let to_root = argv_joined.contains("root:") || argv_joined.contains(" root ");
            if !to_root {
                return None;
            }
        }

        self.emit(
            "file_permission_mod",
            Severity::High,
            format!("Suspicious file permission change: {argv_joined} (pid={pid}, user={user})"),
            format!(
                "Process (pid={pid}, uid={uid}) modified file permissions with a dangerous \
                 pattern. SUID/SGID bits, immutable flags, or ownership changes to root can \
                 be used for privilege escalation or persistence."
            ),
            serde_json::json!([{
                "kind": "file_permission_mod",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "Find all SUID binaries: find / -perm -4000 2>/dev/null".to_string(),
                "Find all SGID binaries: find / -perm -2000 2>/dev/null".to_string(),
                format!("Check process: ps -p {pid} -o pid,ppid,user,comm,args"),
            ],
            &["file_permission", "defense_evasion", "privilege_escalation"],
            vec![EntityRef::path(format!("/proc/{pid}"))],
            user,
            now,
            event,
        )
    }

    // ── T1219: Remote Access Software ──────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_remote_access(
        &mut self,
        argv0_base: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if !REMOTE_ACCESS_TOOLS.contains(&argv0_base) {
            return None;
        }

        self.emit(
            "remote_access_tool",
            Severity::High,
            format!("Remote access tool detected: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) is a remote access or \
                 tunneling tool that can bypass network controls. If not authorized, \
                 this may indicate an attacker establishing persistent remote access."
            ),
            serde_json::json!([{
                "kind": "remote_access_tool",
                "tool": argv0_base,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Kill process: kill -9 {pid}"),
                format!("Check connections: ss -tunap | grep {pid}"),
                format!("Check binary: which {argv0_base} && file $(which {argv0_base})"),
            ],
            &["remote_access", "command_and_control"],
            vec![EntityRef::path(format!("/proc/{pid}"))],
            user,
            now,
            event,
        )
    }

    // ── T1560: Archive Collected Data ──────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_data_archive(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if argv0_base != "tar"
            && argv0_base != "zip"
            && argv0_base != "gzip"
            && argv0_base != "7z"
            && argv0_base != "rar"
        {
            return None;
        }

        // Only flag if archiving sensitive directories
        let targets_sensitive = SENSITIVE_ARCHIVE_TARGETS
            .iter()
            .any(|t| argv_joined.contains(t));

        if !targets_sensitive {
            return None;
        }

        self.emit(
            "data_archive",
            Severity::High,
            format!(
                "Sensitive data archived: {argv0_base} targeting sensitive paths \
                 (pid={pid}, user={user})"
            ),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) is creating an archive \
                 containing sensitive data. This is a common precursor to data \
                 exfiltration — attackers stage data in archives before transferring it out."
            ),
            serde_json::json!([{
                "kind": "data_archive",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Check output file: lsof -p {pid}"),
                format!("Check for exfiltration: ss -tunap | grep {pid}"),
                "Review recent outbound connections".to_string(),
            ],
            &["data_archive", "collection", "exfiltration"],
            vec![EntityRef::path(format!("/proc/{pid}"))],
            user,
            now,
            event,
        )
    }

    // ── T1090: Proxy/Tunneling ─────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_proxy_tunnel(
        &mut self,
        argv0_base: &str,
        argv: &[String],
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        // Dedicated proxy tools
        if PROXY_TOOLS.contains(&argv0_base) {
            return self.emit(
                "proxy_tunnel",
                Severity::High,
                format!("Proxy/tunneling tool detected: {argv0_base} (pid={pid}, user={user})"),
                format!(
                    "Process '{argv0_base}' (pid={pid}, uid={uid}) is a proxy or tunneling \
                     tool that can exfiltrate data or provide covert access channels."
                ),
                serde_json::json!([{
                    "kind": "proxy_tunnel",
                    "tool": argv0_base,
                    "command": argv_joined,
                    "pid": pid,
                    "uid": uid,
                }]),
                vec![
                    format!("Kill process: kill -9 {pid}"),
                    format!("Check tunnel endpoints: ss -tunap | grep {pid}"),
                ],
                &["proxy", "tunneling", "command_and_control"],
                vec![EntityRef::path(format!("/proc/{pid}"))],
                user,
                now,
                event,
            );
        }

        // SSH tunneling: ssh -D (SOCKS), ssh -L (local forward), ssh -R (remote forward)
        if argv0_base == "ssh" {
            let has_tunnel_flag = argv.iter().any(|a| {
                a == "-D"
                    || a == "-L"
                    || a == "-R"
                    || a.starts_with("-D")
                    || a.starts_with("-L")
                    || a.starts_with("-R")
                    // Combined flags like -NfD
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('D') || a.contains('L') || a.contains('R'))
                        && a.len() > 2)
            });
            if !has_tunnel_flag {
                return None;
            }
            return self.emit(
                "proxy_tunnel",
                Severity::High,
                format!("SSH tunnel detected: {argv_joined} (pid={pid}, user={user})"),
                format!(
                    "SSH (pid={pid}, uid={uid}) was invoked with port forwarding flags \
                     (-D/-L/-R). This creates a network tunnel that can bypass firewall \
                     rules and exfiltrate data through encrypted channels."
                ),
                serde_json::json!([{
                    "kind": "ssh_tunnel",
                    "command": argv_joined,
                    "pid": pid,
                    "uid": uid,
                }]),
                vec![
                    format!("Check tunnel: ss -tunap | grep {pid}"),
                    format!("Kill tunnel: kill {pid}"),
                ],
                &["ssh_tunnel", "proxy", "command_and_control"],
                vec![EntityRef::path(format!("/proc/{pid}"))],
                user,
                now,
                event,
            );
        }

        None
    }

    // ── T1053.002: At Jobs ─────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_at_job(
        &mut self,
        argv0_base: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if !AT_COMMANDS.contains(&argv0_base) {
            return None;
        }

        self.emit(
            "at_job_persist",
            Severity::Medium,
            format!("Scheduled task via at: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) schedules one-time task \
                 execution. Attackers use at/batch for persistence that survives cron \
                 monitoring and is harder to discover."
            ),
            serde_json::json!([{
                "kind": "at_job",
                "command": argv0_base,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "List scheduled at jobs: atq".to_string(),
                "Inspect job content: at -c <job_number>".to_string(),
                format!("Check who scheduled it: grep '{user}' /var/log/auth.log | tail"),
            ],
            &["at_job", "persistence", "scheduled_task"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1564.001: Hidden Files and Directories ────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_hidden_artifact(
        &mut self,
        argv0_base: &str,
        argv: &[String],
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        // mv, cp, mkdir, touch creating hidden files/directories
        if argv0_base != "mv"
            && argv0_base != "cp"
            && argv0_base != "mkdir"
            && argv0_base != "touch"
            && argv0_base != "tee"
        {
            return None;
        }

        // Check if any argument (destination) is a hidden path
        // Hidden = contains "/." component that isn't "/." or "/.."
        let hidden_target = argv.iter().skip(1).find(|arg| {
            // Skip flags
            if arg.starts_with('-') {
                return false;
            }
            is_hidden_path(arg)
        });

        let hidden_target = match hidden_target {
            Some(t) => t.clone(),
            None => return None,
        };

        self.emit(
            "hidden_artifact",
            Severity::Medium,
            format!(
                "Hidden file/directory created: {argv0_base} → {hidden_target} \
                 (pid={pid}, user={user})"
            ),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) created or moved a file \
                 to a hidden location '{hidden_target}'. Attackers hide tools and \
                 backdoors in dotfiles/directories to avoid casual discovery."
            ),
            serde_json::json!([{
                "kind": "hidden_artifact",
                "command": argv0_base,
                "target": hidden_target,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Inspect hidden file: ls -la {hidden_target}"),
                format!("Check contents: file {hidden_target}"),
                "Find all hidden files in /tmp: find /tmp -name '.*' -ls".to_string(),
            ],
            &["hidden_files", "defense_evasion"],
            vec![EntityRef::path(&hidden_target)],
            user,
            now,
            event,
        )
    }

    // ── T1040: Network Sniffing ────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_network_sniffing(
        &mut self,
        argv0_base: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if !SNIFFING_TOOLS.contains(&argv0_base) {
            return None;
        }

        self.emit(
            "network_sniffing",
            Severity::Medium,
            format!("Network sniffing tool detected: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) can capture network traffic \
                 including credentials, session tokens, and sensitive data transmitted \
                 in cleartext."
            ),
            serde_json::json!([{
                "kind": "network_sniffing",
                "tool": argv0_base,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Check what it captures: ls -la /tmp/*.pcap 2>/dev/null"),
                format!("Kill process: kill -9 {pid}"),
                format!("Check if running as root: ps -p {pid} -o user,pid,comm"),
            ],
            &["network_sniffing", "credential_access"],
            vec![EntityRef::path(format!("/proc/{pid}"))],
            user,
            now,
            event,
        )
    }

    // ── T1036.004: Masquerade via prctl PR_SET_NAME ─────────────────────

    fn check_prctl_rename(&mut self, event: &Event) -> Option<Incident> {
        let op_name = event.details.get("op_name").and_then(|v| v.as_str())?;
        if op_name != "PR_SET_NAME" {
            return None;
        }

        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip innerwarden's own processes and system daemons
        if super::allowlists::is_innerwarden_process(uid as u64, comm)
            || super::allowlists::comm_in_allowlist(comm, super::allowlists::SYSTEM_DAEMONS)
        {
            return None;
        }

        // Renaming to a known daemon name is suspicious
        let daemon_names = [
            "sshd",
            "crond",
            "cron",
            "systemd",
            "kworker",
            "ksoftirqd",
            "migration",
            "watchdog",
            "nginx",
            "apache2",
            "mysqld",
            "postgres",
        ];
        let is_suspicious = daemon_names.iter().any(|d| comm.contains(d));
        if !is_suspicious {
            return None;
        }

        self.emit(
            "prctl_rename",
            Severity::High,
            format!("Process name change via prctl: PID {pid} renamed to '{comm}'"),
            format!(
                "Process (pid={pid}, uid={uid}) used prctl(PR_SET_NAME) to rename itself to \
                 '{comm}', a known system daemon name. This is a common masquerading technique."
            ),
            serde_json::json!([{
                "kind": "prctl_rename",
                "comm": comm,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!("Check actual binary: readlink /proc/{pid}/exe"),
                format!("Check parent: ps -o ppid= -p {pid}"),
            ],
            &["masquerading", "defense_evasion", "prctl"],
            vec![],
            "unknown",
            event.ts,
            event,
        )
    }

    // ── T1485: Destructive DD ────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_destructive_dd(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if argv0_base != "dd" {
            return None;
        }

        // Check for destructive targets
        let dangerous_targets = [
            "/dev/sd",
            "/dev/vd",
            "/dev/nvme",
            "/dev/mapper/",
            "/dev/dm-",
            "/boot/",
            "/dev/null",
        ];
        let has_dangerous_of = dangerous_targets
            .iter()
            .any(|t| argv_joined.contains(&format!("of={t}")));

        // Also catch dd writing zeros/random to any file
        let has_destructive_input = argv_joined.contains("if=/dev/zero")
            || argv_joined.contains("if=/dev/urandom")
            || argv_joined.contains("if=/dev/random");

        if !has_dangerous_of && !has_destructive_input {
            return None;
        }

        self.emit(
            "destructive_dd",
            Severity::Critical,
            format!("Destructive dd command: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process 'dd' (pid={pid}, uid={uid}) executed with destructive parameters. \
                 Command: {}. This could wipe data or destroy disk contents.",
                &argv_joined[..argv_joined.len().min(120)]
            ),
            serde_json::json!([{
                "kind": "destructive_dd",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                format!(
                    "CRITICAL: Verify dd command was authorized: {}",
                    &argv_joined[..argv_joined.len().min(80)]
                ),
                "Check if data was destroyed: fsck, mount, ls".to_string(),
                format!("Kill if unauthorized: kill -9 {pid}"),
            ],
            &["destructive", "impact", "disk_wipe"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1552.004: Private Key Search ─────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_private_key_search(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        if argv0_base != "find" && argv0_base != "grep" && argv0_base != "locate" {
            return None;
        }

        let key_patterns = [
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            "PRIVATE KEY",
            "private_key",
            "privatekey",
        ];

        let is_key_search = key_patterns.iter().any(|p| argv_joined.contains(p));
        if !is_key_search {
            return None;
        }

        // Skip legitimate tools
        if argv0_base == "find"
            && (argv_joined.contains("ssh-keygen") || argv_joined.contains("certbot"))
        {
            return None;
        }

        self.emit(
            "private_key_search",
            Severity::Medium,
            format!("Private key search: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) searching for private keys. \
                 Command: {}. Attackers search for SSH/TLS keys to enable lateral movement.",
                &argv_joined[..argv_joined.len().min(120)]
            ),
            serde_json::json!([{
                "kind": "private_key_search",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "Verify if this key search was authorized".to_string(),
                "Check if any keys were exfiltrated: review outbound connections".to_string(),
                format!("Review user activity: ausearch -ua {uid}"),
            ],
            &["credential_access", "private_key"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1560: Suspicious Archive/Compression ──────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_suspicious_archive(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        // Detect archiving sensitive directories (not just any tar/zip)
        let archive_tools = ["tar", "zip", "7z", "rar", "gzip", "bzip2", "xz"];
        if !archive_tools.contains(&argv0_base) && !argv_joined.contains("zipfile") {
            return None;
        }

        let sensitive_targets = [
            "/etc/",
            "/root/",
            "/home/",
            "/var/lib/",
            ".ssh/",
            "shadow",
            "passwd",
            ".gnupg",
        ];
        let has_sensitive = sensitive_targets.iter().any(|t| argv_joined.contains(t));
        if !has_sensitive {
            return None;
        }

        self.emit(
            "suspicious_archive",
            Severity::Medium,
            format!("Suspicious data archiving: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) is archiving sensitive data. \
                 Command: {}. This may indicate staging for exfiltration.",
                &argv_joined[..argv_joined.len().min(120)]
            ),
            serde_json::json!([{
                "kind": "suspicious_archive",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "Check if this archive operation was authorized".to_string(),
                "Review outbound connections for exfiltration".to_string(),
            ],
            &["collection", "archive", "exfiltration_staging"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── T1562.006: Logging Configuration Changes ─────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn check_logging_config_change(
        &mut self,
        argv0_base: &str,
        argv_joined: &str,
        pid: u32,
        uid: u32,
        user: &str,
        now: DateTime<Utc>,
        event: &Event,
    ) -> Option<Incident> {
        // Detect modifications to logging configuration files
        let config_editors = ["sed", "vi", "vim", "nano", "tee", "bash", "sh"];
        if !config_editors.contains(&argv0_base) {
            return None;
        }

        let logging_configs = [
            "rsyslog.conf",
            "syslog.conf",
            "journald.conf",
            "logrotate",
            "auditd.conf",
            "audit.rules",
            "/etc/rsyslog.d/",
            "/etc/logrotate.d/",
        ];
        let targets_logging = logging_configs.iter().any(|c| argv_joined.contains(c));
        if !targets_logging {
            return None;
        }

        self.emit(
            "logging_config_change",
            Severity::High,
            format!("Logging configuration modified: {argv0_base} (pid={pid}, user={user})"),
            format!(
                "Process '{argv0_base}' (pid={pid}, uid={uid}) modified logging configuration. \
                 Command: {}. Attackers disable or redirect logging to hide their tracks.",
                &argv_joined[..argv_joined.len().min(120)]
            ),
            serde_json::json!([{
                "kind": "logging_config_change",
                "command": argv_joined,
                "pid": pid,
                "uid": uid,
            }]),
            vec![
                "Check if logging is still functional: journalctl --since '5 min ago'".to_string(),
                "Review the config change: diff against backup".to_string(),
            ],
            &["defense_evasion", "logging", "impair_defenses"],
            vec![],
            user,
            now,
            event,
        )
    }

    // ── Incident emission with cooldown ────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        prefix: &str,
        severity: Severity,
        title: String,
        summary: String,
        evidence: serde_json::Value,
        recommended_checks: Vec<String>,
        tags: &[&str],
        entities: Vec<EntityRef>,
        user: &str,
        now: DateTime<Utc>,
        _event: &Event,
    ) -> Option<Incident> {
        let cooldown_key = format!("{prefix}:{user}");

        if let Some(&last) = self.alerted.get(&cooldown_key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(cooldown_key, now);

        // Prune stale entries to cap memory
        if self.alerted.len() > 2000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("{prefix}:{user}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title,
            summary,
            evidence,
            recommended_checks,
            tags: tags.iter().map(|t| t.to_string()).collect(),
            entities,
        })
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn extract_argv(event: &Event) -> Vec<String> {
    // Try argv array first (exec_audit events)
    if let Some(arr) = event.details.get("argv").and_then(|v| v.as_array()) {
        let v: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    // Fallback: command string (split on whitespace)
    if let Some(cmd) = event.details.get("command").and_then(|v| v.as_str()) {
        if !cmd.is_empty() {
            return cmd.split_whitespace().map(str::to_string).collect();
        }
    }
    vec![]
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

/// Known command wrappers that prefix the actual command.
const WRAPPERS: &[&str] = &[
    "timeout", "nice", "nohup", "env", "strace", "ltrace", "time", "ionice", "taskset", "chrt",
    "numactl", "setsid", "script",
];

/// Skip wrapper commands and their flags to find the actual binary.
/// Returns (full_path, basename) of the resolved command.
fn resolve_wrapper(argv: &[String]) -> (String, String) {
    let mut i = 0;
    while i < argv.len() {
        let base = basename(&argv[i]);
        if WRAPPERS.contains(&base.as_str()) {
            // Skip the wrapper and any flags (args starting with '-')
            i += 1;
            while i < argv.len() && argv[i].starts_with('-') {
                i += 1;
                // Some flags take a value (e.g., timeout -s KILL 5)
                // Skip the value too if the flag doesn't contain '='
            }
            // Skip numeric arguments (e.g., `timeout 5` or `nice -n 10`)
            while i < argv.len()
                && argv[i]
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
            {
                i += 1;
            }
            continue;
        }
        return (argv[i].clone(), base);
    }
    // Fallback: use argv[0]
    (argv[0].clone(), basename(&argv[0]))
}

/// Returns true if the path contains a hidden component (starts with dot)
/// that is not `.` or `..`.
fn is_hidden_path(path: &str) -> bool {
    path.split('/').any(|component| {
        component.starts_with('.') && component != "." && component != ".." && component.len() > 1
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(command: &str, argv: &[&str]) -> Event {
        let ts = Utc::now();
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details: serde_json::json!({
                "command": command,
                "argv": argv,
                "pid": 1234u64,
                "uid": 1000u64,
                "user": "attacker",
                "comm": argv.first().unwrap_or(&""),
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn make_event_with_path(argv0_path: &str, argv: &[&str]) -> Event {
        let ts = Utc::now();
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {argv0_path}"),
            details: serde_json::json!({
                "command": argv0_path,
                "argv": argv,
                "pid": 1234u64,
                "uid": 1000u64,
                "user": "attacker",
                "comm": basename(argv0_path),
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn det() -> MitreHuntDetector {
        MitreHuntDetector::new("test-host", 300)
    }

    // ── T1036.005: Masquerading ────────────────────────────────────────

    #[test]
    fn detects_masquerading_from_tmp() {
        let mut d = det();
        let ev = make_event_with_path("/tmp/ls", &["/tmp/ls", "-la"]);
        let inc = d.process(&ev);
        assert!(inc.is_some(), "should detect masquerading from /tmp");
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.incident_id.starts_with("masquerading:"));
    }

    #[test]
    fn masquerading_ignores_legitimate_path() {
        let mut d = det();
        let ev = make_event_with_path("/usr/bin/ls", &["/usr/bin/ls", "-la"]);
        assert!(
            d.process(&ev).is_none(),
            "legitimate path should not trigger"
        );
    }

    #[test]
    fn masquerading_ignores_unknown_binary() {
        let mut d = det();
        let ev = make_event_with_path("/tmp/my_custom_tool", &["/tmp/my_custom_tool"]);
        assert!(
            d.process(&ev).is_none(),
            "non-system binary name should not trigger"
        );
    }

    #[test]
    fn detects_masquerading_from_dev_shm() {
        let mut d = det();
        let ev = make_event_with_path("/dev/shm/bash", &["/dev/shm/bash", "-c", "id"]);
        let inc = d.process(&ev);
        assert!(inc.is_some(), "should detect masquerading from /dev/shm");
    }

    // ── T1529: System Shutdown ─────────────────────────────────────────

    #[test]
    fn detects_shutdown() {
        let mut d = det();
        let ev = make_event("shutdown", &["shutdown", "-h", "now"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("system_shutdown:"));
    }

    #[test]
    fn detects_init_0() {
        let mut d = det();
        let ev = make_event("init", &["init", "0"]);
        assert!(d.process(&ev).is_some(), "init 0 should trigger");
    }

    #[test]
    fn ignores_init_without_halt_arg() {
        let mut d = det();
        let ev = make_event("init", &["init", "3"]);
        assert!(d.process(&ev).is_none(), "init 3 should not trigger");
    }

    // ── T1489: Service Stop ────────────────────────────────────────────

    #[test]
    fn detects_security_service_stop() {
        let mut d = det();
        let ev = make_event("systemctl", &["systemctl", "stop", "fail2ban"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert!(inc.incident_id.starts_with("service_stop:"));
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn detects_security_service_disable() {
        let mut d = det();
        let ev = make_event("systemctl", &["systemctl", "disable", "auditd"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn ignores_non_security_service_stop() {
        let mut d = det();
        let ev = make_event("systemctl", &["systemctl", "stop", "nginx"]);
        assert!(
            d.process(&ev).is_none(),
            "stopping non-security service should not trigger"
        );
    }

    #[test]
    fn ignores_service_start() {
        let mut d = det();
        let ev = make_event("systemctl", &["systemctl", "start", "fail2ban"]);
        assert!(
            d.process(&ev).is_none(),
            "starting a service should not trigger"
        );
    }

    // ── T1222.002: File Permission Modification ────────────────────────

    #[test]
    fn detects_chmod_suid() {
        let mut d = det();
        let ev = make_event("chmod", &["chmod", "+s", "/tmp/backdoor"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("file_permission_mod:"));
    }

    #[test]
    fn detects_chmod_4755() {
        let mut d = det();
        let ev = make_event("chmod", &["chmod", "4755", "/tmp/escalate"]);
        assert!(d.process(&ev).is_some(), "chmod 4755 should trigger");
    }

    #[test]
    fn detects_chattr_immutable() {
        let mut d = det();
        let ev = make_event("chattr", &["chattr", "+i", "/tmp/persist"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn ignores_normal_chmod() {
        let mut d = det();
        let ev = make_event("chmod", &["chmod", "755", "/opt/app/run.sh"]);
        assert!(d.process(&ev).is_none(), "normal chmod should not trigger");
    }

    // ── T1219: Remote Access Software ──────────────────────────────────

    #[test]
    fn detects_ngrok() {
        let mut d = det();
        let ev = make_event("ngrok", &["ngrok", "http", "8080"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("remote_access_tool:"));
    }

    #[test]
    fn detects_cloudflared() {
        let mut d = det();
        let ev = make_event("cloudflared", &["cloudflared", "tunnel", "run"]);
        assert!(d.process(&ev).is_some());
    }

    // ── T1560: Archive Collected Data ──────────────────────────────────

    #[test]
    fn detects_tar_of_etc() {
        let mut d = det();
        let ev = make_event("tar", &["tar", "czf", "/tmp/loot.tgz", "/etc/"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("data_archive:"));
    }

    #[test]
    fn detects_zip_of_ssh() {
        let mut d = det();
        let ev = make_event("zip", &["zip", "-r", "/tmp/keys.zip", ".ssh/"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn ignores_tar_of_application() {
        let mut d = det();
        let ev = make_event("tar", &["tar", "czf", "backup.tgz", "/opt/myapp/"]);
        assert!(
            d.process(&ev).is_none(),
            "tar of application dir should not trigger"
        );
    }

    // ── T1090: Proxy/Tunneling ─────────────────────────────────────────

    #[test]
    fn detects_ssh_dynamic_forward() {
        let mut d = det();
        let ev = make_event("ssh", &["ssh", "-D", "1080", "user@host"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("proxy_tunnel:"));
    }

    #[test]
    fn detects_ssh_local_forward() {
        let mut d = det();
        let ev = make_event("ssh", &["ssh", "-L", "8080:localhost:80", "user@host"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn detects_ssh_remote_forward() {
        let mut d = det();
        let ev = make_event("ssh", &["ssh", "-R", "9090:localhost:80", "user@host"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn detects_chisel() {
        let mut d = det();
        let ev = make_event("chisel", &["chisel", "client", "attacker:8080", "R:socks"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn detects_socat() {
        let mut d = det();
        let ev = make_event("socat", &["socat", "TCP-LISTEN:4444", "EXEC:/bin/sh"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn ignores_normal_ssh() {
        let mut d = det();
        let ev = make_event("ssh", &["ssh", "user@host"]);
        assert!(d.process(&ev).is_none(), "normal ssh should not trigger");
    }

    // ── T1053.002: At Jobs ─────────────────────────────────────────────

    #[test]
    fn detects_at_command() {
        let mut d = det();
        let ev = make_event("at", &["at", "10:00"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("at_job_persist:"));
    }

    #[test]
    fn detects_batch_command() {
        let mut d = det();
        let ev = make_event("batch", &["batch"]);
        assert!(d.process(&ev).is_some());
    }

    // ── T1564.001: Hidden Files ────────────────────────────────────────

    #[test]
    fn detects_mv_to_hidden() {
        let mut d = det();
        let ev = make_event("mv", &["mv", "backdoor", "/tmp/.hidden_tool"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("hidden_artifact:"));
    }

    #[test]
    fn detects_mkdir_hidden_dir() {
        let mut d = det();
        let ev = make_event("mkdir", &["mkdir", "-p", "/var/tmp/.cache_x"]);
        assert!(d.process(&ev).is_some());
    }

    #[test]
    fn ignores_regular_mv() {
        let mut d = det();
        let ev = make_event("mv", &["mv", "old.txt", "new.txt"]);
        assert!(d.process(&ev).is_none());
    }

    // ── T1040: Network Sniffing ────────────────────────────────────────

    #[test]
    fn detects_tcpdump() {
        let mut d = det();
        let ev = make_event("tcpdump", &["tcpdump", "-i", "eth0", "-w", "capture.pcap"]);
        let inc = d.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().incident_id.starts_with("network_sniffing:"));
    }

    #[test]
    fn detects_tshark() {
        let mut d = det();
        let ev = make_event("tshark", &["tshark", "-i", "any"]);
        assert!(d.process(&ev).is_some());
    }

    // ── Cooldown ───────────────────────────────────────────────────────

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut d = det();
        let ev = make_event("tcpdump", &["tcpdump", "-i", "eth0"]);
        assert!(d.process(&ev).is_some(), "first should fire");
        assert!(
            d.process(&ev).is_none(),
            "second within cooldown should be suppressed"
        );
    }

    // ── Event type filtering ───────────────────────────────────────────

    #[test]
    fn ignores_non_exec_events() {
        let mut d = det();
        let ev = Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "connect".to_string(),
            details: serde_json::json!({"pid": 1234}),
            tags: vec![],
            entities: vec![],
        };
        assert!(d.process(&ev).is_none());
    }

    #[test]
    fn processes_sudo_events() {
        let mut d = det();
        let mut ev = make_event("shutdown", &["shutdown", "-h", "now"]);
        ev.kind = "sudo.command".to_string();
        assert!(
            d.process(&ev).is_some(),
            "sudo.command events should be processed"
        );
    }

    // ── Helper tests ───────────────────────────────────────────────────

    #[test]
    fn test_is_hidden_path() {
        assert!(is_hidden_path("/tmp/.hidden"));
        assert!(is_hidden_path("/home/user/.ssh_backdoor"));
        assert!(is_hidden_path(".hidden_file"));
        assert!(!is_hidden_path("/tmp/visible"));
        assert!(!is_hidden_path("/tmp/./normal"));
        assert!(!is_hidden_path("/tmp/../parent"));
        assert!(!is_hidden_path("normal_file"));
    }

    #[test]
    fn test_basename() {
        assert_eq!(basename("/usr/bin/ls"), "ls");
        assert_eq!(basename("/tmp/Backdoor"), "backdoor");
        assert_eq!(basename("simple"), "simple");
    }

    // ── Wrapper resolution ─────────────────────────────────────────────

    #[test]
    fn resolve_wrapper_skips_timeout() {
        let argv: Vec<String> = vec!["timeout", "5", "tcpdump", "-i", "eth0"]
            .into_iter()
            .map(String::from)
            .collect();
        let (path, base) = resolve_wrapper(&argv);
        assert_eq!(base, "tcpdump");
        assert_eq!(path, "tcpdump");
    }

    #[test]
    fn resolve_wrapper_skips_nice() {
        let argv: Vec<String> = vec!["nice", "-n", "10", "/usr/bin/tar", "czf", "/tmp/a.tgz"]
            .into_iter()
            .map(String::from)
            .collect();
        let (_, base) = resolve_wrapper(&argv);
        assert_eq!(base, "tar");
    }

    #[test]
    fn resolve_wrapper_no_wrapper() {
        let argv: Vec<String> = vec!["/usr/bin/chmod", "+s", "/tmp/x"]
            .into_iter()
            .map(String::from)
            .collect();
        let (_, base) = resolve_wrapper(&argv);
        assert_eq!(base, "chmod");
    }

    #[test]
    fn detects_tcpdump_via_timeout() {
        let mut d = det();
        let ev = make_event("timeout", &["timeout", "5", "tcpdump", "-i", "eth0"]);
        let inc = d.process(&ev);
        assert!(inc.is_some(), "tcpdump via timeout should be detected");
        assert!(inc.unwrap().incident_id.starts_with("network_sniffing:"));
    }

    #[test]
    fn detects_ngrok_via_nohup() {
        let mut d = det();
        let ev = make_event("nohup", &["nohup", "ngrok", "http", "8080"]);
        let inc = d.process(&ev);
        assert!(inc.is_some(), "ngrok via nohup should be detected");
        assert!(inc.unwrap().incident_id.starts_with("remote_access_tool:"));
    }
}
