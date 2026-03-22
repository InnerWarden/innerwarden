/// Log tampering detector.
///
/// Watches `file.write_access` and `file.read_access` events from the eBPF
/// openat tracepoint.  When a process that is NOT a known log writer opens a
/// sensitive log file, an incident is raised.
///
/// Sensitive paths:
///   /var/log/auth.log, /var/log/secure, /var/log/syslog, /var/log/kern.log,
///   /var/log/wtmp, /var/log/btmp, /var/log/lastlog
///
/// Known legitimate log writers (allowlisted):
///   rsyslogd, syslog-ng, systemd-journald, logrotate, in.tftpd,
///   journald, rsyslog, auditd, systemd
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Log files that are sensitive — any non-standard write is suspicious.
const SENSITIVE_LOG_PATHS: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
];

/// Processes that are legitimate log writers — never alert on these.
/// The `comm` field from eBPF is truncated to 15 chars (TASK_COMM_LEN),
/// so we list both the full name and the truncated form where relevant.
const KNOWN_LOG_WRITERS: &[&str] = &[
    "rsyslogd",
    "rsyslog",
    "syslog-ng",
    "systemd-journal", // systemd-journald truncated to 15 chars
    "systemd-journald",
    "journald",
    "logrotate",
    "systemd",
    "auditd",
    "agetty",
    "login",
    "sshd",
    "cron",
    "crond",
    "anacron",
    "savelog",
    "last",
    "lastlog",
    "utmpd",
    "wtmp",
];

pub struct LogTamperingDetector {
    host: String,
    /// Per (process, path) cooldown to suppress duplicate alerts.
    alerted: HashMap<(String, String), DateTime<Utc>>,
    cooldown: Duration,
}

impl LogTamperingDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    /// Feed an event into the detector.
    /// Returns `Some(Incident)` when a non-standard process accesses a
    /// sensitive log file via the eBPF openat tracepoint.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process eBPF file-access events
        if event.source != "ebpf" {
            return None;
        }
        if event.kind != "file.write_access" && event.kind != "file.read_access" {
            return None;
        }

        let filename = event.details.get("filename")?.as_str()?;

        // Check if the file is a sensitive log path
        if !SENSITIVE_LOG_PATHS.contains(&filename) {
            return None;
        }

        let comm = event.details.get("comm")?.as_str()?;

        // Skip known legitimate log writers
        if KNOWN_LOG_WRITERS.contains(&comm) {
            return None;
        }

        let is_write = event
            .details
            .get("write")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let now = event.ts;

        // Cooldown check — keyed on (comm, path) to avoid flooding
        let key = (comm.to_string(), filename.to_string());
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
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let access_type = if is_write { "wrote to" } else { "accessed" };

        // Write access to log files is more severe — Critical
        let severity = if is_write {
            Severity::Critical
        } else {
            Severity::High
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "log_tampering:{}:{}:{}",
                comm,
                filename,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Log tampering: {comm} {access_type} {filename}"),
            summary: format!(
                "Non-standard process {comm} (pid={pid}, uid={uid}) {access_type} \
                 sensitive log file {filename} — possible log tampering or evidence destruction"
            ),
            evidence: serde_json::json!([{
                "kind": event.kind,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "filename": filename,
                "write": is_write,
            }]),
            recommended_checks: vec![
                format!("Investigate why {comm} (pid={pid}) {access_type} {filename}"),
                format!("Check if {filename} was truncated or deleted: stat {filename}"),
                "Review recent logins and sudo activity for the user".to_string(),
                "Compare log file size with expected growth rate".to_string(),
                "Check for anti-forensics tools: chkrootkit, rkhunter".to_string(),
            ],
            tags: vec![
                "log_tampering".to_string(),
                "anti_forensics".to_string(),
                "ebpf".to_string(),
            ],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn file_access_event(comm: &str, filename: &str, is_write: bool, ts: DateTime<Utc>) -> Event {
        let flags: u32 = if is_write { 0x1 } else { 0x0 };
        Event {
            ts,
            host: "host".into(),
            source: "ebpf".into(),
            kind: if is_write {
                "file.write_access".into()
            } else {
                "file.read_access".into()
            },
            severity: Sev::Info,
            summary: format!(
                "{comm} (pid=1234) {} {filename}",
                if is_write { "writing" } else { "reading" }
            ),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "flags": flags,
                "write": is_write,
                "cgroup_id": 0,
            }),
            tags: vec!["ebpf".to_string(), "file".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_unknown_process_writing_auth_log() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("vim"));
        assert!(inc.title.contains("/var/log/auth.log"));
        assert!(inc.title.contains("wrote to"));
    }

    #[test]
    fn fires_on_unknown_process_reading_wtmp() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        let inc = det
            .process(&file_access_event("cat", "/var/log/wtmp", false, base))
            .unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("cat"));
        assert!(inc.title.contains("accessed"));
    }

    #[test]
    fn ignores_known_log_writers() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_access_event(
                "rsyslogd",
                "/var/log/auth.log",
                true,
                base
            ))
            .is_none());
        assert!(det
            .process(&file_access_event(
                "systemd-journal",
                "/var/log/syslog",
                true,
                base
            ))
            .is_none());
        assert!(det
            .process(&file_access_event(
                "logrotate",
                "/var/log/kern.log",
                true,
                base
            ))
            .is_none());
    }

    #[test]
    fn ignores_non_sensitive_paths() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_access_event("vim", "/var/log/myapp.log", true, base))
            .is_none());
        assert!(det
            .process(&file_access_event("vim", "/tmp/test.log", true, base))
            .is_none());
    }

    #[test]
    fn ignores_non_ebpf_events() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        let mut ev = file_access_event("vim", "/var/log/auth.log", true, base);
        ev.source = "integrity".into();
        ev.kind = "file.changed".into();
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        // First fires
        assert!(det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .is_some());
        // Within cooldown — suppressed
        assert!(det
            .process(&file_access_event(
                "vim",
                "/var/log/auth.log",
                true,
                base + Duration::seconds(60)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .is_some());
        // After cooldown — fires
        assert!(det
            .process(&file_access_event(
                "vim",
                "/var/log/auth.log",
                true,
                base + Duration::seconds(3601)
            ))
            .is_some());
    }

    #[test]
    fn different_process_same_path_fires() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .is_some());
        // Different process — fires even though same path is in cooldown
        assert!(det
            .process(&file_access_event("nano", "/var/log/auth.log", true, base))
            .is_some());
    }

    #[test]
    fn same_process_different_path_fires() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        assert!(det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .is_some());
        // Same process, different path — fires
        assert!(det
            .process(&file_access_event("vim", "/var/log/syslog", true, base))
            .is_some());
    }

    #[test]
    fn all_sensitive_paths_trigger() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        for path in SENSITIVE_LOG_PATHS {
            let inc = det
                .process(&file_access_event("evil", path, true, base))
                .unwrap();
            assert!(inc.title.contains(path), "Expected title to contain {path}");
        }
    }

    #[test]
    fn write_is_critical_read_is_high() {
        let mut det = LogTamperingDetector::new("host", 3600);
        let base = Utc::now();
        let write_inc = det
            .process(&file_access_event("vim", "/var/log/auth.log", true, base))
            .unwrap();
        assert_eq!(write_inc.severity, Severity::Critical);

        let read_inc = det
            .process(&file_access_event(
                "cat",
                "/var/log/auth.log",
                false,
                base + Duration::seconds(3601),
            ))
            .unwrap();
        assert_eq!(read_inc.severity, Severity::High);
    }
}
