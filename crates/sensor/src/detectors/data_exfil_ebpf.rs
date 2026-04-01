//! eBPF-based data exfiltration detector.
//!
//! Correlates sensitive file reads (`file.read_access` on /etc/shadow,
//! /etc/passwd, .ssh/*, etc.) with subsequent outbound network connections
//! (`network.outbound_connect`) from the same PID within a short window.
//!
//! This catches the pattern: read sensitive data → send it out, which is
//! invisible to single-event detectors.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Sensitive file paths that trigger tracking.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/.ssh/",
    "/authorized_keys",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/.env",
    "/credentials",
    "/secret",
    "/.kube/config",
    "/token",
];

/// Per-PID tracking of sensitive file access.
struct SensitiveRead {
    ts: DateTime<Utc>,
    filename: String,
    comm: String,
}

/// Detects data exfiltration by correlating sensitive file reads with
/// outbound network connections from the same process.
pub struct DataExfilEbpfDetector {
    host: String,
    /// Window in which a connect after a sensitive read is suspicious.
    window: Duration,
    /// Recent sensitive file reads by PID.
    pending_reads: HashMap<u32, SensitiveRead>,
    /// Cooldown: suppress re-alerts per PID.
    alerted: HashMap<u32, DateTime<Utc>>,
    cooldown: Duration,
}

impl DataExfilEbpfDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            window: Duration::seconds(window_seconds as i64),
            pending_reads: HashMap::new(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let now = event.ts;

        // Skip InnerWarden's own processes — the sensor legitimately reads
        // /etc/ssh/sshd_config and makes outbound API calls (AbuseIPDB, GeoIP).
        let ev_uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let ev_comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if super::allowlists::is_innerwarden_process(ev_uid, ev_comm) {
            return None;
        }

        // Phase 1: Track sensitive file reads
        if event.kind == "file.read_access" || event.kind == "file.write_access" {
            let filename = event
                .details
                .get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_sensitive_path(filename) {
                let comm = event
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                self.pending_reads.insert(
                    pid,
                    SensitiveRead {
                        ts: now,
                        filename: filename.to_string(),
                        comm,
                    },
                );
            }
            return None;
        }

        // Phase 2: Check if outbound connect follows a sensitive read
        if event.kind == "network.outbound_connect" {
            // Expire old reads
            let cutoff = now - self.window;
            self.pending_reads.retain(|_, r| r.ts > cutoff);

            if let Some(read) = self.pending_reads.remove(&pid) {
                // Same PID read a sensitive file then made outbound connection
                let dst_ip = event
                    .details
                    .get("dst_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let dst_port = event
                    .details
                    .get("dst_port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;
                let comm = event
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&read.comm);

                // Skip internal IPs
                if super::is_internal_ip(dst_ip) {
                    return None;
                }

                // Cooldown check
                if let Some(&last) = self.alerted.get(&pid) {
                    if now - last < self.cooldown {
                        return None;
                    }
                }
                self.alerted.insert(pid, now);

                let elapsed = (now - read.ts).num_seconds();

                return Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!("data_exfil_ebpf:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
                    severity: Severity::Critical,
                    title: format!(
                        "Data exfiltration: {comm} read {} then connected to {dst_ip}:{dst_port}",
                        read.filename
                    ),
                    summary: format!(
                        "Process {comm} (pid={pid}) read sensitive file {} then made outbound \
                         connection to {dst_ip}:{dst_port} within {elapsed}s. This pattern \
                         indicates data exfiltration — the file content may have been sent \
                         to the remote host.",
                        read.filename
                    ),
                    evidence: serde_json::json!([{
                        "kind": "data_exfil_ebpf",
                        "detection": "read_then_connect",
                        "comm": comm,
                        "pid": pid,
                        "sensitive_file": read.filename,
                        "file_read_ts": read.ts.to_rfc3339(),
                        "connect_ts": now.to_rfc3339(),
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "elapsed_seconds": elapsed,
                    }]),
                    recommended_checks: vec![
                        format!("Kill process: kill -9 {pid}"),
                        format!("Block destination: {dst_ip}"),
                        format!(
                            "Check if {} was exfiltrated — rotate credentials if so",
                            read.filename
                        ),
                        "Review process tree for attack origin".to_string(),
                    ],
                    tags: vec![
                        "data_exfiltration".to_string(),
                        "ebpf".to_string(),
                        "sensitive_file".to_string(),
                    ],
                    entities: vec![EntityRef::ip(dst_ip), EntityRef::path(&read.filename)],
                });
            }
        }

        // Prune stale data
        if self.pending_reads.len() > 5000 {
            let cutoff = now - self.window;
            self.pending_reads.retain(|_, r| r.ts > cutoff);
        }
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    SENSITIVE_PATHS
        .iter()
        .any(|sensitive| lower.contains(sensitive))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn read_event(pid: u32, filename: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Medium,
            summary: format!("read {filename}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "cat",
                "filename": filename,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![],
        }
    }

    fn connect_event(pid: u32, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: format!("connect {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "cat",
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn skips_innerwarden_process() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // InnerWarden uid=998 reading sensitive files is legitimate
        let iw_read = Event {
            ts: now,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Medium,
            summary: "read /etc/ssh/sshd_config".into(),
            details: serde_json::json!({
                "pid": 9999, "uid": 998, "comm": "tokio-rt-worker",
                "filename": "/etc/ssh/sshd_config",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&iw_read).is_none());

        // Even if followed by outbound connect, should not trigger
        let iw_connect = Event {
            ts: now + Duration::seconds(2),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: "connect 5.6.7.8:443".into(),
            details: serde_json::json!({
                "pid": 9999, "uid": 998, "comm": "tokio-rt-worker",
                "dst_ip": "5.6.7.8", "dst_port": 443,
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&iw_connect).is_none());
    }

    #[test]
    fn detects_read_then_connect() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // Step 1: read /etc/shadow
        assert!(det.process(&read_event(1234, "/etc/shadow", now)).is_none());

        // Step 2: connect to external IP
        let inc = det
            .process(&connect_event(
                1234,
                "5.6.7.8",
                443,
                now + Duration::seconds(5),
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/etc/shadow"));
        assert!(inc.title.contains("5.6.7.8"));
    }

    #[test]
    fn requires_same_pid() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // PID 1234 reads file
        det.process(&read_event(1234, "/etc/shadow", now));

        // Different PID 5678 connects → should NOT trigger
        let inc = det.process(&connect_event(
            5678,
            "5.6.7.8",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_non_sensitive_files() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // Read a normal file
        det.process(&read_event(1234, "/var/log/syslog", now));

        // Connect → should NOT trigger (file was not sensitive)
        let inc = det.process(&connect_event(
            1234,
            "5.6.7.8",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_internal_destinations() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/etc/shadow", now));

        // Connect to internal IP → should NOT trigger
        let inc = det.process(&connect_event(
            1234,
            "192.168.1.1",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn expires_after_window() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/etc/shadow", now));

        // Connect 61 seconds later → window expired
        let inc = det.process(&connect_event(
            1234,
            "5.6.7.8",
            443,
            now + Duration::seconds(61),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn detects_ssh_key_exfil() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/home/admin/.ssh/id_rsa", now));

        let inc = det
            .process(&connect_event(
                1234,
                "8.8.8.8",
                80,
                now + Duration::seconds(2),
            ))
            .unwrap();
        assert!(inc.title.contains("id_rsa"));
    }

    #[test]
    fn sensitive_path_detection() {
        assert!(is_sensitive_path("/etc/shadow"));
        assert!(is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
        assert!(is_sensitive_path("/home/user/.ssh/authorized_keys"));
        assert!(is_sensitive_path("/app/.env"));
        assert!(is_sensitive_path("/home/user/.kube/config"));
        assert!(!is_sensitive_path("/var/log/syslog"));
        assert!(!is_sensitive_path("/usr/bin/ls"));
    }
}
