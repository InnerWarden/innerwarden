use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects fileless malware execution via eBPF execve events.
///
/// Fileless execution occurs when a binary runs from memory-backed paths
/// rather than on-disk files. Attackers use memfd_create, /proc/self/fd,
/// or deleted binaries to evade file-based detection.
///
/// Suspicious paths:
///   - /memfd:*         - anonymous memory-backed file (memfd_create)
///   - /dev/fd/*        - file descriptor pseudo-filesystem
///   - /proc/self/fd/*  - process file descriptor symlinks
///   - /proc/<pid>/fd/* - another process's file descriptors
///   - *(deleted)       - binary was deleted after execution started
pub struct FilelessDetector {
    window: Duration,
    /// Suppress re-alerts per pid within window
    alerted: HashMap<u32, DateTime<Utc>>,
    host: String,
}

impl FilelessDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Returns true if the path indicates fileless execution.
    fn is_fileless_path(path: &str) -> bool {
        path.starts_with("/memfd:")
            || path.starts_with("/dev/fd/")
            || path.starts_with("/proc/self/fd/")
            || path.starts_with("/proc/")
                && path.contains("/fd/")
                && path
                    .strip_prefix("/proc/")
                    .and_then(|rest| rest.split('/').next())
                    .map(|seg| seg.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            || path.ends_with("(deleted)")
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" {
            return None;
        }

        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() || !Self::is_fileless_path(command) {
            return None;
        }

        let pid = event.details["pid"].as_u64()? as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let container_id = event.details["container_id"]
            .as_str()
            .map(|s| s.to_string());

        let now = event.ts;

        // Suppress re-alerts for same pid within window
        if let Some(&last) = self.alerted.get(&pid) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(pid, now);

        let severity = Severity::Critical;

        let mut tags = vec![
            "ebpf".to_string(),
            "fileless".to_string(),
            "malware".to_string(),
        ];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        let summary = if let Some(ref cid) = container_id {
            format!(
                "Fileless execution: {comm} (pid={pid}, uid={uid}) running from {command} in container {cid}"
            )
        } else {
            format!("Fileless execution: {comm} (pid={pid}, uid={uid}) running from {command}")
        };

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.window;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "fileless:{comm}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Fileless execution detected: {command}"),
            summary,
            evidence: serde_json::json!([{
                "kind": "fileless_execution",
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "command": command,
                "container_id": container_id,
            }]),
            recommended_checks: vec![
                format!("Investigate process {comm} (pid={pid}) - fileless execution is a strong indicator of malware"),
                format!("Check parent process: ps -o ppid= -p {pid}"),
                format!("Dump process memory: cat /proc/{pid}/maps"),
                "Review network connections from this process: ss -tunp | grep {pid}".to_string(),
                "If unexpected: kill the process immediately and investigate the attack vector".to_string(),
            ],
            tags,
            entities,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fileless_event(
        command: &str,
        comm: &str,
        pid: u32,
        container_id: Option<&str>,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut details = serde_json::json!({
            "pid": pid,
            "uid": 1000,
            "ppid": 1,
            "comm": comm,
            "command": command,
            "argv": [command],
            "argc": 1,
            "cgroup_id": 0,
        });
        if let Some(cid) = container_id {
            details["container_id"] = serde_json::Value::String(cid.to_string());
        }

        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details,
            tags: vec!["ebpf".to_string(), "exec".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_memfd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/memfd:payload",
            "malware",
            1234,
            None,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/memfd:payload"));
        assert!(inc.summary.contains("malware"));
    }

    #[test]
    fn detects_dev_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event("/dev/fd/3", "bash", 5678, None, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/dev/fd/3"));
    }

    #[test]
    fn detects_proc_self_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/proc/self/fd/63",
            "python3",
            9999,
            None,
            now,
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/proc/self/fd/63"));
    }

    #[test]
    fn detects_proc_pid_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event("/proc/1234/fd/5", "sh", 4321, None, now));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/proc/1234/fd/5"));
    }

    #[test]
    fn detects_deleted_binary() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/tmp/dropper (deleted)",
            "dropper",
            7777,
            None,
            now,
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("(deleted)"));
    }

    #[test]
    fn detects_container_fileless() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/memfd:exploit",
            "exploit",
            1234,
            Some("abc123def456"),
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert!(inc.summary.contains("container"));
        assert!(inc.tags.contains(&"container".to_string()));
    }

    #[test]
    fn suppresses_realert() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/memfd:x", "mal", 1234, None, now))
            .is_some());
        assert!(det
            .process(&fileless_event(
                "/memfd:x",
                "mal",
                1234,
                None,
                now + Duration::seconds(5)
            ))
            .is_none());
    }

    #[test]
    fn different_pids_alert_independently() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/memfd:a", "mal", 100, None, now))
            .is_some());
        assert!(det
            .process(&fileless_event("/memfd:b", "mal", 200, None, now))
            .is_some());
    }

    #[test]
    fn ignores_normal_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/usr/bin/curl", "curl", 1234, None, now))
            .is_none());
        assert!(det
            .process(&fileless_event("/bin/bash", "bash", 1234, None, now))
            .is_none());
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "not an exec".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn does_not_match_proc_non_numeric() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        // /proc/cpuinfo contains /proc/ but is not a fileless path
        assert!(det
            .process(&fileless_event("/proc/cpuinfo", "cat", 1234, None, now))
            .is_none());
        // /proc/net/fd/something - "net" is not a pid
        assert!(det
            .process(&fileless_event("/proc/net/fd/1", "cat", 1234, None, now))
            .is_none());
    }
}
