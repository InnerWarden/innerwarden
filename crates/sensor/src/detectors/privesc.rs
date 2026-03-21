use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects privilege escalation via eBPF commit_creds kprobe.
///
/// When a non-root process becomes root through an unexpected path,
/// this detector fires a Critical incident immediately.
pub struct PrivescDetector {
    window: Duration,
    /// Suppress re-alerts per pid within window
    alerted: HashMap<u32, DateTime<Utc>>,
    host: String,
}

impl PrivescDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "privilege.escalation" {
            return None;
        }

        let pid = event.details["pid"].as_u64()? as u32;
        let old_uid = event.details["old_uid"].as_u64().unwrap_or(0) as u32;
        let new_uid = event.details["new_uid"].as_u64().unwrap_or(0) as u32;
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

        let severity = Severity::Critical; // privesc is always critical

        let mut tags = vec![
            "ebpf".to_string(),
            "kprobe".to_string(),
            "privesc".to_string(),
        ];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        let summary = if let Some(ref cid) = container_id {
            format!(
                "Privilege escalation: {comm} (pid={pid}) gained root (uid {old_uid} → {new_uid}) in container {cid}"
            )
        } else {
            format!(
                "Privilege escalation: {comm} (pid={pid}) gained root (uid {old_uid} → {new_uid})"
            )
        };

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.window;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("privesc:{comm}:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Privilege escalation: {comm} gained root"),
            summary,
            evidence: serde_json::json!([{
                "kind": "privilege_escalation",
                "comm": comm,
                "pid": pid,
                "old_uid": old_uid,
                "new_uid": new_uid,
                "container_id": container_id,
            }]),
            recommended_checks: vec![
                format!("Investigate process {comm} (pid={pid}) — how did it gain root?"),
                format!("Check parent process: ps -o ppid= -p {pid}"),
                "Review /var/log/auth.log for corresponding sudo/su entries".to_string(),
                "If unexpected: kill the process and investigate the attack vector".to_string(),
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

    fn privesc_event(
        comm: &str,
        pid: u32,
        old_uid: u32,
        container_id: Option<&str>,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut details = serde_json::json!({
            "pid": pid,
            "old_uid": old_uid,
            "new_uid": 0,
            "comm": comm,
            "cgroup_id": 0,
        });
        if let Some(cid) = container_id {
            details["container_id"] = serde_json::Value::String(cid.to_string());
        }

        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "privilege.escalation".to_string(),
            severity: Severity::High,
            summary: format!("Privilege escalation: {comm}"),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_privesc() {
        let mut det = PrivescDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&privesc_event("exploit", 1234, 1000, None, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("exploit"));
        assert!(inc.summary.contains("1000"));
    }

    #[test]
    fn detects_container_privesc() {
        let mut det = PrivescDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&privesc_event("exploit", 1234, 33, Some("abc123"), now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("container"));
    }

    #[test]
    fn suppresses_realert() {
        let mut det = PrivescDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&privesc_event("exploit", 1234, 1000, None, now))
            .is_some());
        assert!(det
            .process(&privesc_event(
                "exploit",
                1234,
                1000,
                None,
                now + Duration::seconds(5)
            ))
            .is_none());
    }

    #[test]
    fn different_pids_alert_independently() {
        let mut det = PrivescDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&privesc_event("exploit", 100, 1000, None, now))
            .is_some());
        assert!(det
            .process(&privesc_event("exploit", 200, 1000, None, now))
            .is_some());
    }

    #[test]
    fn ignores_non_privesc_events() {
        let mut det = PrivescDetector::new("test", 300);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: "not privesc".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }
}
