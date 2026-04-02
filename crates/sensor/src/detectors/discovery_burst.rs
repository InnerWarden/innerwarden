//! Discovery burst detector.
//!
//! Alerts when a single user/PID runs many reconnaissance commands in a
//! short window. Individual discovery commands (ps, id, whoami, ss, ip addr)
//! are normal. But 5+ in 60 seconds from the same source = active recon.
//!
//! Catches MITRE ATT&CK:
//!   T1087 (Account Discovery), T1082 (System Info), T1016 (Network Config),
//!   T1049 (Network Connections), T1057 (Process Discovery), T1083 (File Discovery)

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Commands that count as discovery activity.
const DISCOVERY_COMMANDS: &[&str] = &[
    "ps aux",
    "ps -ef",
    "ps -",
    "/bin/ps",
    "/usr/bin/ps",
    "id",
    "/usr/bin/id",
    "whoami",
    "/usr/bin/whoami",
    "uname",
    "/usr/bin/uname",
    "hostname",
    "/usr/bin/hostname",
    "ip addr",
    "ip route",
    "ip neigh",
    "ip link",
    "ifconfig",
    "ss -",
    "ss\n",
    "/usr/bin/ss",
    "netstat",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "cat /etc/group",
    "cat /etc/resolv",
    "cat /etc/hostname",
    "cat /etc/os-release",
    "cat /proc/net",
    "cat /proc/cpuinfo",
    "cat /proc/meminfo",
    "cat /proc/version",
    "getent passwd",
    "getent group",
    "find /etc",
    "find /home",
    "find /var",
    "find /opt",
    "find /root",
    "ls /root",
    "ls /home",
    "ls -la /root",
    "ls -la /home",
    "df -",
    "free -",
    "lscpu",
    "lsmod",
    "mount",
    "arp -",
    "cat /proc/1/cgroup",
    "groups",
    "last ",
    "w\n",
    "who\n",
];

/// Use centralized allowlist from allowlists.rs
use super::allowlists;

pub struct DiscoveryBurstDetector {
    /// Per-user sliding window of discovery command timestamps.
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Threshold: how many discovery commands in window to alert.
    threshold: usize,
    /// Window duration.
    window: Duration,
    /// Cooldown per user.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
    host: String,
}

impl DiscoveryBurstDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            windows: HashMap::new(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(1800), // 30 min — one alert per burst is enough
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" {
            return None;
        }

        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Skip allowed processes (centralized allowlist)
        if allowlists::is_innerwarden_process(uid, comm)
            || allowlists::comm_in_allowlist(comm, allowlists::DISCOVERY_ALLOWED)
        {
            return None;
        }

        // Check if command is a discovery command
        let lower = command.to_lowercase();
        let is_discovery = DISCOVERY_COMMANDS.iter().any(|d| lower.contains(d));
        if !is_discovery {
            return None;
        }

        // Skip discovery commands embedded in larger scripts (bash -lc "cd ... && ip neigh").
        // Real recon runs commands standalone; scripts chain them with && or ;
        if (comm == "sh" || comm == "bash") && lower.contains("&&") {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        // Track per user (uid)
        let key = format!("uid:{}", uid);
        {
            let entries = self.windows.entry(key.clone()).or_default();
            while entries.front().is_some_and(|ts| *ts < cutoff) {
                entries.pop_front();
            }
            entries.push_back(now);
        }

        let count = self.windows.get(&key).map(|e| e.len()).unwrap_or(0);
        // Root (uid=0) legitimately runs many commands during deploys,
        // package installs, and system administration. Use 3x threshold.
        let effective_threshold = if uid == 0 {
            self.threshold * 3
        } else {
            self.threshold
        };
        if count < effective_threshold {
            return None;
        }

        // Cooldown
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key.clone(), now);

        // Prune
        if self.alerted.len() > 500 {
            let cd_cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cd_cutoff);
        }
        if self.windows.len() > 500 {
            let wc = now - self.window;
            self.windows
                .retain(|_, w| w.back().is_some_and(|t| *t > wc));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "discovery_burst:uid{}:{}",
                uid,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: if count > self.threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            },
            title: format!(
                "Discovery burst: {} recon commands from uid {} in {}s",
                count,
                uid,
                self.window.num_seconds()
            ),
            summary: format!(
                "User uid={} ran {} discovery commands in {} seconds (threshold: {}). \
                 Last command: {} (pid={}, comm={})",
                uid,
                count,
                self.window.num_seconds(),
                self.threshold,
                command,
                pid,
                comm
            ),
            evidence: serde_json::json!([{
                "kind": "discovery_burst",
                "uid": uid,
                "count": count,
                "window_seconds": self.window.num_seconds(),
                "last_command": command,
                "pid": pid,
                "comm": comm,
            }]),
            recommended_checks: vec![
                format!("Review commands run by uid {}: ausearch -ua {}", uid, uid),
                "Check if this is a legitimate admin session or automated recon".to_string(),
                "Correlate with SSH login source IP for this session".to_string(),
            ],
            tags: vec!["discovery".to_string(), "reconnaissance".to_string()],
            entities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(command: &str, uid: u64) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command: {}", command),
            details: serde_json::json!({
                "command": command,
                "comm": "bash",
                "uid": uid,
                "pid": 1234,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn no_alert_under_threshold() {
        let mut det = DiscoveryBurstDetector::new("test", 5, 60);
        assert!(det.process(&make_event("ps aux", 1000)).is_none());
        assert!(det.process(&make_event("id", 1000)).is_none());
        assert!(det.process(&make_event("whoami", 1000)).is_none());
    }

    #[test]
    fn alert_at_threshold() {
        let mut det = DiscoveryBurstDetector::new("test", 5, 60);
        det.process(&make_event("ps aux", 1000));
        det.process(&make_event("id", 1000));
        det.process(&make_event("whoami", 1000));
        det.process(&make_event("uname -a", 1000));
        let result = det.process(&make_event("cat /etc/passwd", 1000));
        assert!(result.is_some());
    }

    #[test]
    fn different_users_tracked_separately() {
        let mut det = DiscoveryBurstDetector::new("test", 5, 60);
        det.process(&make_event("ps aux", 1000));
        det.process(&make_event("id", 1000));
        det.process(&make_event("whoami", 1001)); // different user
        det.process(&make_event("uname -a", 1000));
        let result = det.process(&make_event("hostname", 1000));
        assert!(result.is_none()); // only 4 from uid 1000
    }

    #[test]
    fn ignores_non_discovery() {
        let mut det = DiscoveryBurstDetector::new("test", 3, 60);
        det.process(&make_event("vim file.txt", 1000));
        det.process(&make_event("gcc -o main main.c", 1000));
        let result = det.process(&make_event("npm install", 1000));
        assert!(result.is_none());
    }

    #[test]
    fn ignores_allowed_processes() {
        let mut det = DiscoveryBurstDetector::new("test", 3, 60);
        let mut ev = make_event("ps aux", 1000);
        ev.details = serde_json::json!({"command": "ps aux", "comm": "innerwarden-sensor", "uid": 1000, "pid": 1});
        for _ in 0..5 {
            assert!(det.process(&ev).is_none());
        }
    }
}
