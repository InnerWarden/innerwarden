use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Sensitive internal service ports that indicate lateral movement intent
/// when accessed from a process that wouldn't normally use them.
const SENSITIVE_PORTS: &[u16] = &[
    3306,  // MySQL
    5432,  // PostgreSQL
    6379,  // Redis
    27017, // MongoDB
    2379,  // etcd
    8500,  // Consul
    5000,  // Docker registry
];

/// Detects lateral movement patterns within internal networks.
///
/// Patterns detected:
/// 1. Internal SSH scanning - process connects to port 22 on multiple internal IPs
/// 2. Internal port scanning - process connects to same port on many internal IPs
/// 3. Internal service probing - process connects to sensitive service ports on internal IPs
pub struct LateralMovementDetector {
    window: Duration,
    ssh_threshold: usize,
    scan_threshold: usize,
    /// Per source process key (comm:pid): ring of (timestamp, dst_ip, dst_port)
    history: HashMap<String, VecDeque<(DateTime<Utc>, String, u16)>>,
    /// Cooldown per alert key - suppresses re-alerts for 600s
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

struct IncidentParams<'a> {
    dst_ip: &'a str,
    dst_port: u16,
    comm: &'a str,
    pid: u32,
    ts: DateTime<Utc>,
    pattern: &'a str,
    severity: Severity,
    summary: String,
}

impl LateralMovementDetector {
    pub fn new(
        host: impl Into<String>,
        ssh_threshold: usize,
        scan_threshold: usize,
        window_seconds: u64,
    ) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            ssh_threshold,
            scan_threshold,
            history: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process eBPF outbound connect events
        if event.kind != "network.outbound_connect" && event.kind != "network.connection" {
            return None;
        }
        if event.source != "ebpf_syscall" && event.source != "ebpf" {
            return None;
        }

        let dst_ip = event.details.get("dst_ip")?.as_str()?;
        let dst_port = event.details.get("dst_port")?.as_u64()? as u16;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Only process connections to private/internal IPs
        if !is_private_ip(dst_ip) {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;
        let cooldown = Duration::seconds(600);

        // Record connection in history
        let proc_key = format!("{}:{}", comm, pid);
        let ring = self.history.entry(proc_key.clone()).or_default();
        while ring.front().is_some_and(|(ts, _, _)| *ts < cutoff) {
            ring.pop_front();
        }
        ring.push_back((now, dst_ip.to_string(), dst_port));

        // Compute unique IP counts from ring before calling &mut self methods.
        let ssh_unique_count = if dst_port == 22 {
            let unique_ssh_ips: HashSet<&str> = ring
                .iter()
                .filter(|(_, _, port)| *port == 22)
                .map(|(_, ip, _)| ip.as_str())
                .collect();
            unique_ssh_ips.len()
        } else {
            0
        };

        let scan_unique_count = {
            let unique_ips_on_port: HashSet<&str> = ring
                .iter()
                .filter(|(_, _, port)| *port == dst_port)
                .map(|(_, ip, _)| ip.as_str())
                .collect();
            unique_ips_on_port.len()
        };

        // ── Check 1: Internal SSH scanning ─────────────────────────────────
        if dst_port == 22 && ssh_unique_count >= self.ssh_threshold {
            let alert_key = format!("lateral_ssh:{}:{}", comm, pid);
            if !self.is_in_cooldown(&alert_key, now, cooldown) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(IncidentParams {
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    ts: now,
                    pattern: "ssh_scanning",
                    severity: Severity::High,
                    summary: format!(
                        "Lateral movement: {comm} SSH scanning {ssh_unique_count} internal hosts"
                    ),
                }));
            }
        }

        // ── Check 2: Internal port scanning (same port, many IPs) ──────────
        if scan_unique_count >= self.scan_threshold {
            let alert_key = format!("lateral_scan:{}:{}:{}", comm, pid, dst_port);
            if !self.is_in_cooldown(&alert_key, now, cooldown) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(IncidentParams {
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    ts: now,
                    pattern: "port_scanning",
                    severity: Severity::High,
                    summary: format!(
                        "Lateral movement: {comm} scanning port {dst_port} on {scan_unique_count} internal hosts"
                    ),
                }));
            }
        }

        // ── Check 3: Sensitive internal service probe ──────────────────────
        if SENSITIVE_PORTS.contains(&dst_port) {
            let alert_key = format!("lateral_service:{}:{}:{}", comm, dst_ip, dst_port);
            if !self.is_in_cooldown(&alert_key, now, cooldown) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(IncidentParams {
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    ts: now,
                    pattern: "service_probe",
                    severity: Severity::Medium,
                    summary: format!(
                        "Internal service probe: {comm} connecting to {dst_ip}:{dst_port}"
                    ),
                }));
            }
        }

        // Prune stale data
        if self.history.len() > 5000 {
            self.history.retain(|_, v| {
                v.retain(|(ts, _, _)| *ts > cutoff);
                !v.is_empty()
            });
        }
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    fn is_in_cooldown(&self, key: &str, now: DateTime<Utc>, cooldown: Duration) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < cooldown
        } else {
            false
        }
    }

    fn build_incident(&self, params: IncidentParams<'_>) -> Incident {
        let IncidentParams {
            dst_ip,
            dst_port,
            comm,
            pid,
            ts,
            pattern,
            severity,
            summary,
        } = params;
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "lateral_movement:{}:{}:{}",
                comm,
                dst_ip,
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!(
                "Lateral movement detected: {} to {}:{}",
                comm, dst_ip, dst_port
            ),
            summary,
            evidence: serde_json::json!([{
                "kind": "lateral_movement",
                "pattern": pattern,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "comm": comm,
                "pid": pid,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!(
                    "Investigate process {} (pid={}) - is it compromised or malicious?",
                    comm, pid
                ),
                format!("Check what {comm} is doing on {dst_ip}:{dst_port}"),
                "Review process tree: who spawned this process?".to_string(),
                "Consider isolating the source host and killing the process".to_string(),
            ],
            tags: vec!["lateral-movement".to_string(), "internal".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }
}

/// Returns true if the IP is in a private/internal range (RFC 1918).
/// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        let octets = addr.octets();
        // 10.0.0.0/8
        if octets[0] == 10 {
            return true;
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            source: "ebpf_syscall".to_string(),
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
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    // ── Test 1: SSH to 3+ internal IPs triggers ────────────────────────────
    #[test]
    fn ssh_scanning_three_internal_ips_triggers() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Connect to 3 different internal IPs on port 22
        let r1 = det.process(&connect_event("nmap", 1000, "10.0.0.1", 22, now));
        assert!(r1.is_none());

        let r2 = det.process(&connect_event(
            "nmap",
            1000,
            "10.0.0.2",
            22,
            now + Duration::seconds(1),
        ));
        assert!(r2.is_none());

        let r3 = det.process(&connect_event(
            "nmap",
            1000,
            "10.0.0.3",
            22,
            now + Duration::seconds(2),
        ));
        assert!(r3.is_some());
        let inc = r3.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.summary.contains("SSH scanning"));
        assert!(inc.summary.contains("3 internal hosts"));
        assert!(inc.tags.contains(&"lateral-movement".to_string()));
        assert!(inc.tags.contains(&"internal".to_string()));
    }

    // ── Test 2: SSH to 2 internal IPs doesn't trigger ──────────────────────
    #[test]
    fn ssh_two_internal_ips_no_trigger() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        let r1 = det.process(&connect_event("ssh", 2000, "192.168.1.1", 22, now));
        assert!(r1.is_none());

        let r2 = det.process(&connect_event(
            "ssh",
            2000,
            "192.168.1.2",
            22,
            now + Duration::seconds(1),
        ));
        assert!(r2.is_none());
    }

    // ── Test 3: SSH to external IPs doesn't trigger ────────────────────────
    #[test]
    fn ssh_external_ips_no_trigger() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // External IPs should be filtered out
        let r1 = det.process(&connect_event("ssh", 3000, "8.8.8.8", 22, now));
        assert!(r1.is_none());

        let r2 = det.process(&connect_event(
            "ssh",
            3000,
            "1.1.1.1",
            22,
            now + Duration::seconds(1),
        ));
        assert!(r2.is_none());

        let r3 = det.process(&connect_event(
            "ssh",
            3000,
            "203.0.113.5",
            22,
            now + Duration::seconds(2),
        ));
        assert!(r3.is_none());
    }

    // ── Test 4: Port scan on internal IPs triggers ─────────────────────────
    #[test]
    fn internal_port_scan_triggers() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Connect to 5 different internal IPs on port 8080
        for i in 0..5 {
            let ip = format!("172.16.0.{}", i + 1);
            let result = det.process(&connect_event(
                "curl",
                4000,
                &ip,
                8080,
                now + Duration::seconds(i as i64),
            ));
            if i < 4 {
                assert!(result.is_none(), "should not trigger at {} IPs", i + 1);
            } else {
                assert!(result.is_some(), "should trigger at 5 IPs");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("scanning port 8080"));
                assert!(inc.summary.contains("5 internal hosts"));
            }
        }
    }

    // ── Test 5: Below scan threshold doesn't trigger ───────────────────────
    #[test]
    fn below_scan_threshold_no_trigger() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Connect to 4 different internal IPs on port 443 (below threshold of 5)
        for i in 0..4 {
            let ip = format!("10.1.1.{}", i + 1);
            let result = det.process(&connect_event(
                "wget",
                5000,
                &ip,
                443,
                now + Duration::seconds(i as i64),
            ));
            assert!(
                result.is_none(),
                "should not trigger at {} IPs (threshold=5)",
                i + 1
            );
        }
    }

    // ── Test 6: Sensitive service probe triggers ───────────────────────────
    #[test]
    fn sensitive_service_probe_triggers() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Single connection to MySQL on internal IP
        let result = det.process(&connect_event("python3", 6000, "10.0.0.50", 3306, now));
        assert!(result.is_some());
        let inc = result.unwrap();
        assert_eq!(inc.severity, Severity::Medium);
        assert!(inc.summary.contains("Internal service probe"));
        assert!(inc.summary.contains("10.0.0.50:3306"));

        // Also test Redis
        let result = det.process(&connect_event(
            "nc",
            6001,
            "192.168.1.100",
            6379,
            now + Duration::seconds(1),
        ));
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(inc.summary.contains("192.168.1.100:6379"));

        // Also test PostgreSQL
        let result = det.process(&connect_event(
            "bash",
            6002,
            "172.16.5.10",
            5432,
            now + Duration::seconds(2),
        ));
        assert!(result.is_some());

        // Non-sensitive port should not trigger on single connection
        let result = det.process(&connect_event(
            "curl",
            6003,
            "10.0.0.50",
            80,
            now + Duration::seconds(3),
        ));
        assert!(result.is_none());
    }

    // ── Test 7: Cooldown suppresses re-alert ───────────────────────────────
    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // First service probe triggers
        let r1 = det.process(&connect_event("python3", 7000, "10.0.0.50", 3306, now));
        assert!(r1.is_some());

        // Same alert within 600s cooldown - suppressed
        let r2 = det.process(&connect_event(
            "python3",
            7000,
            "10.0.0.50",
            3306,
            now + Duration::seconds(10),
        ));
        assert!(r2.is_none());

        // After 600s cooldown - triggers again
        let r3 = det.process(&connect_event(
            "python3",
            7000,
            "10.0.0.50",
            3306,
            now + Duration::seconds(601),
        ));
        assert!(r3.is_some());
    }

    // ── Test 8: Different processes tracked independently ──────────────────
    #[test]
    fn different_processes_tracked_independently() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Process A: 2 SSH connections
        det.process(&connect_event("nmap", 8000, "10.0.0.1", 22, now));
        det.process(&connect_event(
            "nmap",
            8000,
            "10.0.0.2",
            22,
            now + Duration::seconds(1),
        ));

        // Process B: 2 SSH connections to different IPs
        det.process(&connect_event(
            "ssh",
            8001,
            "10.0.0.10",
            22,
            now + Duration::seconds(2),
        ));
        det.process(&connect_event(
            "ssh",
            8001,
            "10.0.0.11",
            22,
            now + Duration::seconds(3),
        ));

        // Neither should trigger yet (both at 2, threshold=3)

        // Process A hits threshold with 3rd unique IP
        let r = det.process(&connect_event(
            "nmap",
            8000,
            "10.0.0.3",
            22,
            now + Duration::seconds(4),
        ));
        assert!(r.is_some(), "process A should trigger at 3 unique IPs");
        let inc = r.unwrap();
        assert!(inc.summary.contains("nmap"));

        // Process B still at 2 - shouldn't trigger
        // (but the 3rd IP for B will trigger)
        let r = det.process(&connect_event(
            "ssh",
            8001,
            "10.0.0.12",
            22,
            now + Duration::seconds(5),
        ));
        assert!(r.is_some(), "process B should trigger at 3 unique IPs");
        let inc = r.unwrap();
        assert!(inc.summary.contains("ssh"));
    }

    // ── Test 9: Wrong event source ignored ─────────────────────────────────
    #[test]
    fn wrong_source_ignored() {
        let mut det = LateralMovementDetector::new("test", 3, 5, 300);
        let now = Utc::now();

        // Event from auth_log, not eBPF - should be ignored
        let ev = Event {
            ts: now,
            host: "test".to_string(),
            source: "auth_log".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "test".to_string(),
            details: serde_json::json!({
                "pid": 1234,
                "comm": "ssh",
                "dst_ip": "10.0.0.1",
                "dst_port": 22,
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    // ── Test 10: is_private_ip correctness ─────────────────────────────────
    #[test]
    fn is_private_ip_correctness() {
        // 10.0.0.0/8
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));

        // 172.16.0.0/12
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(!is_private_ip("172.32.0.1")); // outside range

        // 192.168.0.0/16
        assert!(is_private_ip("192.168.0.1"));
        assert!(is_private_ip("192.168.255.255"));

        // Public IPs
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("203.0.113.5"));

        // Edge cases
        assert!(!is_private_ip("not-an-ip"));
        assert!(!is_private_ip("127.0.0.1")); // loopback is not RFC 1918
    }
}
