use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Known DDoS tool process names — instant Critical alert on execution.
const DDOS_TOOLS: &[&str] = &[
    "hping3",
    "slowloris",
    "goldeneye",
    "hulk",
    "torshammer",
    "loic",
    "hoic",
    "xerxes",
    "slowhttptest",
];

/// Detects outbound traffic anomalies indicating compromise, botnet participation,
/// or data exfiltration.
///
/// Patterns detected:
/// 1. Connection flood — process opens many outbound connections in short window
/// 2. Port spray — process connects to many ports on the same external IP
/// 3. UDP flood indicator — high-volume UDP connections (common DDoS pattern)
/// 4. Fan-out — process connects to many unique IPs on the same port (botnet)
/// 5. Known DDoS tool execution — instant critical alert
pub struct OutboundAnomalyDetector {
    /// Sliding window for connection flood and UDP flood detection
    flood_window: Duration,
    /// Sliding window for port spray and fan-out detection
    spray_window: Duration,
    /// Cooldown between re-alerts on same key
    cooldown: Duration,
    /// Thresholds
    connection_flood_threshold: usize,
    port_spray_threshold: usize,
    udp_flood_threshold: usize,
    fanout_threshold: usize,
    /// Per-process ring of (timestamp, dst_ip, dst_port, protocol) for flood detection
    conn_history: HashMap<String, VecDeque<ConnRecord>>,
    /// Per-(process, dst_ip) set of ports seen in window — for port spray
    port_spray: HashMap<(String, String), VecDeque<(DateTime<Utc>, u16)>>,
    /// Per-(process, port) set of IPs seen in window — for fan-out
    fanout: HashMap<(String, u16), VecDeque<(DateTime<Utc>, String)>>,
    /// Cooldown per alert key
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ConnRecord {
    ts: DateTime<Utc>,
    dst_ip: String,
    dst_port: u16,
    proto: String,
}

impl OutboundAnomalyDetector {
    pub fn new(
        host: impl Into<String>,
        connection_flood_threshold: usize,
        port_spray_threshold: usize,
        udp_flood_threshold: usize,
        fanout_threshold: usize,
        window_seconds: u64,
        cooldown_seconds: u64,
    ) -> Self {
        Self {
            flood_window: Duration::seconds(30),
            spray_window: Duration::seconds(window_seconds as i64),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            connection_flood_threshold,
            port_spray_threshold,
            udp_flood_threshold,
            fanout_threshold,
            conn_history: HashMap::new(),
            port_spray: HashMap::new(),
            fanout: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // ── Check 5: Known DDoS tool execution ─────────────────────────────
        if event.kind == "shell.command_exec" || event.kind == "process.exec" {
            let comm = event
                .details
                .get("comm")
                .and_then(|v| v.as_str())
                .or_else(|| event.details.get("command").and_then(|v| v.as_str()))
                .unwrap_or("");
            let comm_base = comm.split('/').next_back().unwrap_or(comm);
            if DDOS_TOOLS.contains(&comm_base) {
                let alert_key = format!("ddos_tool:{}", comm_base);
                if !self.is_in_cooldown(&alert_key, event.ts) {
                    self.alerted.insert(alert_key, event.ts);
                    let pid = event
                        .details
                        .get("pid")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    return Some(self.build_incident(
                        "",
                        0,
                        comm_base,
                        pid,
                        event.ts,
                        "ddos_tool",
                        Severity::Critical,
                        format!("DDoS tool detected: {comm_base}"),
                    ));
                }
            }
            return None;
        }

        // Only process network events from here on
        if event.kind != "network.outbound_connect" && event.kind != "network.connection" {
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
        let proto = event
            .details
            .get("proto")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_lowercase();

        // Skip private/internal IPs — only detect anomalies to external destinations
        if super::is_internal_ip(dst_ip) {
            return None;
        }

        let now = event.ts;
        let flood_cutoff = now - self.flood_window;
        let spray_cutoff = now - self.spray_window;

        let proc_key = format!("{}:{}", comm, pid);

        // Record connection in per-process history
        {
            let ring = self.conn_history.entry(proc_key.clone()).or_default();
            while ring.front().is_some_and(|r| r.ts < flood_cutoff) {
                ring.pop_front();
            }
            ring.push_back(ConnRecord {
                ts: now,
                dst_ip: dst_ip.to_string(),
                dst_port,
                proto: proto.clone(),
            });
        }

        // Record in port spray tracker
        {
            let spray_ring = self
                .port_spray
                .entry((proc_key.clone(), dst_ip.to_string()))
                .or_default();
            while spray_ring.front().is_some_and(|(ts, _)| *ts < spray_cutoff) {
                spray_ring.pop_front();
            }
            spray_ring.push_back((now, dst_port));
        }

        // Record in fan-out tracker
        {
            let fanout_ring = self.fanout.entry((proc_key.clone(), dst_port)).or_default();
            while fanout_ring
                .front()
                .is_some_and(|(ts, _)| *ts < spray_cutoff)
            {
                fanout_ring.pop_front();
            }
            fanout_ring.push_back((now, dst_ip.to_string()));
        }

        // Compute all values from rings before any &mut self calls
        let udp_count = if proto == "udp" {
            self.conn_history
                .get(&proc_key)
                .map(|r| r.iter().filter(|c| c.proto == "udp").count())
                .unwrap_or(0)
        } else {
            0
        };

        let conn_count = self
            .conn_history
            .get(&proc_key)
            .map(|r| r.len())
            .unwrap_or(0);

        let unique_port_count = self
            .port_spray
            .get(&(proc_key.clone(), dst_ip.to_string()))
            .map(|r| {
                let s: HashSet<u16> = r.iter().map(|(_, p)| *p).collect();
                s.len()
            })
            .unwrap_or(0);

        let unique_ip_count = self
            .fanout
            .get(&(proc_key.clone(), dst_port))
            .map(|r| {
                let s: HashSet<&str> = r.iter().map(|(_, ip)| ip.as_str()).collect();
                s.len()
            })
            .unwrap_or(0);

        // ── Check 3: UDP flood (highest priority — Critical) ───────────────
        if proto == "udp" && udp_count >= self.udp_flood_threshold {
            let alert_key = format!("udp_flood:{}", proc_key);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    now,
                    "udp_flood",
                    Severity::Critical,
                    format!("UDP flood detected: {comm} sending {udp_count} UDP packets in 30s"),
                ));
            }
        }

        // ── Check 1: Connection flood ──────────────────────────────────────
        if conn_count >= self.connection_flood_threshold {
            let alert_key = format!("conn_flood:{}", proc_key);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    now,
                    "connection_flood",
                    Severity::High,
                    format!("Outbound flood: {comm} opened {conn_count} connections in 30s"),
                ));
            }
        }

        // ── Check 2: Port spray ────────────────────────────────────────────
        if unique_port_count >= self.port_spray_threshold {
            let alert_key = format!("port_spray:{}:{}", proc_key, dst_ip);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    now,
                    "port_spray",
                    Severity::High,
                    format!(
                        "Outbound port spray: {comm} scanning {unique_port_count} ports on {dst_ip}",
                    ),
                ));
            }
        }

        // ── Check 4: Fan-out ───────────────────────────────────────────────
        if unique_ip_count >= self.fanout_threshold {
            let alert_key = format!("fanout:{}:{}", proc_key, dst_port);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    dst_ip,
                    dst_port,
                    comm,
                    pid,
                    now,
                    "fanout",
                    Severity::High,
                    format!(
                        "Outbound fan-out: {comm} connecting to {unique_ip_count} IPs on port {dst_port}",
                    ),
                ));
            }
        }

        // Prune stale data
        if self.conn_history.len() > 5000 {
            self.conn_history.retain(|_, v| {
                v.retain(|r| r.ts > flood_cutoff);
                !v.is_empty()
            });
        }
        if self.port_spray.len() > 5000 {
            self.port_spray.retain(|_, v| {
                v.retain(|(ts, _)| *ts > spray_cutoff);
                !v.is_empty()
            });
        }
        if self.fanout.len() > 5000 {
            self.fanout.retain(|_, v| {
                v.retain(|(ts, _)| *ts > spray_cutoff);
                !v.is_empty()
            });
        }
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| now - *ts < self.cooldown);
        }

        None
    }

    fn is_in_cooldown(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < self.cooldown
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_incident(
        &self,
        dst_ip: &str,
        dst_port: u16,
        comm: &str,
        pid: u32,
        ts: DateTime<Utc>,
        pattern: &str,
        severity: Severity,
        summary: String,
    ) -> Incident {
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "outbound_anomaly:{}:{}:{}",
                pattern,
                comm,
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Outbound traffic anomaly: {comm} ({pattern})"),
            summary,
            evidence: serde_json::json!([{
                "kind": "outbound_anomaly",
                "pattern": pattern,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Investigate process {comm} (pid={pid}) — is it compromised or malicious?"),
                "Check if this host is participating in a DDoS or botnet".to_string(),
                "Review outbound traffic with tcpdump or ss for confirmation".to_string(),
                "Consider killing the process and blocking outbound traffic".to_string(),
            ],
            tags: vec![
                "outbound-anomaly".to_string(),
                "network".to_string(),
                pattern.to_string(),
            ],
            entities: if dst_ip.is_empty() {
                vec![]
            } else {
                vec![EntityRef::ip(dst_ip)]
            },
        }
    }
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
                "proto": "tcp",
            }),
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    fn udp_event(comm: &str, pid: u32, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf_syscall".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} UDP to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": "udp",
            }),
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    fn exec_event(comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf_syscall".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} executed"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "comm": comm,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn new_detector() -> OutboundAnomalyDetector {
        OutboundAnomalyDetector::new("test", 50, 20, 100, 10, 60, 300)
    }

    // ── Test 1: Connection flood triggers ──────────────────────────────────
    #[test]
    fn connection_flood_triggers() {
        // Use high fanout threshold so fan-out doesn't interfere
        let mut det = OutboundAnomalyDetector::new("test", 50, 200, 200, 200, 60, 300);
        let now = Utc::now();

        // Fire 50 connections within 30s window to varied IPs on varied ports
        for i in 0..50 {
            let ip = format!("5.6.{}.{}", i / 256, i % 256 + 1);
            let result = det.process(&connect_event(
                "malware",
                1000,
                &ip,
                80,
                now + Duration::milliseconds(i * 100),
            ));
            if i < 49 {
                assert!(
                    result.is_none(),
                    "should not trigger at {} connections",
                    i + 1
                );
            } else {
                assert!(result.is_some(), "should trigger at 50 connections");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("Outbound flood"));
                assert!(inc.summary.contains("malware"));
                assert!(inc.summary.contains("50 connections in 30s"));
            }
        }
    }

    // ── Test 2: Below flood threshold doesn't trigger ──────────────────────
    #[test]
    fn below_flood_threshold_no_trigger() {
        // Use high fanout threshold so fan-out doesn't interfere
        let mut det = OutboundAnomalyDetector::new("test", 50, 200, 200, 200, 60, 300);
        let now = Utc::now();

        // Fire 49 connections — below threshold of 50
        for i in 0..49 {
            let ip = format!("5.6.{}.{}", i / 256, i % 256 + 1);
            let result = det.process(&connect_event(
                "curl",
                2000,
                &ip,
                443,
                now + Duration::milliseconds(i * 100),
            ));
            assert!(
                result.is_none(),
                "should not trigger at {} connections",
                i + 1
            );
        }
    }

    // ── Test 3: Port spray triggers ────────────────────────────────────────
    #[test]
    fn port_spray_triggers() {
        let mut det = new_detector();
        let now = Utc::now();

        // Connect to 20 different ports on same external IP
        for i in 0..20 {
            let port = 1000 + i as u16;
            let result = det.process(&connect_event(
                "scanner",
                3000,
                "8.8.8.8",
                port,
                now + Duration::seconds(i),
            ));
            if i < 19 {
                assert!(result.is_none(), "should not trigger at {} ports", i + 1);
            } else {
                assert!(result.is_some(), "should trigger at 20 ports");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("Outbound port spray"));
                assert!(inc.summary.contains("scanner"));
                assert!(inc.summary.contains("20 ports"));
                assert!(inc.summary.contains("8.8.8.8"));
            }
        }
    }

    // ── Test 4: Below spray threshold doesn't trigger ──────────────────────
    #[test]
    fn below_spray_threshold_no_trigger() {
        let mut det = new_detector();
        let now = Utc::now();

        // Connect to 19 different ports — below threshold of 20
        for i in 0..19 {
            let port = 2000 + i as u16;
            let result = det.process(&connect_event(
                "nmap",
                4000,
                "1.2.3.4",
                port,
                now + Duration::seconds(i),
            ));
            assert!(result.is_none(), "should not trigger at {} ports", i + 1);
        }
    }

    // ── Test 5: UDP flood triggers ─────────────────────────────────────────
    #[test]
    fn udp_flood_triggers() {
        // High flood/fanout thresholds so only UDP flood fires
        let mut det = OutboundAnomalyDetector::new("test", 200, 200, 100, 200, 60, 300);
        let now = Utc::now();

        // Send 100 UDP packets within 30s
        for i in 0..100 {
            let ip = format!("9.9.{}.{}", i / 256, i % 256 + 1);
            let result = det.process(&udp_event(
                "amplifier",
                5000,
                &ip,
                53,
                now + Duration::milliseconds(i * 100),
            ));
            if i < 99 {
                assert!(
                    result.is_none(),
                    "should not trigger at {} UDP packets",
                    i + 1
                );
            } else {
                assert!(result.is_some(), "should trigger at 100 UDP packets");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::Critical);
                assert!(inc.summary.contains("UDP flood detected"));
                assert!(inc.summary.contains("amplifier"));
                assert!(inc.summary.contains("100 UDP packets in 30s"));
            }
        }
    }

    // ── Test 6: Fan-out triggers ───────────────────────────────────────────
    #[test]
    fn fanout_triggers() {
        let mut det = new_detector();
        let now = Utc::now();

        // Connect to 10 unique external IPs on same port
        for i in 0..10 {
            let ip = format!("44.{}.0.1", i + 1);
            let result = det.process(&connect_event(
                "botclient",
                6000,
                &ip,
                6667,
                now + Duration::seconds(i),
            ));
            if i < 9 {
                assert!(result.is_none(), "should not trigger at {} IPs", i + 1);
            } else {
                assert!(result.is_some(), "should trigger at 10 IPs");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("Outbound fan-out"));
                assert!(inc.summary.contains("botclient"));
                assert!(inc.summary.contains("10 IPs"));
                assert!(inc.summary.contains("port 6667"));
            }
        }
    }

    // ── Test 7: Private IPs excluded ───────────────────────────────────────
    #[test]
    fn private_ips_excluded() {
        let mut det = new_detector();
        let now = Utc::now();

        let private_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"];

        // Even with 200 connections to private IPs, no trigger
        for (i, ip) in private_ips.iter().cycle().take(200).enumerate() {
            let result = det.process(&connect_event(
                "scanner",
                7000,
                ip,
                80,
                now + Duration::milliseconds(i as i64 * 10),
            ));
            assert!(result.is_none(), "private IP {} should be excluded", ip);
        }
    }

    // ── Test 8: Known DDoS tool triggers (critical) ────────────────────────
    #[test]
    fn ddos_tool_triggers_critical() {
        let mut det = new_detector();
        let now = Utc::now();

        for (i, tool) in DDOS_TOOLS.iter().enumerate() {
            let mut det2 = new_detector();
            let result = det2.process(&exec_event(tool, 8000 + i as u32, now));
            assert!(result.is_some(), "DDoS tool {} should trigger", tool);
            let inc = result.unwrap();
            assert_eq!(inc.severity, Severity::Critical);
            assert!(inc.summary.contains("DDoS tool detected"));
            assert!(inc.summary.contains(tool));
        }

        // Verify the first one triggers from shared detector too
        let result = det.process(&exec_event("hping3", 9000, now));
        assert!(result.is_some());
    }

    // ── Test 9: Normal process doesn't trigger ─────────────────────────────
    #[test]
    fn normal_process_no_trigger() {
        let mut det = new_detector();
        let now = Utc::now();

        // Normal traffic: a few connections to various IPs
        for i in 0..5 {
            let ip = format!("93.184.{}.{}", i, i + 1);
            let result = det.process(&connect_event(
                "nginx",
                10000,
                &ip,
                443,
                now + Duration::seconds(i * 10),
            ));
            assert!(result.is_none());
        }

        // Normal process exec should not trigger
        let result = det.process(&exec_event("nginx", 10000, now));
        assert!(result.is_none());

        let result = det.process(&exec_event("sshd", 10001, now));
        assert!(result.is_none());
    }

    // ── Test 10: Cooldown suppresses re-alert ──────────────────────────────
    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = new_detector();
        let now = Utc::now();

        // Trigger a DDoS tool alert
        let r1 = det.process(&exec_event("hping3", 11000, now));
        assert!(r1.is_some());

        // Same tool within cooldown (300s) — suppressed
        let r2 = det.process(&exec_event("hping3", 11001, now + Duration::seconds(10)));
        assert!(r2.is_none());

        // After cooldown — triggers again
        let r3 = det.process(&exec_event("hping3", 11002, now + Duration::seconds(301)));
        assert!(r3.is_some());
    }

    // ── Test 11: Different processes tracked independently ─────────────────
    #[test]
    fn different_processes_tracked_independently() {
        let mut det = OutboundAnomalyDetector::new("test", 5, 20, 100, 10, 60, 300);
        let now = Utc::now();

        // Process A: 4 connections (below threshold=5)
        for i in 0..4 {
            let ip = format!("8.8.{}.{}", i, i + 1);
            let result = det.process(&connect_event(
                "proc_a",
                12000,
                &ip,
                80,
                now + Duration::milliseconds(i * 100),
            ));
            assert!(result.is_none());
        }

        // Process B: 4 connections (below threshold=5)
        for i in 0..4 {
            let ip = format!("9.9.{}.{}", i, i + 1);
            let result = det.process(&connect_event(
                "proc_b",
                12001,
                &ip,
                80,
                now + Duration::milliseconds(i * 100),
            ));
            assert!(result.is_none());
        }

        // Process A gets 5th connection — triggers
        let r = det.process(&connect_event(
            "proc_a",
            12000,
            "8.8.5.6",
            80,
            now + Duration::milliseconds(500),
        ));
        assert!(r.is_some(), "process A should trigger at 5 connections");
        let inc = r.unwrap();
        assert!(inc.summary.contains("proc_a"));

        // Process B still at 4 — shouldn't trigger yet
        // (one more will trigger it)
        let r = det.process(&connect_event(
            "proc_b",
            12001,
            "9.9.5.6",
            80,
            now + Duration::milliseconds(600),
        ));
        assert!(r.is_some(), "process B should trigger at 5 connections");
        let inc = r.unwrap();
        assert!(inc.summary.contains("proc_b"));
    }

    // ── Test 12: UDP and TCP mixed — only UDP counted for UDP flood ────────
    #[test]
    fn udp_tcp_mixed_only_udp_counted() {
        let mut det = OutboundAnomalyDetector::new("test", 200, 20, 5, 10, 60, 300);
        let now = Utc::now();

        // 3 UDP + 3 TCP = 6 total, but only 3 UDP (below udp threshold of 5)
        for i in 0..3 {
            let ip = format!("7.7.7.{}", i + 1);
            det.process(&udp_event(
                "mixed",
                13000,
                &ip,
                53,
                now + Duration::seconds(i),
            ));
        }
        for i in 0..3 {
            let ip = format!("7.7.8.{}", i + 1);
            let result = det.process(&connect_event(
                "mixed",
                13000,
                &ip,
                80,
                now + Duration::seconds(i + 3),
            ));
            assert!(result.is_none());
        }

        // 2 more UDP brings total to 5 — should trigger UDP flood
        det.process(&udp_event(
            "mixed",
            13000,
            "7.7.9.1",
            53,
            now + Duration::seconds(6),
        ));
        let result = det.process(&udp_event(
            "mixed",
            13000,
            "7.7.9.2",
            53,
            now + Duration::seconds(7),
        ));
        assert!(result.is_some());
        let inc = result.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("UDP flood"));
    }

    // ── Test 13: Events outside window are pruned ──────────────────────────
    #[test]
    fn events_outside_window_pruned() {
        let mut det = OutboundAnomalyDetector::new("test", 5, 20, 100, 10, 60, 300);
        let now = Utc::now();

        // 4 connections long ago (outside the 30s flood window)
        for i in 0..4 {
            let ip = format!("3.3.3.{}", i + 1);
            det.process(&connect_event(
                "old_proc",
                14000,
                &ip,
                80,
                now - Duration::seconds(60) + Duration::seconds(i),
            ));
        }

        // 1 connection now — total in window = 1 (old ones pruned), should not trigger
        let result = det.process(&connect_event("old_proc", 14000, "3.3.3.5", 80, now));
        assert!(result.is_none());
    }
}
