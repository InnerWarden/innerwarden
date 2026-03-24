use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Event kinds that this detector processes.
const SYN_FLOOD_KINDS: &[&str] = &[
    "ssh.login_failed",
    "network.connection_blocked",
    "network.connection_reset",
];

const HTTP_FLOOD_KINDS: &[&str] = &[
    "http.scan",
    "http.request",
    "http.search_abuse",
    "nginx.access",
    "web_scan",
    "search_abuse",
];

const UDP_KINDS: &[&str] = &[
    "network.udp_amplification",
    "suricata.dns.query",
    "network.connection",
];

/// Detects volumetric and multi-vector DDoS attacks by analyzing packet/event
/// patterns at the sensor level, inspired by the iKern paper (MDPI 2024).
///
/// Patterns detected:
/// 1. SYN flood     - rapid failed connections from many IPs
/// 2. UDP amplification - many UDP-related events to single destination
/// 3. HTTP flood (L7) - massive HTTP request volume from many IPs
/// 4. Slowloris     - many stale connections from same IP
/// 5. Multi-vector  - 2+ patterns trigger simultaneously
/// 6. Connection rate anomaly - current rate >> historical baseline
pub struct PacketFloodDetector {
    host: String,

    // Thresholds
    syn_threshold: usize,
    http_threshold: usize,
    slowloris_threshold: usize,
    udp_threshold: usize,
    rate_multiplier: f64,
    window: Duration,
    udp_window: Duration,
    cooldown: Duration,

    // SYN flood state: sliding window of (timestamp, source_ip)
    syn_events: VecDeque<(DateTime<Utc>, String)>,
    // UDP amplification state: per destination IP, sliding window of (timestamp, source_ip)
    udp_events: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    // HTTP flood state: sliding window of (timestamp, source_ip)
    http_events: VecDeque<(DateTime<Utc>, String)>,
    // Slowloris state: per source IP, set of connection IDs/timestamps that are "open"
    slowloris_conns: HashMap<String, VecDeque<DateTime<Utc>>>,

    // Connection rate baseline (Welford's online algorithm)
    rate_count: u64,
    rate_mean: f64,
    rate_m2: f64,
    /// Connections in the current minute bucket
    current_minute_conns: u64,
    /// Start of the current minute bucket
    current_minute_start: Option<DateTime<Utc>>,

    // Track which patterns fired in the current window for multi-vector detection
    active_patterns: HashMap<String, DateTime<Utc>>,

    // Cooldown per alert key
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Parameters for constructing a PacketFloodDetector.
pub struct PacketFloodParams {
    pub host: String,
    pub syn_threshold: usize,
    pub http_threshold: usize,
    pub slowloris_threshold: usize,
    pub udp_threshold: usize,
    pub rate_multiplier: f64,
    pub window_seconds: u64,
    pub cooldown_seconds: u64,
}

impl PacketFloodDetector {
    pub fn new(params: PacketFloodParams) -> Self {
        Self {
            host: params.host,
            syn_threshold: params.syn_threshold,
            http_threshold: params.http_threshold,
            slowloris_threshold: params.slowloris_threshold,
            udp_threshold: params.udp_threshold,
            rate_multiplier: params.rate_multiplier,
            window: Duration::seconds(params.window_seconds as i64),
            udp_window: Duration::seconds(10),
            cooldown: Duration::seconds(params.cooldown_seconds as i64),
            syn_events: VecDeque::new(),
            udp_events: HashMap::new(),
            http_events: VecDeque::new(),
            slowloris_conns: HashMap::new(),
            rate_count: 0,
            rate_mean: 0.0,
            rate_m2: 0.0,
            current_minute_conns: 0,
            current_minute_start: None,
            active_patterns: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    /// Process an event and return zero or more incidents.
    ///
    /// May return multiple incidents when individual patterns fire AND a
    /// multi-vector detection is triggered simultaneously.
    pub fn process(&mut self, event: &Event) -> Vec<Incident> {
        let now = event.ts;
        let mut incidents = Vec::new();

        // Update connection rate baseline for any network-related event
        if is_network_event(event) {
            self.update_rate(now);
        }

        // --- SYN flood detection ---
        if SYN_FLOOD_KINDS.contains(&event.kind.as_str()) {
            if let Some(src_ip) = extract_source_ip(event) {
                let cutoff = now - self.window;
                self.syn_events.push_back((now, src_ip.clone()));
                while self.syn_events.front().is_some_and(|(ts, _)| *ts < cutoff) {
                    self.syn_events.pop_front();
                }

                let count = self.syn_events.len();
                let unique_ips: HashSet<&str> =
                    self.syn_events.iter().map(|(_, ip)| ip.as_str()).collect();
                let unique_count = unique_ips.len();

                if count >= self.syn_threshold && unique_count >= 3 {
                    let alert_key = "packet_flood:syn".to_string();
                    if !self.is_in_cooldown(&alert_key, now) {
                        self.alerted.insert(alert_key, now);
                        self.active_patterns.insert("SYN flood".to_string(), now);
                        incidents.push(self.build_incident(
                            &src_ip,
                            now,
                            "syn_flood",
                            Severity::Critical,
                            format!(
                                "SYN flood: {} connections from {} IPs in {}s",
                                count,
                                unique_count,
                                self.window.num_seconds()
                            ),
                        ));
                    }
                }
            }
        }

        // --- UDP amplification detection ---
        if is_udp_event(event) {
            if let Some(dst_ip) = extract_dest_ip(event) {
                let src_ip = extract_source_ip(event).unwrap_or_default();
                let cutoff = now - self.udp_window;
                let ring = self.udp_events.entry(dst_ip.clone()).or_default();
                ring.push_back((now, src_ip));
                while ring.front().is_some_and(|(ts, _)| *ts < cutoff) {
                    ring.pop_front();
                }

                let count = ring.len();
                let unique_sources: HashSet<&str> =
                    ring.iter().map(|(_, ip)| ip.as_str()).collect();

                if count >= self.udp_threshold && unique_sources.len() >= 2 {
                    let alert_key = format!("packet_flood:udp:{}", dst_ip);
                    if !self.is_in_cooldown(&alert_key, now) {
                        self.alerted.insert(alert_key, now);
                        self.active_patterns
                            .insert("UDP amplification".to_string(), now);
                        incidents.push(self.build_incident(
                            &dst_ip,
                            now,
                            "udp_amplification",
                            Severity::Critical,
                            format!("UDP amplification attack: {} packets in 10s", count),
                        ));
                    }
                }
            }
        }

        // --- HTTP flood (L7) detection ---
        if HTTP_FLOOD_KINDS.contains(&event.kind.as_str()) {
            if let Some(src_ip) = extract_source_ip(event) {
                let cutoff = now - self.window;
                self.http_events.push_back((now, src_ip.clone()));
                while self.http_events.front().is_some_and(|(ts, _)| *ts < cutoff) {
                    self.http_events.pop_front();
                }

                let count = self.http_events.len();
                let unique_ips: HashSet<&str> =
                    self.http_events.iter().map(|(_, ip)| ip.as_str()).collect();
                let unique_count = unique_ips.len();

                if count >= self.http_threshold && unique_count >= 3 {
                    let alert_key = "packet_flood:http".to_string();
                    if !self.is_in_cooldown(&alert_key, now) {
                        self.alerted.insert(alert_key, now);
                        self.active_patterns.insert("HTTP flood".to_string(), now);
                        incidents.push(self.build_incident(
                            &src_ip,
                            now,
                            "http_flood",
                            Severity::High,
                            format!(
                                "HTTP flood: {} requests from {} IPs in {}s",
                                count,
                                unique_count,
                                self.window.num_seconds()
                            ),
                        ));
                    }
                }
            }
        }

        // --- Slowloris detection ---
        if event.kind == "network.connection" || event.kind == "network.connection_open" {
            if let Some(src_ip) = extract_source_ip(event) {
                let conns = self.slowloris_conns.entry(src_ip.clone()).or_default();
                conns.push_back(now);

                // Expire connections older than 2x window (stale = older than window)
                let expire_cutoff = now - self.window * 2;
                while conns.front().is_some_and(|ts| *ts < expire_cutoff) {
                    conns.pop_front();
                }

                // Count connections that have been open for > window seconds
                let stale_cutoff = now - self.window;
                let stale_count = conns.iter().filter(|ts| **ts < stale_cutoff).count();

                if stale_count >= self.slowloris_threshold {
                    let alert_key = format!("packet_flood:slowloris:{}", src_ip);
                    if !self.is_in_cooldown(&alert_key, now) {
                        self.alerted.insert(alert_key, now);
                        self.active_patterns.insert("Slowloris".to_string(), now);
                        incidents.push(self.build_incident(
                            &src_ip,
                            now,
                            "slowloris",
                            Severity::High,
                            format!(
                                "Slowloris attack: {} stale connections from {}",
                                stale_count, src_ip
                            ),
                        ));
                    }
                }
            }
        }

        // --- Connection rate anomaly ---
        if is_network_event(event) {
            if let Some(rate_incident) = self.check_rate_anomaly(event, now) {
                incidents.push(rate_incident);
            }
        }

        // --- Multi-vector detection ---
        // Clean expired patterns (only keep those within 2x window)
        let multi_cutoff = now - self.window * 2;
        self.active_patterns.retain(|_, ts| *ts > multi_cutoff);

        if self.active_patterns.len() >= 2 {
            let alert_key = "packet_flood:multi_vector".to_string();
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                let patterns: Vec<String> = self.active_patterns.keys().cloned().collect();
                let pattern_str = patterns.join(", ");
                incidents.push(self.build_incident(
                    "",
                    now,
                    "multi_vector",
                    Severity::Critical,
                    format!(
                        "Multi-vector DDoS: {} attack vectors detected ({})",
                        self.active_patterns.len(),
                        pattern_str
                    ),
                ));
            }
        }

        // Prune stale state
        self.prune(now);

        incidents
    }

    fn update_rate(&mut self, now: DateTime<Utc>) {
        let minute_start = match self.current_minute_start {
            Some(start) => start,
            None => {
                self.current_minute_start = Some(now);
                self.current_minute_conns = 1;
                return;
            }
        };

        if now - minute_start < Duration::minutes(1) {
            self.current_minute_conns += 1;
        } else {
            // Bucket completed: update running stats with Welford's algorithm
            let value = self.current_minute_conns as f64;
            self.rate_count += 1;
            let delta = value - self.rate_mean;
            self.rate_mean += delta / self.rate_count as f64;
            let delta2 = value - self.rate_mean;
            self.rate_m2 += delta * delta2;

            // Start new bucket
            self.current_minute_start = Some(now);
            self.current_minute_conns = 1;
        }
    }

    fn check_rate_anomaly(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        // Need at least 5 minutes of baseline data
        if self.rate_count < 5 {
            return None;
        }

        let baseline = self.rate_mean;
        if baseline < 1.0 {
            return None;
        }

        let current = self.current_minute_conns as f64;
        if current > baseline * self.rate_multiplier {
            let alert_key = "packet_flood:rate_anomaly".to_string();
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                let src_ip = extract_source_ip(event).unwrap_or_default();
                return Some(self.build_incident(
                    &src_ip,
                    now,
                    "rate_anomaly",
                    Severity::High,
                    format!(
                        "Connection rate anomaly: {}/min vs {:.0}/min baseline",
                        self.current_minute_conns, baseline
                    ),
                ));
            }
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

    fn build_incident(
        &self,
        ip: &str,
        ts: DateTime<Utc>,
        pattern: &str,
        severity: Severity,
        summary: String,
    ) -> Incident {
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!("packet_flood:{}:{}", pattern, ts.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("DDoS detected: {}", pattern.replace('_', " ")),
            summary,
            evidence: serde_json::json!([{
                "kind": "packet_flood",
                "pattern": pattern,
                "ip": ip,
            }]),
            recommended_checks: vec![
                "Check network traffic with tcpdump/iftop for volumetric patterns".to_string(),
                "Review firewall logs for connection spikes".to_string(),
                "Consider enabling rate limiting or IP blocking".to_string(),
                "Check if upstream DDoS mitigation is available".to_string(),
            ],
            tags: vec![
                "ddos".to_string(),
                "packet-flood".to_string(),
                pattern.to_string(),
            ],
            entities: if ip.is_empty() {
                vec![]
            } else {
                vec![EntityRef::ip(ip)]
            },
        }
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.window;
        let udp_cutoff = now - self.udp_window;

        // Prune SYN events
        while self.syn_events.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.syn_events.pop_front();
        }

        // Prune UDP events
        if self.udp_events.len() > 1000 {
            self.udp_events.retain(|_, v| {
                v.retain(|(ts, _)| *ts > udp_cutoff);
                !v.is_empty()
            });
        }

        // Prune HTTP events
        while self.http_events.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.http_events.pop_front();
        }

        // Prune slowloris
        if self.slowloris_conns.len() > 5000 {
            let expire = now - self.window * 2;
            self.slowloris_conns.retain(|_, v| {
                v.retain(|ts| *ts > expire);
                !v.is_empty()
            });
        }

        // Prune cooldown map
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| now - *ts < self.cooldown);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_source_ip(event: &Event) -> Option<String> {
    event
        .details
        .get("src_ip")
        .and_then(|v| v.as_str())
        .or_else(|| event.details.get("ip").and_then(|v| v.as_str()))
        .or_else(|| event.details.get("remote_ip").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

fn extract_dest_ip(event: &Event) -> Option<String> {
    event
        .details
        .get("dst_ip")
        .and_then(|v| v.as_str())
        .or_else(|| event.details.get("dest_ip").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

fn is_network_event(event: &Event) -> bool {
    event.kind.starts_with("network.")
        || event.kind.starts_with("ssh.")
        || event.kind.starts_with("http.")
        || SYN_FLOOD_KINDS.contains(&event.kind.as_str())
        || HTTP_FLOOD_KINDS.contains(&event.kind.as_str())
        || UDP_KINDS.contains(&event.kind.as_str())
}

fn is_udp_event(event: &Event) -> bool {
    let proto = event
        .details
        .get("proto")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    proto.eq_ignore_ascii_case("udp")
        || event.kind == "network.udp_amplification"
        || (event.kind == "suricata.dns.query"
            && event
                .details
                .get("proto")
                .and_then(|v| v.as_str())
                .unwrap_or("udp")
                == "udp")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn syn_event(src_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth_log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: format!("SSH login failed from {}", src_ip),
            details: serde_json::json!({
                "src_ip": src_ip,
                "user": "root",
            }),
            tags: vec!["ssh".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn udp_event(src_ip: &str, dst_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "suricata".to_string(),
            kind: "network.connection".to_string(),
            severity: Severity::Info,
            summary: format!("UDP from {} to {}", src_ip, dst_ip),
            details: serde_json::json!({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": "udp",
                "dst_port": 53,
            }),
            tags: vec!["network".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn http_event(src_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "nginx".to_string(),
            kind: "web_scan".to_string(),
            severity: Severity::Info,
            summary: format!("HTTP request from {}", src_ip),
            details: serde_json::json!({
                "src_ip": src_ip,
                "path": "/api/search",
                "status": 200,
            }),
            tags: vec!["http".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn slowloris_event(src_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.connection".to_string(),
            severity: Severity::Info,
            summary: format!("Connection from {}", src_ip),
            details: serde_json::json!({
                "src_ip": src_ip,
                "dst_port": 80,
                "proto": "tcp",
            }),
            tags: vec!["network".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn network_event(src_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.connection".to_string(),
            severity: Severity::Info,
            summary: format!("Connection from {}", src_ip),
            details: serde_json::json!({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "proto": "tcp",
            }),
            tags: vec!["network".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn new_detector() -> PacketFloodDetector {
        PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        })
    }

    // ── Test 1: SYN flood triggers at threshold ─────────────────────────
    #[test]
    fn syn_flood_triggers_at_threshold() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 10,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 10 failed SSH logins from different IPs within 30s
        let mut triggered = false;
        for i in 0..10 {
            let ip = format!("1.2.3.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::milliseconds(i * 100)));
            if results.iter().any(|inc| inc.summary.contains("SYN flood")) {
                triggered = true;
                let inc = results
                    .iter()
                    .find(|inc| inc.summary.contains("SYN flood"))
                    .unwrap();
                assert_eq!(inc.severity, Severity::Critical);
                assert!(inc.summary.contains("10 connections"));
                assert!(inc.tags.contains(&"syn_flood".to_string()));
            }
        }
        assert!(triggered, "SYN flood should have triggered at 10 events");
    }

    // ── Test 2: Below SYN threshold doesn't trigger ─────────────────────
    #[test]
    fn below_syn_threshold_no_trigger() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 20 failed logins from different IPs (well below 100 threshold)
        for i in 0..20 {
            let ip = format!("2.2.2.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::milliseconds(i * 100)));
            let syn_incidents: Vec<_> = results
                .iter()
                .filter(|inc| inc.summary.contains("SYN flood"))
                .collect();
            assert!(
                syn_incidents.is_empty(),
                "should not trigger SYN flood at {} events",
                i + 1
            );
        }
    }

    // ── Test 3: UDP amplification triggers ───────────────────────────────
    #[test]
    fn udp_amplification_triggers() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 10,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 10 UDP events from different sources to same destination in 10s
        let mut triggered = false;
        for i in 0..10 {
            let src = format!("3.3.3.{}", i + 1);
            let results = det.process(&udp_event(
                &src,
                "10.0.0.1",
                now + Duration::milliseconds(i * 500),
            ));
            if results
                .iter()
                .any(|inc| inc.summary.contains("UDP amplification"))
            {
                triggered = true;
                let inc = results
                    .iter()
                    .find(|inc| inc.summary.contains("UDP amplification"))
                    .unwrap();
                assert_eq!(inc.severity, Severity::Critical);
                assert!(inc.summary.contains("10 packets"));
            }
        }
        assert!(
            triggered,
            "UDP amplification should have triggered at 10 events"
        );
    }

    // ── Test 4: HTTP flood triggers ──────────────────────────────────────
    #[test]
    fn http_flood_triggers() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 20,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 20 HTTP events from different IPs
        let mut triggered = false;
        for i in 0..20 {
            let ip = format!("4.4.4.{}", i + 1);
            let results = det.process(&http_event(&ip, now + Duration::milliseconds(i * 100)));
            if results.iter().any(|inc| inc.summary.contains("HTTP flood")) {
                triggered = true;
                let inc = results
                    .iter()
                    .find(|inc| inc.summary.contains("HTTP flood"))
                    .unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("20 requests"));
            }
        }
        assert!(triggered, "HTTP flood should have triggered at 20 events");
    }

    // ── Test 5: Slowloris detection triggers ─────────────────────────────
    #[test]
    fn slowloris_triggers() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 5,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();
        let attacker_ip = "5.5.5.5";

        // Open 5 connections at time T=0 (these will become "stale" after 30s)
        for i in 0..5 {
            det.process(&slowloris_event(
                attacker_ip,
                now + Duration::milliseconds(i * 10),
            ));
        }

        // Advance time past window (31s) and send another event to trigger check
        let later = now + Duration::seconds(31);
        let results = det.process(&slowloris_event(attacker_ip, later));

        let slowloris_incidents: Vec<_> = results
            .iter()
            .filter(|inc| inc.summary.contains("Slowloris"))
            .collect();
        assert!(
            !slowloris_incidents.is_empty(),
            "Slowloris should have triggered with 5 stale connections"
        );
        let inc = slowloris_incidents[0];
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.summary.contains("5 stale connections"));
        assert!(inc.summary.contains(attacker_ip));
    }

    // ── Test 6: Multi-vector detection (2+ patterns) ─────────────────────
    #[test]
    fn multi_vector_triggers() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 5,
            http_threshold: 5,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Trigger SYN flood first
        for i in 0..5 {
            let ip = format!("6.6.6.{}", i + 1);
            det.process(&syn_event(&ip, now + Duration::milliseconds(i * 10)));
        }

        // Now trigger HTTP flood — should also fire multi-vector
        let mut multi_triggered = false;
        for i in 0..5 {
            let ip = format!("7.7.7.{}", i + 1);
            let results = det.process(&http_event(&ip, now + Duration::milliseconds(100 + i * 10)));
            if results
                .iter()
                .any(|inc| inc.summary.contains("Multi-vector"))
            {
                multi_triggered = true;
                let inc = results
                    .iter()
                    .find(|inc| inc.summary.contains("Multi-vector"))
                    .unwrap();
                assert_eq!(inc.severity, Severity::Critical);
                assert!(inc.summary.contains("attack vectors detected"));
            }
        }
        assert!(
            multi_triggered,
            "Multi-vector should have triggered with SYN + HTTP patterns"
        );
    }

    // ── Test 7: Connection rate anomaly triggers ─────────────────────────
    #[test]
    fn connection_rate_anomaly_triggers() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let start = Utc::now();

        // Build 5 minutes of baseline with ~5 connections per minute
        for minute in 0..5 {
            for conn in 0..5 {
                let ts = start + Duration::minutes(minute) + Duration::seconds(conn * 10);
                det.process(&network_event("8.8.8.1", ts));
            }
            // Force minute bucket rollover
            let next_minute = start + Duration::minutes(minute + 1);
            det.process(&network_event("8.8.8.1", next_minute));
        }

        // Now spike to 60 connections in a single minute (12x baseline of ~5)
        let spike_start = start + Duration::minutes(6);
        let mut triggered = false;
        for i in 0..60 {
            let ts = spike_start + Duration::seconds(i);
            let results = det.process(&network_event("8.8.8.2", ts));
            if results
                .iter()
                .any(|inc| inc.summary.contains("rate anomaly"))
            {
                triggered = true;
                let inc = results
                    .iter()
                    .find(|inc| inc.summary.contains("rate anomaly"))
                    .unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("/min vs"));
                assert!(inc.summary.contains("baseline"));
            }
        }
        assert!(
            triggered,
            "Connection rate anomaly should have triggered with 12x spike"
        );
    }

    // ── Test 8: Normal traffic doesn't trigger ───────────────────────────
    #[test]
    fn normal_traffic_no_trigger() {
        let mut det = new_detector();
        let now = Utc::now();

        // Few SYN events (well below threshold=100)
        for i in 0..5 {
            let ip = format!("9.9.9.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::seconds(i * 5)));
            assert!(
                results.is_empty(),
                "normal SYN traffic should not trigger at {} events",
                i + 1
            );
        }

        // Few HTTP events (well below threshold=200)
        for i in 0..10 {
            let ip = format!("10.10.10.{}", i + 1);
            let results = det.process(&http_event(&ip, now + Duration::seconds(i * 3)));
            assert!(
                results.is_empty(),
                "normal HTTP traffic should not trigger at {} events",
                i + 1
            );
        }

        // Few network events
        for i in 0..3 {
            let results = det.process(&network_event(
                "11.11.11.1",
                now + Duration::seconds(i * 10),
            ));
            assert!(
                results.is_empty(),
                "normal network traffic should not trigger"
            );
        }
    }

    // ── Test 9: Cooldown suppresses re-alert ─────────────────────────────
    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 5,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Trigger SYN flood
        let mut first_triggered = false;
        for i in 0..5 {
            let ip = format!("12.12.12.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::milliseconds(i * 10)));
            if results.iter().any(|inc| inc.summary.contains("SYN flood")) {
                first_triggered = true;
            }
        }
        assert!(first_triggered, "first SYN flood should trigger");

        // Clear the event window and try again within cooldown (60s)
        det.syn_events.clear();
        let within_cooldown = now + Duration::seconds(30);
        let mut second_triggered = false;
        for i in 0..5 {
            let ip = format!("13.13.13.{}", i + 1);
            let results = det.process(&syn_event(
                &ip,
                within_cooldown + Duration::milliseconds(i * 10),
            ));
            if results.iter().any(|inc| inc.summary.contains("SYN flood")) {
                second_triggered = true;
            }
        }
        assert!(
            !second_triggered,
            "SYN flood should be suppressed within cooldown"
        );

        // After cooldown expires
        det.syn_events.clear();
        let after_cooldown = now + Duration::seconds(61);
        let mut third_triggered = false;
        for i in 0..5 {
            let ip = format!("14.14.14.{}", i + 1);
            let results = det.process(&syn_event(
                &ip,
                after_cooldown + Duration::milliseconds(i * 10),
            ));
            if results.iter().any(|inc| inc.summary.contains("SYN flood")) {
                third_triggered = true;
            }
        }
        assert!(
            third_triggered,
            "SYN flood should trigger again after cooldown expires"
        );
    }

    // ── Test 10: Different attack types tracked independently ────────────
    #[test]
    fn different_attack_types_tracked_independently() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 5,
            http_threshold: 5,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // 3 SYN events (below threshold=5)
        for i in 0..3 {
            let ip = format!("15.15.15.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::milliseconds(i * 10)));
            let syn_count: usize = results
                .iter()
                .filter(|inc| inc.summary.contains("SYN flood"))
                .count();
            assert_eq!(syn_count, 0, "SYN should not trigger at {} events", i + 1);
        }

        // 3 HTTP events (below threshold=5)
        for i in 0..3 {
            let ip = format!("16.16.16.{}", i + 1);
            let results = det.process(&http_event(&ip, now + Duration::milliseconds(50 + i * 10)));
            let http_count: usize = results
                .iter()
                .filter(|inc| inc.summary.contains("HTTP flood"))
                .count();
            assert_eq!(http_count, 0, "HTTP should not trigger at {} events", i + 1);
        }

        // SYN reaches threshold (2 more = 5 total)
        let mut syn_triggered = false;
        for i in 3..5 {
            let ip = format!("15.15.15.{}", i + 1);
            let results = det.process(&syn_event(&ip, now + Duration::milliseconds(100 + i * 10)));
            if results.iter().any(|inc| inc.summary.contains("SYN flood")) {
                syn_triggered = true;
            }
        }
        assert!(syn_triggered, "SYN should trigger at 5 events");

        // HTTP still at 3 — should not trigger
        assert_eq!(det.http_events.len(), 3);
    }

    // ── Test 11: Baseline rate calculation works ─────────────────────────
    #[test]
    fn baseline_rate_calculation_works() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let start = Utc::now();

        // Simulate 5 minutes with 10 connections each
        for minute in 0..5 {
            for conn in 0..10 {
                let ts = start + Duration::minutes(minute) + Duration::seconds(conn * 5);
                det.process(&network_event("20.20.20.1", ts));
            }
            // Force bucket rollover
            let next = start + Duration::minutes(minute + 1);
            det.process(&network_event("20.20.20.1", next));
        }

        // After 5 complete minute buckets, mean should be approximately 11
        // (10 connections + 1 rollover event per bucket)
        assert!(det.rate_count >= 5, "should have at least 5 rate samples");
        assert!(
            det.rate_mean > 5.0,
            "baseline mean should be > 5, got {}",
            det.rate_mean
        );
        assert!(
            det.rate_mean < 20.0,
            "baseline mean should be < 20, got {}",
            det.rate_mean
        );
    }

    // ── Test 12: Window expiration cleans old events ─────────────────────
    #[test]
    fn window_expiration_cleans_old_events() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 10,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 8 SYN events at T=0 (below threshold of 10)
        for i in 0..8 {
            let ip = format!("21.21.21.{}", i + 1);
            det.process(&syn_event(&ip, now + Duration::milliseconds(i * 10)));
        }
        assert_eq!(det.syn_events.len(), 8);

        // Advance time past window (31s) and send 2 more — total in window = 2
        let later = now + Duration::seconds(31);
        for i in 0..2 {
            let ip = format!("22.22.22.{}", i + 1);
            let results = det.process(&syn_event(&ip, later + Duration::milliseconds(i * 10)));
            let syn_incidents: Vec<_> = results
                .iter()
                .filter(|inc| inc.summary.contains("SYN flood"))
                .collect();
            assert!(
                syn_incidents.is_empty(),
                "should not trigger — old events expired, only {} in window",
                det.syn_events.len()
            );
        }

        // Only the recent events should remain
        assert!(
            det.syn_events.len() <= 2,
            "old events should be pruned, got {} remaining",
            det.syn_events.len()
        );
    }

    // ── Test 13: UDP amplification requires multiple sources ─────────────
    #[test]
    fn udp_single_source_below_threshold_no_trigger() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 100,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 10,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 10 UDP events from same source to same destination
        // Threshold is 10, and we have 10 events, but only 1 unique source
        // So unique_sources.len() < 2 should prevent trigger
        for i in 0..9 {
            let results = det.process(&udp_event(
                "3.3.3.1",
                "10.0.0.1",
                now + Duration::milliseconds(i * 500),
            ));
            let udp_incidents: Vec<_> = results
                .iter()
                .filter(|inc| inc.summary.contains("UDP amplification"))
                .collect();
            assert!(
                udp_incidents.is_empty(),
                "single source should not trigger UDP amplification"
            );
        }
    }

    // ── Test 14: SYN flood requires multiple unique IPs ──────────────────
    #[test]
    fn syn_flood_requires_multiple_ips() {
        let mut det = PacketFloodDetector::new(PacketFloodParams {
            host: "test".to_string(),
            syn_threshold: 5,
            http_threshold: 200,
            slowloris_threshold: 50,
            udp_threshold: 50,
            rate_multiplier: 10.0,
            window_seconds: 30,
            cooldown_seconds: 60,
        });
        let now = Utc::now();

        // Send 5 events but all from same IP — unique_ips < 3
        for i in 0..5 {
            let results = det.process(&syn_event("1.1.1.1", now + Duration::milliseconds(i * 10)));
            let syn_incidents: Vec<_> = results
                .iter()
                .filter(|inc| inc.summary.contains("SYN flood"))
                .collect();
            assert!(
                syn_incidents.is_empty(),
                "single-IP SYN should not trigger DDoS alert"
            );
        }
    }
}
