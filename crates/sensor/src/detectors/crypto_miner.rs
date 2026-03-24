use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Known mining pool ports (stratum protocol and variants).
const MINING_POOL_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 8888, 9999, 14444, 14433];

/// Known mining pool domain substrings.
const MINING_POOL_DOMAINS: &[&str] = &[
    "pool.minexmr.com",
    "xmrpool.eu",
    "monerohash.com",
    "pool.hashvault.pro",
    "mine.c3pool.com",
    "pool.supportxmr.com",
    "xmr.nanopool.org",
    "pool.minergate.com",
    "stratum+tcp://",
    "stratum+ssl://",
    "stratum2+tcp://",
    "mining.pool",
    "nicehash.com",
    "2miners.com",
    "f2pool.com",
    "ethermine.org",
    "flypool.org",
    "unmineable.com",
];

/// Known crypto miner process names (matched against comm basename).
const KNOWN_MINER_NAMES: &[&str] = &[
    "xmrig",
    "minerd",
    "cpuminer",
    "ethminer",
    "cgminer",
    "bfgminer",
    "cryptonight",
    "t-rex",
    "phoenixminer",
    "nbminer",
    "gminer",
    "lolminer",
    "teamredminer",
];

/// Detects cryptocurrency mining activity via network connections and process execution.
///
/// Patterns detected:
/// 1. Connections to known mining pool ports (3333, 4444, 5555, 7777, 8888, 9999, 14444, 14433)
/// 2. DNS/hostname matching known mining pool domains
/// 3. Execution of known miner process names (xmrig, minerd, cpuminer, etc.)
/// 4. Stratum protocol indicators (mining pool port + persistent connection pattern)
pub struct CryptoMinerDetector {
    cooldown: Duration,
    /// Cooldown per alert key to suppress re-alerts
    alerted: HashMap<String, DateTime<Utc>>,
    /// Track (process, dst_ip) connections to mining ports for stratum detection
    stratum_connections: HashMap<(String, String), Vec<DateTime<Utc>>>,
    host: String,
}

struct IncidentParams<'a> {
    ts: DateTime<Utc>,
    pattern: &'a str,
    severity: Severity,
    title: String,
    summary: String,
    evidence: serde_json::Value,
    recommended_checks: Vec<String>,
    tags: Vec<String>,
    entities: Vec<EntityRef>,
}

impl CryptoMinerDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            stratum_connections: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // ── Check process execution for known miner names ─────────────────
        if event.kind == "shell.command_exec" || event.kind == "process.exec" {
            return self.check_miner_process(event);
        }

        // ── Check network connections for mining pool indicators ──────────
        if event.kind == "network.outbound_connect" || event.kind == "network.connection" {
            return self.check_mining_connection(event);
        }

        None
    }

    /// Check if a process execution event matches a known miner name.
    fn check_miner_process(&mut self, event: &Event) -> Option<Incident> {
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("command").and_then(|v| v.as_str()))?;

        let comm_base = comm.split('/').next_back().unwrap_or(comm).to_lowercase();

        let is_known_miner = KNOWN_MINER_NAMES
            .iter()
            .any(|name| comm_base == *name || comm_base.starts_with(name));

        if !is_known_miner {
            return None;
        }

        let now = event.ts;
        let alert_key = format!("miner_process:{}", comm_base);

        if self.is_in_cooldown(&alert_key, now) {
            return None;
        }

        self.alerted.insert(alert_key, now);

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Some(self.build_incident(IncidentParams {
            ts: now,
            pattern: "miner_process",
            severity: Severity::Critical,
            title: format!("Crypto miner detected: {comm}"),
            summary: format!(
                "Known cryptocurrency miner process '{}' (pid={}) executing on host",
                comm, pid
            ),
            evidence: serde_json::json!([{
                "kind": "crypto_miner",
                "pattern": "miner_process",
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Kill process {comm} (pid={pid}) immediately"),
                "Check how the miner was installed — review process tree and parent".to_string(),
                "Scan for persistence mechanisms (crontab, systemd services)".to_string(),
                "Check for lateral movement — the attacker may have compromised other hosts"
                    .to_string(),
            ],
            tags: vec!["crypto-miner".to_string(), "process".to_string()],
            entities: vec![],
        }))
    }

    /// Check if a network connection targets a mining pool.
    fn check_mining_connection(&mut self, event: &Event) -> Option<Incident> {
        let dst_ip = event.details.get("dst_ip").and_then(|v| v.as_str())?;
        let dst_port = event.details.get("dst_port").and_then(|v| v.as_u64())? as u16;
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

        // Filter out internal IPs
        if super::is_internal_ip(dst_ip) {
            return None;
        }

        let now = event.ts;

        // ── Check for known mining pool domain in event details ──────────
        if let Some(incident) = self.check_mining_domain(event, comm, pid, now) {
            return Some(incident);
        }

        // ── Check for known mining pool port ──────────────────────────────
        let is_mining_port = MINING_POOL_PORTS.contains(&dst_port);

        if is_mining_port {
            // Track for stratum protocol detection
            let stratum_key = (comm.to_string(), dst_ip.to_string());
            let entries = self.stratum_connections.entry(stratum_key).or_default();
            let cutoff = now - self.cooldown;
            entries.retain(|ts| *ts > cutoff);
            entries.push(now);

            // ── Stratum detection: 3+ connections to same mining port ─────
            let conn_count = entries.len();
            if conn_count >= 3 {
                let alert_key = format!("stratum:{}:{}:{}", comm, dst_ip, dst_port);
                if !self.is_in_cooldown(&alert_key, now) {
                    self.alerted.insert(alert_key, now);
                    return Some(self.build_incident(IncidentParams {
                        ts: now,
                        pattern: "stratum_protocol",
                        severity: Severity::High,
                        title: format!(
                            "Stratum mining protocol: {comm} persistent connection to {dst_ip}:{dst_port}"
                        ),
                        summary: format!(
                            "Process {} shows stratum mining protocol pattern: {} persistent connections to {}:{} (mining pool port)",
                            comm,
                            conn_count,
                            dst_ip,
                            dst_port
                        ),
                        evidence: serde_json::json!([{
                            "kind": "crypto_miner",
                            "pattern": "stratum_protocol",
                            "comm": comm,
                            "pid": pid,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "connection_count": conn_count,
                        }]),
                        recommended_checks: vec![
                            format!("Investigate process {comm} (pid={pid}) — likely a crypto miner"),
                            format!("Block outbound connections to {dst_ip}:{dst_port}"),
                            "Review process tree to find installation vector".to_string(),
                            "Check CPU usage — mining causes sustained high CPU".to_string(),
                        ],
                        tags: vec![
                            "crypto-miner".to_string(),
                            "stratum".to_string(),
                            "network".to_string(),
                        ],
                        entities: vec![EntityRef::ip(dst_ip)],
                    }));
                }
            }

            // ── Single connection to mining pool port ─────────────────────
            let alert_key = format!("mining_port:{}:{}", comm, dst_ip);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(IncidentParams {
                    ts: now,
                    pattern: "mining_pool_port",
                    severity: Severity::High,
                    title: format!(
                        "Crypto mining: {comm} connecting to mining pool {dst_ip}:{dst_port}"
                    ),
                    summary: format!(
                        "Process {} (pid={}) connected to {}:{} — known mining pool port",
                        comm, pid, dst_ip, dst_port
                    ),
                    evidence: serde_json::json!([{
                        "kind": "crypto_miner",
                        "pattern": "mining_pool_port",
                        "comm": comm,
                        "pid": pid,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                    }]),
                    recommended_checks: vec![
                        format!("Investigate process {comm} (pid={pid}) — possible crypto miner"),
                        format!("Check if {dst_ip}:{dst_port} is a known mining pool"),
                        "Review CPU/GPU usage on the host".to_string(),
                        "Consider blocking the process and the destination IP".to_string(),
                    ],
                    tags: vec![
                        "crypto-miner".to_string(),
                        "network".to_string(),
                        "ebpf".to_string(),
                    ],
                    entities: vec![EntityRef::ip(dst_ip)],
                }));
            }
        }

        // Prune stale state
        if self.stratum_connections.len() > 5000 {
            let cutoff = now - self.cooldown;
            self.stratum_connections.retain(|_, v| {
                v.retain(|ts| *ts > cutoff);
                !v.is_empty()
            });
        }
        if self.alerted.len() > 500 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    /// Check if event details contain a known mining pool domain.
    fn check_mining_domain(
        &mut self,
        event: &Event,
        comm: &str,
        pid: u32,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        // Look for domain/hostname in event details
        let hostname = event
            .details
            .get("hostname")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("domain").and_then(|v| v.as_str()))
            .or_else(|| event.details.get("server_name").and_then(|v| v.as_str()));

        let hostname = hostname?;
        let hostname_lower = hostname.to_lowercase();

        let matched_domain = MINING_POOL_DOMAINS
            .iter()
            .find(|domain| hostname_lower.contains(*domain))?;

        let alert_key = format!("mining_domain:{}:{}", comm, matched_domain);
        if self.is_in_cooldown(&alert_key, now) {
            return None;
        }

        self.alerted.insert(alert_key, now);

        Some(self.build_incident(IncidentParams {
            ts: now,
            pattern: "mining_pool_domain",
            severity: Severity::High,
            title: format!("Crypto mining: {comm} connecting to mining pool {hostname}"),
            summary: format!(
                "Process {} (pid={}) connected to known mining pool domain: {}",
                comm, pid, hostname
            ),
            evidence: serde_json::json!([{
                "kind": "crypto_miner",
                "pattern": "mining_pool_domain",
                "comm": comm,
                "pid": pid,
                "hostname": hostname,
                "matched_domain": *matched_domain,
            }]),
            recommended_checks: vec![
                format!("Kill process {comm} (pid={pid}) and investigate"),
                format!("Block DNS resolution for {hostname}"),
                "Scan for persistence mechanisms (crontab, systemd services)".to_string(),
                "Review how the miner was installed".to_string(),
            ],
            tags: vec![
                "crypto-miner".to_string(),
                "network".to_string(),
                "dns".to_string(),
            ],
            entities: vec![],
        }))
    }

    /// Check if an alert key is within the cooldown period.
    fn is_in_cooldown(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < self.cooldown
        } else {
            false
        }
    }

    fn build_incident(&self, params: IncidentParams<'_>) -> Incident {
        let IncidentParams {
            ts,
            pattern,
            severity,
            title,
            summary,
            evidence,
            recommended_checks,
            tags,
            entities,
        } = params;
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!("crypto_miner:{}:{}", pattern, ts.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title,
            summary,
            evidence,
            recommended_checks,
            tags,
            entities,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_event(comm: &str, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} connecting to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    fn connect_event_with_hostname(
        comm: &str,
        dst_ip: &str,
        dst_port: u16,
        hostname: &str,
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
                "pid": 1234,
                "uid": 0,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "hostname": hostname,
            }),
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    fn exec_event(comm: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: format!("process exec: {comm}"),
            details: serde_json::json!({
                "pid": 5678,
                "uid": 0,
                "comm": comm,
            }),
            tags: vec!["ebpf".to_string(), "process".to_string()],
            entities: vec![],
        }
    }

    // ── Test 1: Known mining port triggers ──────────────────────────────

    #[test]
    fn known_mining_port_triggers() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        for &port in &[3333u16, 4444, 5555, 7777, 8888, 9999, 14444, 14433] {
            let mut det = CryptoMinerDetector::new("test", 300);
            let inc = det.process(&connect_event("suspicious", "45.33.32.1", port, now));
            assert!(inc.is_some(), "expected trigger on mining port {port}");
            let inc = inc.unwrap();
            assert_eq!(inc.severity, Severity::High);
            assert!(
                inc.title.contains("mining pool"),
                "title should mention mining pool for port {port}: {}",
                inc.title
            );
        }

        // Verify alert_key tracking works across ports for same detector instance
        let inc = det.process(&connect_event("worker", "45.33.32.1", 3333, now));
        assert!(inc.is_some());
    }

    // ── Test 2: Normal port doesn't trigger ─────────────────────────────

    #[test]
    fn normal_port_does_not_trigger() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        for &port in &[80u16, 443, 8080, 22, 25, 53, 3306, 5432] {
            let inc = det.process(&connect_event("curl", "1.2.3.4", port, now));
            assert!(inc.is_none(), "should not trigger on normal port {port}");
        }
    }

    // ── Test 3: Known miner process name triggers (critical) ────────────

    #[test]
    fn known_miner_process_triggers_critical() {
        let now = Utc::now();

        for name in &[
            "xmrig",
            "minerd",
            "cpuminer",
            "ethminer",
            "cgminer",
            "bfgminer",
            "cryptonight",
            "t-rex",
            "phoenixminer",
            "nbminer",
            "gminer",
            "lolminer",
            "teamredminer",
        ] {
            let mut det = CryptoMinerDetector::new("test", 300);
            let inc = det.process(&exec_event(name, now));
            assert!(inc.is_some(), "expected trigger on miner process: {name}");
            let inc = inc.unwrap();
            assert_eq!(
                inc.severity,
                Severity::Critical,
                "miner process {name} should be Critical severity"
            );
            assert!(
                inc.title.contains("Crypto miner detected"),
                "title should mention crypto miner for {name}: {}",
                inc.title
            );
        }
    }

    // ── Test 4: Unknown process name doesn't trigger ────────────────────

    #[test]
    fn unknown_process_does_not_trigger() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        for name in &[
            "nginx", "postgres", "sshd", "systemd", "bash", "python3", "node",
        ] {
            let inc = det.process(&exec_event(name, now));
            assert!(
                inc.is_none(),
                "should not trigger on normal process: {name}"
            );
        }
    }

    // ── Test 5: Private IP doesn't trigger ──────────────────────────────

    #[test]
    fn private_ip_does_not_trigger() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // Private/loopback IPs on mining ports should not trigger
        for ip in &["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"] {
            let inc = det.process(&connect_event("suspicious", ip, 3333, now));
            assert!(inc.is_none(), "should not trigger on private IP {ip}");
        }
    }

    // ── Test 6: Cooldown suppresses re-alert ────────────────────────────

    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // First alert triggers
        let inc = det.process(&connect_event("miner", "45.33.32.1", 3333, now));
        assert!(inc.is_some());

        // Same process+IP within cooldown — suppressed
        let inc = det.process(&connect_event(
            "miner",
            "45.33.32.1",
            3333,
            now + Duration::seconds(10),
        ));
        assert!(inc.is_none(), "should be suppressed within cooldown");

        // After cooldown expires — triggers again
        let inc = det.process(&connect_event(
            "miner",
            "45.33.32.1",
            3333,
            now + Duration::seconds(301),
        ));
        assert!(inc.is_some(), "should trigger after cooldown expires");
    }

    // ── Test 7: Different processes tracked independently ────────────────

    #[test]
    fn different_processes_tracked_independently() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // Process A triggers
        let inc = det.process(&connect_event("worker_a", "45.33.32.1", 3333, now));
        assert!(inc.is_some(), "process A should trigger");

        // Process B to same IP should also trigger (different cooldown key)
        let inc = det.process(&connect_event(
            "worker_b",
            "45.33.32.1",
            3333,
            now + Duration::seconds(1),
        ));
        assert!(inc.is_some(), "process B should trigger independently");

        // Process A to different IP should also trigger
        let inc = det.process(&connect_event(
            "worker_a",
            "99.99.99.99",
            4444,
            now + Duration::seconds(2),
        ));
        assert!(inc.is_some(), "process A to different IP should trigger");
    }

    // ── Test 8: Multiple mining indicators boost severity ───────────────

    #[test]
    fn multiple_indicators_boost_severity() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // Known miner process name → Critical (already the highest for process detection)
        let inc = det.process(&exec_event("xmrig", now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(
            inc.severity,
            Severity::Critical,
            "known miner process should be Critical"
        );

        // Mining port connection → High
        let inc = det.process(&connect_event("unknown_proc", "5.6.7.8", 3333, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(
            inc.severity,
            Severity::High,
            "mining port connection should be High"
        );

        // Stratum pattern (3+ connections) → High
        let mut det2 = CryptoMinerDetector::new("test", 300);

        // First connection triggers mining_pool_port (High)
        let inc = det2.process(&connect_event("worker", "5.6.7.8", 3333, now));
        let inc = inc.expect("first connection should trigger");
        assert_eq!(inc.severity, Severity::High);

        // Second connection — suppressed by cooldown on mining_port key
        let _inc2 = det2.process(&connect_event(
            "worker",
            "5.6.7.8",
            3333,
            now + Duration::seconds(10),
        ));

        // Third connection triggers stratum pattern (High)
        let inc = det2.process(&connect_event(
            "worker",
            "5.6.7.8",
            3333,
            now + Duration::seconds(20),
        ));
        let inc = inc.expect("third connection should trigger stratum");
        assert_eq!(inc.severity, Severity::High);
        assert!(
            inc.title.contains("Stratum"),
            "stratum detection should mention Stratum: {}",
            inc.title
        );
    }

    // ── Additional: Mining pool domain detection ────────────────────────

    #[test]
    fn mining_pool_domain_triggers() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&connect_event_with_hostname(
            "curl",
            "5.6.7.8",
            443,
            "pool.minexmr.com",
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("mining pool"));
        assert!(inc.tags.contains(&"dns".to_string()));
    }

    #[test]
    fn stratum_uri_in_hostname_triggers() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&connect_event_with_hostname(
            "miner",
            "5.6.7.8",
            3333,
            "stratum+tcp://pool.example.com",
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn normal_hostname_does_not_trigger() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&connect_event_with_hostname(
            "curl",
            "5.6.7.8",
            443,
            "api.github.com",
            now,
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_unrelated_event_kinds() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        let ev = Event {
            ts: now,
            host: "test".to_string(),
            source: "auth_log".to_string(),
            kind: "auth.login".to_string(),
            severity: Severity::Info,
            summary: "login".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn miner_process_with_path_prefix_triggers() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // Process name with path prefix — basename extraction should catch it
        let inc = det.process(&exec_event("/tmp/.hidden/xmrig", now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn cooldown_works_for_process_detection() {
        let mut det = CryptoMinerDetector::new("test", 300);
        let now = Utc::now();

        // First detection
        let inc = det.process(&exec_event("xmrig", now));
        assert!(inc.is_some());

        // Within cooldown — suppressed
        let inc = det.process(&exec_event("xmrig", now + Duration::seconds(10)));
        assert!(inc.is_none());

        // After cooldown — triggers again
        let inc = det.process(&exec_event("xmrig", now + Duration::seconds(301)));
        assert!(inc.is_some());
    }
}
