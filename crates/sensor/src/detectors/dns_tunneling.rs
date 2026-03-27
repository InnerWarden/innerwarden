use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Well-known public DNS resolvers that should NOT trigger non-standard DNS alerts.
const STANDARD_RESOLVERS: &[&str] = &[
    "127.0.0.53", // systemd-resolved
    "8.8.8.8",    // Google
    "8.8.4.4",    // Google
    "1.1.1.1",    // Cloudflare
    "1.0.0.1",    // Cloudflare
    "9.9.9.9",    // Quad9
];

/// Processes that legitimately query many DNS servers and should be excluded
/// from eBPF DNS tunneling detection (beaconing, burst, nonstandard checks).
const DNS_ALLOWED_COMMS: &[&str] = &[
    "crowdsec",     // CrowdSec queries many DNS servers for threat intel
    "gomon",        // Go monitoring agent does health checks
    "systemd-reso", // systemd-resolved (truncated comm)
    "unbound",      // DNS resolver
    "named",        // BIND DNS
    "dnsmasq",      // DNS forwarder
];

/// Detects DNS tunneling patterns from Suricata DNS query logs AND eBPF connect events.
///
/// Suricata path (deep inspection):
/// 1. High Shannon entropy in subdomain labels (encoded/encrypted data)
/// 2. Volume of unique subdomains to same base domain in window (C2 channel)
/// 3. Unusually long domain names (data exfiltration payload)
///
/// eBPF fallback (port 53 connect() analysis - works WITHOUT Suricata):
/// 4. DNS beaconing - same process connects to same DNS server > 20 times in 60s
/// 5. Non-standard DNS server - connect to port 53 on a non-common resolver
/// 6. DNS burst - > 50 port 53 connections in 30s from any process
pub struct DnsTunnelingDetector {
    entropy_threshold: f64,
    volume_threshold: usize,
    length_threshold: usize,
    window: Duration,
    /// Per (src_ip, base_domain) -> set of unique subdomains seen
    query_history: HashMap<(String, String), HashSet<String>>,
    /// Per (src_ip, base_domain) -> timestamps for windowing
    timestamps: HashMap<(String, String), VecDeque<DateTime<Utc>>>,
    /// Cooldown per alert key to suppress re-alerts
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
    // ── eBPF fallback state ─────────────────────────────────────────────
    /// Per (comm, dst_ip) -> timestamps for DNS beaconing detection (60s window)
    ebpf_beacon: HashMap<(String, String), VecDeque<DateTime<Utc>>>,
    /// Per comm -> timestamps for DNS burst detection (30s window)
    ebpf_burst: HashMap<String, VecDeque<DateTime<Utc>>>,
}

struct EbpfIncidentParams<'a> {
    dst_ip: &'a str,
    comm: &'a str,
    pid: u32,
    ts: DateTime<Utc>,
    pattern: &'a str,
    severity: Severity,
    summary: String,
}

impl DnsTunnelingDetector {
    pub fn new(
        host: impl Into<String>,
        entropy_threshold: f64,
        volume_threshold: usize,
        length_threshold: usize,
        window_seconds: u64,
    ) -> Self {
        Self {
            entropy_threshold,
            volume_threshold,
            length_threshold,
            window: Duration::seconds(window_seconds as i64),
            query_history: HashMap::new(),
            timestamps: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            ebpf_beacon: HashMap::new(),
            ebpf_burst: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // ── eBPF path: connect() to port 53 ─────────────────────────────
        if event.kind == "network.outbound_connect" {
            let dst_port = event.details.get("dst_port")?.as_u64()? as u16;
            if dst_port == 53 {
                return self.process_ebpf_dns(event);
            }
            return None;
        }

        // ── Suricata path: DNS query events ──────────────────────────────
        let is_dns = event.kind == "suricata.dns.query"
            || (event.source == "suricata" && event.kind.contains("dns"));
        if !is_dns {
            return None;
        }

        let rrname = event.details.get("rrname")?.as_str()?;
        let src_ip = event.details.get("src_ip")?.as_str()?;

        let now = event.ts;
        let cutoff = now - self.window;

        // Parse base domain (last 2 labels) and subdomain
        let (base_domain, subdomain) = parse_domain(rrname)?;

        let key = (src_ip.to_string(), base_domain.clone());
        let alert_key = format!("{}:{}", src_ip, base_domain);

        // Cooldown: 300s per (src_ip, base_domain)
        if let Some(&last) = self.alerted.get(&alert_key) {
            if now - last < Duration::seconds(300) {
                return None;
            }
        }

        // Update windowed state
        let ts_ring = self.timestamps.entry(key.clone()).or_default();
        while ts_ring.front().is_some_and(|t| *t < cutoff) {
            ts_ring.pop_front();
        }
        ts_ring.push_back(now);

        let subs = self.query_history.entry(key.clone()).or_default();
        subs.insert(subdomain.clone());

        // ── Check 1: Shannon entropy on subdomain labels ──────────────────
        if !subdomain.is_empty() {
            let entropy = shannon_entropy(&subdomain);
            if entropy > self.entropy_threshold {
                self.alerted.insert(alert_key, now);
                return Some(self.build_incident(
                    src_ip,
                    &base_domain,
                    now,
                    "high_entropy",
                    Severity::High,
                    format!(
                        "DNS tunneling: high-entropy queries to {} (entropy={:.2})",
                        base_domain, entropy
                    ),
                ));
            }
        }

        // ── Check 2: Unique subdomain count in window ─────────────────────
        let unique_count = subs.len();
        if unique_count > self.volume_threshold {
            self.alerted.insert(alert_key, now);
            return Some(self.build_incident(
                src_ip,
                &base_domain,
                now,
                "subdomain_volume",
                Severity::High,
                format!(
                    "DNS tunneling: {} unique subdomains to {}",
                    unique_count, base_domain
                ),
            ));
        }

        // ── Check 3: Total domain length ──────────────────────────────────
        if rrname.len() > self.length_threshold {
            self.alerted.insert(alert_key, now);
            return Some(self.build_incident(
                src_ip,
                &base_domain,
                now,
                "long_domain",
                Severity::Medium,
                format!(
                    "DNS tunneling: unusually long domain ({} chars)",
                    rrname.len()
                ),
            ));
        }

        // Prune stale data
        if self.query_history.len() > 5000 {
            self.timestamps.retain(|_, v| {
                v.retain(|t| *t > cutoff);
                !v.is_empty()
            });
            let live_keys: HashSet<_> = self.timestamps.keys().cloned().collect();
            self.query_history.retain(|k, _| live_keys.contains(k));
        }
        if self.alerted.len() > 500 {
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    /// Process eBPF connect() events targeting port 53.
    /// Provides DNS tunneling detection without Suricata.
    fn process_ebpf_dns(&mut self, event: &Event) -> Option<Incident> {
        let dst_ip = event.details.get("dst_ip")?.as_str()?;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip processes that legitimately query many DNS servers.
        // Verify binary path to prevent evasion by renaming a malicious binary.
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if super::is_verified_infra_process(comm, pid, DNS_ALLOWED_COMMS) {
            return None;
        }

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let now = event.ts;

        let beacon_window = Duration::seconds(60);
        let burst_window = Duration::seconds(30);
        let beacon_cutoff = now - beacon_window;
        let burst_cutoff = now - burst_window;

        // ── Check 4: Non-standard DNS server ────────────────────────────
        // Check before beaconing/burst so a single connection to a rogue
        // DNS server is caught immediately.
        let nonstandard_key = format!("ebpf_nonstandard:{}:{}", comm, dst_ip);
        let is_standard = is_standard_resolver(dst_ip);

        if !is_standard && !self.is_in_cooldown(&nonstandard_key, now) {
            self.alerted.insert(nonstandard_key, now);
            return Some(self.build_ebpf_incident(EbpfIncidentParams {
                dst_ip,
                comm,
                pid,
                ts: now,
                pattern: "nonstandard_dns",
                severity: Severity::Medium,
                summary: format!(
                    "Non-standard DNS server: {} connecting to {}:53",
                    comm, dst_ip
                ),
            }));
        }

        // ── Update beaconing state (per comm+dst_ip) ────────────────────
        let beacon_key = (comm.to_string(), dst_ip.to_string());
        let beacon_ring = self.ebpf_beacon.entry(beacon_key.clone()).or_default();
        while beacon_ring.front().is_some_and(|t| *t < beacon_cutoff) {
            beacon_ring.pop_front();
        }
        beacon_ring.push_back(now);

        // ── Check 5: DNS beaconing (> 20 queries to same server in 60s) ─
        let beacon_count = beacon_ring.len();
        if beacon_count > 20 {
            let alert_key = format!("ebpf_beacon:{}:{}", comm, dst_ip);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_ebpf_incident(EbpfIncidentParams {
                    dst_ip,
                    comm,
                    pid,
                    ts: now,
                    pattern: "dns_beaconing",
                    severity: Severity::High,
                    summary: format!(
                        "DNS beaconing: {} made {} DNS queries in {}s",
                        comm,
                        beacon_count,
                        beacon_window.num_seconds()
                    ),
                }));
            }
        }

        // ── Update burst state (per comm, any destination) ──────────────
        let burst_ring = self.ebpf_burst.entry(comm.to_string()).or_default();
        while burst_ring.front().is_some_and(|t| *t < burst_cutoff) {
            burst_ring.pop_front();
        }
        burst_ring.push_back(now);

        // ── Check 6: DNS burst (> 50 queries in 30s) ────────────────────
        let burst_count = burst_ring.len();
        if burst_count > 50 {
            let alert_key = format!("ebpf_burst:{}", comm);
            if !self.is_in_cooldown(&alert_key, now) {
                self.alerted.insert(alert_key, now);
                return Some(self.build_ebpf_incident(EbpfIncidentParams {
                    dst_ip,
                    comm,
                    pid,
                    ts: now,
                    pattern: "dns_burst",
                    severity: Severity::High,
                    summary: format!(
                        "DNS query burst: {} queries in 30s from {}",
                        burst_count, comm
                    ),
                }));
            }
        }

        // Prune eBPF state
        if self.ebpf_beacon.len() > 5000 {
            self.ebpf_beacon.retain(|_, v| {
                v.retain(|t| *t > beacon_cutoff);
                !v.is_empty()
            });
        }
        if self.ebpf_burst.len() > 2000 {
            self.ebpf_burst.retain(|_, v| {
                v.retain(|t| *t > burst_cutoff);
                !v.is_empty()
            });
        }
        if self.alerted.len() > 500 {
            let cutoff = now - Duration::seconds(300);
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    /// Check if an alert key is within the 300s cooldown period.
    fn is_in_cooldown(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < Duration::seconds(300)
        } else {
            false
        }
    }

    fn build_incident(
        &self,
        src_ip: &str,
        base_domain: &str,
        ts: DateTime<Utc>,
        pattern: &str,
        severity: Severity,
        summary: String,
    ) -> Incident {
        Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "dns_tunneling:{}:{}:{}",
                src_ip,
                base_domain,
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("DNS tunneling detected to {}", base_domain),
            summary,
            evidence: serde_json::json!([{
                "kind": "dns_tunneling",
                "pattern": pattern,
                "src_ip": src_ip,
                "base_domain": base_domain,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Investigate DNS queries from {} to {}", src_ip, base_domain),
                format!("Check if {} is a known DNS tunneling domain", base_domain),
                "Review Suricata DNS logs for full query payload".to_string(),
                "Consider blocking the domain or the source IP".to_string(),
            ],
            tags: vec!["dns-tunneling".to_string(), "exfiltration".to_string()],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn build_ebpf_incident(&self, params: EbpfIncidentParams<'_>) -> Incident {
        let EbpfIncidentParams {
            dst_ip,
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
                "dns_tunneling_ebpf:{}:{}:{}",
                comm,
                dst_ip,
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("DNS tunneling detected (eBPF): {} to {}:53", comm, dst_ip),
            summary,
            evidence: serde_json::json!([{
                "kind": "dns_tunneling_ebpf",
                "pattern": pattern,
                "dst_ip": dst_ip,
                "comm": comm,
                "pid": pid,
                "dst_port": 53,
            }]),
            recommended_checks: vec![
                format!(
                    "Investigate process {} (pid={}) - why is it making DNS queries?",
                    comm, pid
                ),
                format!("Check if {} is a legitimate DNS server", dst_ip),
                "Review /etc/resolv.conf for expected nameservers".to_string(),
                "Consider blocking the process or the destination IP".to_string(),
            ],
            tags: vec![
                "dns-tunneling".to_string(),
                "ebpf".to_string(),
                "exfiltration".to_string(),
            ],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }
}

/// Returns true if the IP is a well-known public resolver or a private/local address
/// that should NOT trigger the non-standard DNS server alert.
fn is_standard_resolver(ip: &str) -> bool {
    if STANDARD_RESOLVERS.contains(&ip) {
        return true;
    }
    // Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
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

/// Parse a domain into (base_domain, subdomain).
/// base_domain = last 2 labels (e.g. "example.com").
/// subdomain = everything before the base domain labels, joined with dots.
/// Returns None if the domain has fewer than 3 labels (no subdomain).
fn parse_domain(domain: &str) -> Option<(String, String)> {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 3 {
        return None;
    }
    let base_domain = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let subdomain = labels[..labels.len() - 2].join(".");
    Some((base_domain, subdomain))
}

/// Compute Shannon entropy (bits per character) of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_event(src_ip: &str, rrname: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "suricata".to_string(),
            kind: "suricata.dns.query".to_string(),
            severity: Severity::Info,
            summary: format!("DNS query for {}", rrname),
            details: serde_json::json!({
                "src_ip": src_ip,
                "rrname": rrname,
            }),
            tags: vec![],
            entities: vec![EntityRef::ip(src_ip)],
        }
    }

    fn ebpf_connect_event(comm: &str, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} connecting to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 1000,
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    // ── Suricata path tests ─────────────────────────────────────────────

    #[test]
    fn high_entropy_subdomain_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();
        // High-entropy subdomain: random hex-like string
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.evil.com",
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.summary.contains("high-entropy"));
        assert!(inc.tags.contains(&"dns-tunneling".to_string()));
        assert!(inc.tags.contains(&"exfiltration".to_string()));
    }

    #[test]
    fn normal_domain_does_not_trigger() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();
        // Normal subdomain: low entropy
        let inc = det.process(&dns_event("10.0.0.5", "www.example.com", now));
        assert!(inc.is_none());
    }

    #[test]
    fn volume_threshold_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 5, 200, 60);
        let now = Utc::now();

        // Send 6 unique subdomains (threshold=5, so >5 triggers)
        for i in 0..6 {
            let domain = format!("sub{}.tunnel.com", i);
            let result = det.process(&dns_event("10.0.0.5", &domain, now + Duration::seconds(i)));
            if i <= 4 {
                // At or below threshold - none of these should trigger on volume
                // (they may trigger on entropy, but "sub0" has low entropy)
                // With threshold=5, count must be >5 to trigger
            }
            if i == 5 {
                // 6th unique subdomain should trigger
                assert!(
                    result.is_some(),
                    "expected volume trigger on subdomain #{i}"
                );
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("unique subdomains"));
                return;
            }
        }
        panic!("volume threshold should have triggered");
    }

    #[test]
    fn below_volume_threshold_does_not_trigger() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 200, 60);
        let now = Utc::now();

        // Send 5 unique subdomains - below threshold of 15
        for i in 0..5 {
            let domain = format!("sub{}.normal.com", i);
            let result = det.process(&dns_event("10.0.0.5", &domain, now + Duration::seconds(i)));
            assert!(
                result.is_none(),
                "should not trigger at {} subdomains",
                i + 1
            );
        }
    }

    #[test]
    fn long_domain_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 100, 50, 60);
        let now = Utc::now();
        // Build a domain longer than 50 chars with low-entropy subdomain
        let long_sub = "a".repeat(60);
        let domain = format!("{}.exfil.com", long_sub);
        let inc = det.process(&dns_event("10.0.0.5", &domain, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Medium);
        assert!(inc.summary.contains("unusually long domain"));
    }

    #[test]
    fn normal_length_does_not_trigger() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 100, 100, 60);
        let now = Utc::now();
        // Short normal domain
        let inc = det.process(&dns_event("10.0.0.5", "api.example.com", now));
        assert!(inc.is_none());
    }

    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // First alert triggers
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.evil.com",
            now,
        ));
        assert!(inc.is_some());

        // Second alert within 300s cooldown - suppressed
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "z9y8x7w6v5u4t3s2r1q0p9o8n7m6.evil.com",
            now + Duration::seconds(10),
        ));
        assert!(inc.is_none());

        // After cooldown expires - triggers again
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "f1e2d3c4b5a6z7y8x9w0v1u2t3s4.evil.com",
            now + Duration::seconds(301),
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn different_base_domains_tracked_independently() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Trigger on evil.com
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.evil.com",
            now,
        ));
        assert!(inc.is_some());

        // evil.com is in cooldown, but other.com should still trigger
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.other.com",
            now + Duration::seconds(1),
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert!(inc.title.contains("other.com"));
    }

    #[test]
    fn shannon_entropy_correctness() {
        // All same chars: entropy = 0
        assert!((shannon_entropy("aaaa") - 0.0).abs() < 0.01);

        // Two equally likely chars: entropy = 1.0
        assert!((shannon_entropy("ab") - 1.0).abs() < 0.01);
        assert!((shannon_entropy("aabb") - 1.0).abs() < 0.01);

        // High entropy: many distinct chars
        let high = shannon_entropy("a1b2c3d4e5f6g7h8");
        assert!(high > 3.5, "expected high entropy, got {high}");
    }

    #[test]
    fn ignores_non_dns_events() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // A network.outbound_connect to a non-53 port should be ignored
        let ev = ebpf_connect_event("curl", "1.2.3.4", 443, now);
        assert!(det.process(&ev).is_none());

        // A completely unrelated event kind should be ignored
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
    fn two_label_domain_skipped() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();
        // Only 2 labels - no subdomain to analyze
        let inc = det.process(&dns_event("10.0.0.5", "example.com", now));
        assert!(inc.is_none());
    }

    // ── eBPF fallback tests ─────────────────────────────────────────────

    #[test]
    fn ebpf_port53_beaconing_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Send 21 connect() to same DNS server from same process in 60s.
        // Use a standard resolver so nonstandard_dns doesn't fire.
        // Beaconing threshold is > 20, so the 21st event (i=20) triggers.
        let mut triggered = false;
        for i in 0..=20 {
            let result = det.process(&ebpf_connect_event(
                "malware",
                "8.8.8.8",
                53,
                now + Duration::seconds(i),
            ));
            if i <= 19 {
                assert!(
                    result.is_none(),
                    "should not trigger at {} connections",
                    i + 1
                );
            }
            if i == 20 {
                assert!(
                    result.is_some(),
                    "expected beaconing trigger at 21 connections"
                );
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("DNS beaconing"));
                assert!(inc.summary.contains("malware"));
                assert!(inc.tags.contains(&"ebpf".to_string()));
                triggered = true;
            }
        }
        assert!(triggered, "beaconing should have triggered");
    }

    #[test]
    fn ebpf_normal_dns_volume_does_not_trigger() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Send 10 connects to standard resolver - well below thresholds
        for i in 0..10 {
            let result = det.process(&ebpf_connect_event(
                "systemd-resolved",
                "1.1.1.1",
                53,
                now + Duration::seconds(i * 3),
            ));
            assert!(
                result.is_none(),
                "normal DNS volume should not trigger at {} connections",
                i + 1
            );
        }
    }

    #[test]
    fn ebpf_nonstandard_dns_server_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Connect to a suspicious external DNS server
        let inc = det.process(&ebpf_connect_event("curl", "45.33.32.156", 53, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Medium);
        assert!(inc.summary.contains("Non-standard DNS server"));
        assert!(inc.summary.contains("45.33.32.156"));
        assert!(inc.tags.contains(&"ebpf".to_string()));
    }

    #[test]
    fn ebpf_standard_resolvers_do_not_trigger_nonstandard() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Standard public resolvers should not trigger
        for (i, resolver) in [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "127.0.0.53",
        ]
        .iter()
        .enumerate()
        {
            let result = det.process(&ebpf_connect_event(
                "systemd-resolved",
                resolver,
                53,
                now + Duration::seconds(i as i64),
            ));
            assert!(
                result.is_none(),
                "standard resolver {} should not trigger",
                resolver
            );
        }

        // Private network DNS servers should not trigger
        for (i, resolver) in ["10.0.0.1", "172.16.0.1", "192.168.1.1"].iter().enumerate() {
            let result = det.process(&ebpf_connect_event(
                "systemd-resolved",
                resolver,
                53,
                now + Duration::seconds(10 + i as i64),
            ));
            assert!(
                result.is_none(),
                "private DNS {} should not trigger nonstandard alert",
                resolver
            );
        }
    }

    #[test]
    fn ebpf_dns_burst_triggers() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Send 51 connects to port 53 within 30s from same process.
        // Rotate across 3 standard resolvers so beaconing (per dst_ip) stays
        // at ~17 each - below the >20 threshold - while burst (per comm)
        // accumulates across all destinations.
        let resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"];
        let mut triggered = false;
        for i in 0..=50 {
            let resolver = resolvers[i as usize % resolvers.len()];
            let result = det.process(&ebpf_connect_event(
                "dig",
                resolver,
                53,
                // Spread across < 30s
                now + Duration::milliseconds(i * 500),
            ));
            if i < 50 {
                assert!(
                    result.is_none(),
                    "should not trigger burst at {} connections",
                    i + 1
                );
            }
            if i == 50 {
                assert!(result.is_some(), "expected burst trigger at 51 connections");
                let inc = result.unwrap();
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.summary.contains("DNS query burst"));
                assert!(inc.summary.contains("dig"));
                triggered = true;
            }
        }
        assert!(triggered, "burst should have triggered");
    }

    #[test]
    fn ebpf_cooldown_works() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // First: non-standard DNS triggers
        let inc = det.process(&ebpf_connect_event("curl", "45.33.32.156", 53, now));
        assert!(inc.is_some());

        // Same alert within 300s - suppressed
        let inc = det.process(&ebpf_connect_event(
            "curl",
            "45.33.32.156",
            53,
            now + Duration::seconds(10),
        ));
        assert!(inc.is_none());

        // After 300s cooldown - triggers again
        let inc = det.process(&ebpf_connect_event(
            "curl",
            "45.33.32.156",
            53,
            now + Duration::seconds(301),
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn ebpf_non_port53_ignored() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();

        // Port 80 connect should be completely ignored
        let inc = det.process(&ebpf_connect_event("curl", "1.2.3.4", 80, now));
        assert!(inc.is_none());
    }

    #[test]
    fn is_standard_resolver_correctness() {
        // Standard public resolvers
        assert!(is_standard_resolver("8.8.8.8"));
        assert!(is_standard_resolver("8.8.4.4"));
        assert!(is_standard_resolver("1.1.1.1"));
        assert!(is_standard_resolver("1.0.0.1"));
        assert!(is_standard_resolver("9.9.9.9"));
        assert!(is_standard_resolver("127.0.0.53"));

        // Private ranges
        assert!(is_standard_resolver("10.0.0.1"));
        assert!(is_standard_resolver("10.255.255.255"));
        assert!(is_standard_resolver("172.16.0.1"));
        assert!(is_standard_resolver("172.31.255.255"));
        assert!(is_standard_resolver("192.168.1.1"));
        assert!(is_standard_resolver("192.168.0.1"));

        // Non-standard - external IPs
        assert!(!is_standard_resolver("45.33.32.156"));
        assert!(!is_standard_resolver("203.0.113.1"));
        assert!(!is_standard_resolver("172.32.0.1")); // outside 172.16-31 range

        // Edge cases
        assert!(!is_standard_resolver("not-an-ip"));
    }
}
