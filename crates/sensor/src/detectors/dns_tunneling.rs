use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects DNS tunneling patterns from Suricata DNS query logs.
///
/// Patterns detected:
/// 1. High Shannon entropy in subdomain labels (encoded/encrypted data)
/// 2. Volume of unique subdomains to same base domain in window (C2 channel)
/// 3. Unusually long domain names (data exfiltration payload)
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
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Filter: only Suricata DNS query events
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
                // At or below threshold — none of these should trigger on volume
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

        // Send 5 unique subdomains — below threshold of 15
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

        // Second alert within 300s cooldown — suppressed
        let inc = det.process(&dns_event(
            "10.0.0.5",
            "z9y8x7w6v5u4t3s2r1q0p9o8n7m6.evil.com",
            now + Duration::seconds(10),
        ));
        assert!(inc.is_none());

        // After cooldown expires — triggers again
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

        let mut ev = dns_event("10.0.0.5", "a1b2c3d4e5f6g7h8i9j0.evil.com", now);
        ev.kind = "network.outbound_connect".to_string();
        ev.source = "ebpf".to_string();
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn two_label_domain_skipped() {
        let mut det = DnsTunnelingDetector::new("test", 4.0, 15, 100, 60);
        let now = Utc::now();
        // Only 2 labels — no subdomain to analyze
        let inc = det.process(&dns_event("10.0.0.5", "example.com", now));
        assert!(inc.is_none());
    }
}
