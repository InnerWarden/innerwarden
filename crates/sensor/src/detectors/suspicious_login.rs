use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects successful SSH logins from IPs that previously had failed attempts.
/// Pattern: brute-force → success = possible compromise.
///
/// Also flags logins from IPs that are not in a known-good set (first-time IPs).
pub struct SuspiciousLoginDetector {
    window: Duration,
    /// Per-IP ring of failed login timestamps within window.
    failed_ips: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// IPs that have successfully logged in before (known-good baseline).
    known_good_ips: std::collections::HashSet<String>,
    /// Suppress re-alerts per IP within window.
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl SuspiciousLoginDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            failed_ips: HashMap::new(),
            known_good_ips: std::collections::HashSet::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let ip = event.details["ip"].as_str()?.to_string();
        if super::is_internal_ip(&ip) {
            return None;
        }
        let now = event.ts;
        let cutoff = now - self.window;

        // Track failed logins
        if event.kind == "ssh.login_failed" {
            let entries = self.failed_ips.entry(ip).or_default();
            while entries.front().is_some_and(|&t| t < cutoff) {
                entries.pop_front();
            }
            entries.push_back(now);
            return None;
        }

        // Only care about successful logins
        if event.kind != "ssh.login_success" {
            return None;
        }

        let user = event.details["user"].as_str().unwrap_or("unknown");

        // Track known-good IPs (baseline)
        if self.known_good_ips.contains(&ip) {
            return None;
        }

        // Check if this IP had prior failed attempts
        let prior_failures = self
            .failed_ips
            .get(&ip)
            .map(|entries| entries.iter().filter(|&&t| t > cutoff).count())
            .unwrap_or(0);

        // Suppress re-alerts within window
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                // Still add to known-good so we don't alert again
                self.known_good_ips.insert(ip);
                return None;
            }
        }

        if prior_failures == 0 {
            // First-time IP with no failures — add to known-good baseline
            self.known_good_ips.insert(ip);
            return None;
        }

        // Brute-force followed by success — possible compromise
        self.alerted.insert(ip.clone(), now);
        self.known_good_ips.insert(ip.clone());

        let severity = if prior_failures >= 5 {
            Severity::Critical
        } else {
            Severity::High
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "suspicious_login:{}:{}",
                ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Successful SSH login from previously attacking IP {ip}"),
            summary: format!(
                "IP {ip} logged in as {user} after {prior_failures} failed attempts in the last {} seconds. \
                 This could indicate a compromised credential.",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "suspicious_login",
                "ip": ip,
                "user": user,
                "prior_failures": prior_failures,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Immediately verify if {user} login from {ip} was authorized"),
                format!("Check what commands were run by {user} after login"),
                "Consider suspending the user's sudo access until verified".to_string(),
                "Review /var/log/auth.log for the full session".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                "compromise".to_string(),
            ],
            entities: vec![EntityRef::ip(&ip), EntityRef::user(user)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: format!("Failed SSH from {ip}"),
            details: serde_json::json!({"ip": ip, "user": "root"}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn success_event(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: Severity::Info,
            summary: format!("Login accepted for {user} from {ip}"),
            details: serde_json::json!({"ip": ip, "user": user}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip), EntityRef::user(user)],
        }
    }

    #[test]
    fn fires_on_success_after_failures() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        // 3 failed attempts
        det.process(&failed_event("1.2.3.4", now));
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(1)));
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(2)));

        // Then success
        let inc = det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(10),
            ))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("1.2.3.4"));
        assert!(inc.summary.contains("3 failed"));
    }

    #[test]
    fn critical_for_many_failures() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        for i in 0..6 {
            det.process(&failed_event("5.6.7.8", now + Duration::seconds(i)));
        }

        let inc = det
            .process(&success_event(
                "5.6.7.8",
                "admin",
                now + Duration::seconds(10),
            ))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn no_alert_for_clean_login() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        // Success without prior failures
        assert!(det
            .process(&success_event("9.9.9.9", "ubuntu", now))
            .is_none());
    }

    #[test]
    fn no_alert_for_known_good_ip() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        // First login — becomes known-good
        det.process(&success_event("1.1.1.1", "ubuntu", now));

        // Failures then success from known-good — no alert
        det.process(&failed_event("1.1.1.1", now + Duration::seconds(100)));
        assert!(det
            .process(&success_event(
                "1.1.1.1",
                "ubuntu",
                now + Duration::seconds(200)
            ))
            .is_none());
    }

    #[test]
    fn ignores_internal_ips() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        det.process(&failed_event("192.168.1.1", now));
        assert!(det
            .process(&success_event(
                "192.168.1.1",
                "root",
                now + Duration::seconds(1)
            ))
            .is_none());
    }

    #[test]
    fn suppresses_realert_within_window() {
        let mut det = SuspiciousLoginDetector::new("test", 300);
        let now = Utc::now();

        det.process(&failed_event("1.2.3.4", now));
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(1)
            ))
            .is_some());
        // Second alert suppressed
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(10)));
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(11)
            ))
            .is_none());
    }
}
