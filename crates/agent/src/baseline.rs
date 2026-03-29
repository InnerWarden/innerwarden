//! Baseline Learning and Anomaly Detection.
//!
//! Learns what is "normal" for a host over a 7-day training period, then
//! detects deviations that could indicate zero-day attacks, insider threats,
//! or compromised systems — without any predefined rules.
//!
//! Tracked baselines:
//! - Event rate per hour by source (24-hour profile)
//! - Process lineages (parent→child relationships)
//! - User login hours
//! - Outbound network destinations per process

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::{Event, Severity};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Days of data needed before baselines are considered mature.
const TRAINING_DAYS: u32 = 7;
/// Minimum events per hour baseline to trigger rate anomaly.
const MIN_RATE_BASELINE: f32 = 5.0;
/// Rate drop threshold to trigger silence anomaly (80% drop).
const SILENCE_THRESHOLD: f32 = 0.20;
/// Rate spike threshold (300% increase).
const SPIKE_THRESHOLD: f32 = 3.0;
/// Maximum process lineages to track.
const MAX_LINEAGES: usize = 5_000;
/// Maximum outbound destinations per process.
const MAX_DESTINATIONS_PER_PROCESS: usize = 500;
/// Maximum processes to track destinations for.
const MAX_DESTINATION_PROCESSES: usize = 200;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Persistent baseline store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStore {
    /// Events per hour by source. Key = source name (e.g., "auth_log").
    /// Value = 24-element array, each element is the average event count for that hour.
    event_rate_by_hour: HashMap<String, [f32; 24]>,

    /// Known normal process lineages (parent_comm→child_comm).
    process_lineages: HashSet<String>,

    /// User login hour profile. Key = username.
    /// Value = 24-element array, each bit indicates login activity seen in that hour.
    user_login_hours: HashMap<String, [u8; 24]>,

    /// Normal outbound destinations per process. Key = process name.
    /// Value = set of destination IPs/hostnames seen.
    process_destinations: HashMap<String, HashSet<String>>,

    /// Has the learning period completed?
    mature: bool,

    /// Number of distinct days of data observed.
    training_days: u32,

    /// Dates observed (YYYY-MM-DD), used to count training_days.
    observed_dates: HashSet<String>,

    /// Running event counts for current hour (for rate calculation).
    current_hour_counts: HashMap<String, u32>,
    /// Which hour the current counts belong to.
    current_hour: u8,

    /// Total observations (for stats).
    total_observations: u64,
}

/// An anomaly detected by the baseline engine.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyReport {
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub expected: String,
    pub observed: String,
    pub confidence: f32,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Event rate dropped significantly vs baseline.
    EventRateDrop,
    /// Event rate spiked significantly vs baseline.
    EventRateSpike,
    /// Previously unseen process lineage.
    ProcessLineage,
    /// User login at unusual hour.
    UserLoginTime,
    /// Process connecting to previously unseen destination.
    NewDestination,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl BaselineStore {
    /// Create a new empty baseline store.
    pub fn new() -> Self {
        Self {
            event_rate_by_hour: HashMap::new(),
            process_lineages: HashSet::new(),
            user_login_hours: HashMap::new(),
            process_destinations: HashMap::new(),
            mature: false,
            training_days: 0,
            observed_dates: HashSet::new(),
            current_hour_counts: HashMap::new(),
            current_hour: 0,
            total_observations: 0,
        }
    }

    /// Is the baseline mature (training period complete)?
    #[allow(dead_code)]
    pub fn is_mature(&self) -> bool {
        self.mature
    }

    /// Days of training data collected.
    #[allow(dead_code)]
    pub fn training_days(&self) -> u32 {
        self.training_days
    }

    /// Total events observed.
    #[allow(dead_code)]
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }

    /// Observe an event to update baselines (always) and check for anomalies
    /// (only when mature).
    ///
    /// Returns anomalies found (empty vec during training).
    pub fn observe_event(&mut self, event: &Event) -> Vec<AnomalyReport> {
        self.total_observations += 1;
        let hour = event.ts.hour() as u8;
        let date = event.ts.format("%Y-%m-%d").to_string();

        // Track training days
        if self.observed_dates.insert(date) {
            self.training_days = self.observed_dates.len() as u32;
            if !self.mature && self.training_days >= TRAINING_DAYS {
                self.mature = true;
                info!(
                    days = self.training_days,
                    lineages = self.process_lineages.len(),
                    "baseline learning complete — anomaly detection active"
                );
            }
        }

        // Flush hourly counts when the hour changes
        if hour != self.current_hour {
            self.flush_hour_counts();
            self.current_hour = hour;
        }

        // Update event rate counts
        *self
            .current_hour_counts
            .entry(event.source.clone())
            .or_default() += 1;

        // Track process lineages from eBPF exec events
        // NOTE: We track the lineage string before inserting so anomaly
        // detection can check if it's new before it's learned.
        let mut new_lineage: Option<String> = None;
        if event.source == "ebpf" && event.kind == "shell.command_exec" {
            if let (Some(ppid_comm), Some(comm)) = (
                event.details.get("parent_comm").and_then(|v| v.as_str()),
                event.details.get("comm").and_then(|v| v.as_str()),
            ) {
                let lineage = format!("{ppid_comm}→{comm}");
                let is_new = !self.process_lineages.contains(&lineage);
                if self.process_lineages.len() < MAX_LINEAGES {
                    self.process_lineages.insert(lineage.clone());
                }
                if is_new && self.mature {
                    new_lineage = Some(lineage);
                }
            }
        }

        // Track user login hours
        if event.kind.contains("login") || event.kind.contains("accepted") {
            for entity in &event.entities {
                if entity.r#type == EntityType::User {
                    let profile = self
                        .user_login_hours
                        .entry(entity.value.clone())
                        .or_insert([0; 24]);
                    profile[hour as usize] = profile[hour as usize].saturating_add(1);
                }
            }
        }

        // Track outbound destinations per process
        // Check for new destination BEFORE inserting (same pattern as lineages).
        let mut new_destination: Option<(String, String, usize)> = None;
        if event.kind == "network.outbound_connect" {
            if let Some(comm) = event.details.get("comm").and_then(|v| v.as_str()) {
                if let Some(dst_ip) = event.details.get("dst_ip").and_then(|v| v.as_str()) {
                    if let Some(known_dests) = self.process_destinations.get(comm) {
                        if !known_dests.contains(dst_ip) && known_dests.len() >= 3 && self.mature {
                            new_destination =
                                Some((comm.to_string(), dst_ip.to_string(), known_dests.len()));
                        }
                    }
                    if self.process_destinations.len() < MAX_DESTINATION_PROCESSES {
                        let dests = self
                            .process_destinations
                            .entry(comm.to_string())
                            .or_default();
                        if dests.len() < MAX_DESTINATIONS_PER_PROCESS {
                            dests.insert(dst_ip.to_string());
                        }
                    }
                }
            }
        }

        // Anomaly detection only when mature
        if !self.mature {
            return Vec::new();
        }

        let mut anomalies = Vec::new();

        // Check process lineage anomaly (using pre-computed new_lineage)
        if let Some(lineage) = new_lineage {
            anomalies.push(AnomalyReport {
                anomaly_type: AnomalyType::ProcessLineage,
                description: format!("Previously unseen process lineage: {lineage}"),
                expected: "Known process lineage".into(),
                observed: lineage,
                confidence: 0.7,
                severity: Severity::Medium,
            });
        }

        // Check user login time anomaly
        if event.kind.contains("login") || event.kind.contains("accepted") {
            for entity in &event.entities {
                if entity.r#type == EntityType::User {
                    if let Some(profile) = self.user_login_hours.get(&entity.value) {
                        if profile[hour as usize] == 0 {
                            // User never logged in at this hour before
                            anomalies.push(AnomalyReport {
                                anomaly_type: AnomalyType::UserLoginTime,
                                description: format!(
                                    "User '{}' logged in at {}:00 UTC (never seen at this hour)",
                                    entity.value, hour
                                ),
                                expected: format!("Login hours: {}", format_active_hours(profile)),
                                observed: format!("{}:00 UTC", hour),
                                confidence: 0.6,
                                severity: Severity::Medium,
                            });
                        }
                    }
                }
            }
        }

        // Check new outbound destination (using pre-computed new_destination)
        if let Some((comm, dst_ip, known_count)) = new_destination {
            anomalies.push(AnomalyReport {
                anomaly_type: AnomalyType::NewDestination,
                description: format!(
                    "Process '{}' connected to new destination {} (not in {} known destinations)",
                    comm, dst_ip, known_count
                ),
                expected: format!("{} known destinations", known_count),
                observed: dst_ip,
                confidence: 0.5,
                severity: Severity::Low,
            });
        }

        anomalies
    }

    /// Check event rate anomalies. Call this periodically (e.g., every 5 minutes).
    ///
    /// Returns anomalies for sources whose event rate significantly deviates
    /// from the baseline for the current hour.
    pub fn check_rate_anomalies(&self) -> Vec<AnomalyReport> {
        if !self.mature {
            return Vec::new();
        }

        let hour = Utc::now().hour() as usize;
        let mut anomalies = Vec::new();

        for (source, count) in &self.current_hour_counts {
            if let Some(baseline) = self.event_rate_by_hour.get(source) {
                let expected = baseline[hour];
                if expected < MIN_RATE_BASELINE {
                    continue; // Not enough data to compare
                }

                let current = *count as f32;
                let ratio = current / expected;

                // Silence detection: rate dropped >80%
                if ratio < SILENCE_THRESHOLD && current < expected - MIN_RATE_BASELINE {
                    anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::EventRateDrop,
                        description: format!(
                            "Event rate for '{}' dropped {:.0}% vs baseline ({} vs {:.0} expected at {}:00)",
                            source,
                            (1.0 - ratio) * 100.0,
                            count,
                            expected,
                            hour
                        ),
                        expected: format!("{:.0} events", expected),
                        observed: format!("{} events", count),
                        confidence: 0.7,
                        severity: Severity::High, // Silence is dangerous
                    });
                }

                // Spike detection: rate increased >300%
                if ratio > SPIKE_THRESHOLD {
                    anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::EventRateSpike,
                        description: format!(
                            "Event rate for '{}' spiked {:.0}x vs baseline ({} vs {:.0} expected at {}:00)",
                            source,
                            ratio,
                            count,
                            expected,
                            hour
                        ),
                        expected: format!("{:.0} events", expected),
                        observed: format!("{} events", count),
                        confidence: 0.6,
                        severity: Severity::Medium,
                    });
                }
            }
        }

        anomalies
    }

    /// Persist the baseline to a JSON file.
    pub fn save(&self, data_dir: &Path) {
        let path = data_dir.join("baseline.json");
        match serde_json::to_string(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write baseline.json: {e}");
                }
            }
            Err(e) => warn!("failed to serialize baseline: {e}"),
        }
    }

    /// Load a baseline from a JSON file.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("baseline.json");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Self::new();
        };
        match serde_json::from_str(&content) {
            Ok(store) => {
                info!("loaded baseline from disk");
                store
            }
            Err(e) => {
                warn!("failed to deserialize baseline: {e}");
                Self::new()
            }
        }
    }

    // ── Internal ───────────────────────────────────────────────────

    /// Flush current hour counts into the running average.
    fn flush_hour_counts(&mut self) {
        let hour = self.current_hour as usize;
        for (source, count) in &self.current_hour_counts {
            let profile = self
                .event_rate_by_hour
                .entry(source.clone())
                .or_insert([0.0; 24]);
            // Exponential moving average: new = 0.8 * old + 0.2 * current
            // This gives more weight to recent data while retaining history.
            profile[hour] = profile[hour] * 0.8 + *count as f32 * 0.2;
        }
        self.current_hour_counts.clear();
    }
}

impl Default for BaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_active_hours(profile: &[u8; 24]) -> String {
    let active: Vec<String> = profile
        .iter()
        .enumerate()
        .filter(|(_, v)| **v > 0)
        .map(|(h, _)| format!("{h}:00"))
        .collect();
    if active.is_empty() {
        "none".to_string()
    } else {
        active.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_event(source: &str, kind: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: source.into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        }
    }

    fn make_exec_event(parent: &str, child: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "parent_comm": parent,
                "comm": child,
                "pid": 1234,
                "uid": 0,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![],
        }
    }

    fn make_login_event(user: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "auth_log".into(),
            kind: "ssh.login_accepted".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::user(user)],
        }
    }

    fn make_connect_event(comm: &str, dst_ip: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": 443,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn new_baseline_is_immature() {
        let store = BaselineStore::new();
        assert!(!store.is_mature());
        assert_eq!(store.training_days(), 0);
    }

    #[test]
    fn training_period_tracks_days() {
        let mut store = BaselineStore::new();
        // Simulate events across 7 different days
        for day in 1..=7 {
            let mut ev = make_event("auth_log", "ssh.login_failed");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }
        assert!(store.is_mature());
        assert_eq!(store.training_days(), 7);
    }

    #[test]
    fn no_anomalies_during_training() {
        let mut store = BaselineStore::new();
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn process_lineage_anomaly_after_training() {
        let mut store = BaselineStore::new();

        // Train for 7 days with known lineage
        for day in 1..=7 {
            let mut ev = make_exec_event("nginx", "worker");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }
        assert!(store.is_mature());

        // Now a new lineage should trigger anomaly
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::ProcessLineage
        ));
    }

    #[test]
    fn known_lineage_no_anomaly() {
        let mut store = BaselineStore::new();

        // Train with nginx→sh
        for day in 1..=7 {
            let mut ev = make_exec_event("nginx", "sh");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }

        // Same lineage again — no anomaly
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn new_destination_anomaly() {
        let mut store = BaselineStore::new();

        // Train for 7 days with known destinations
        for day in 1..=7 {
            for ip in &["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
                let mut ev = make_connect_event("curl", ip);
                ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap()
                    .and_utc();
                store.observe_event(&ev);
            }
        }
        assert!(store.is_mature());

        // New destination should trigger anomaly
        let ev = make_connect_event("curl", "185.220.101.45");
        let anomalies = store.observe_event(&ev);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::NewDestination
        ));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = BaselineStore::new();
        store.process_lineages.insert("nginx→worker".into());
        store.training_days = 5;
        store.save(dir.path());

        let loaded = BaselineStore::load(dir.path());
        assert_eq!(loaded.training_days, 5);
        assert!(loaded.process_lineages.contains("nginx→worker"));
    }

    #[test]
    fn rate_anomaly_silence() {
        let mut store = BaselineStore::new();
        // Fake a mature baseline with known rate
        store.mature = true;
        store.training_days = 7;
        let hour = Utc::now().hour() as usize;
        store.event_rate_by_hour.insert("auth_log".into(), {
            let mut arr = [0.0f32; 24];
            arr[hour] = 100.0; // baseline: 100 events at this hour
            arr
        });
        // Current hour: only 5 events (95% drop)
        store.current_hour = hour as u8;
        store.current_hour_counts.insert("auth_log".into(), 5);

        let anomalies = store.check_rate_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::EventRateDrop
        ));
        assert_eq!(anomalies[0].severity, Severity::High);
    }

    #[test]
    fn rate_anomaly_spike() {
        let mut store = BaselineStore::new();
        store.mature = true;
        store.training_days = 7;
        let hour = Utc::now().hour() as usize;
        store.event_rate_by_hour.insert("auth_log".into(), {
            let mut arr = [0.0f32; 24];
            arr[hour] = 10.0; // baseline: 10 events at this hour
            arr
        });
        store.current_hour = hour as u8;
        store.current_hour_counts.insert("auth_log".into(), 50); // 5x spike

        let anomalies = store.check_rate_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::EventRateSpike
        ));
    }
}
