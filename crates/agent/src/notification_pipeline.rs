//! Notification pipeline — incident grouping, channel filtering, and digest.
//!
//! Replaces the per-channel TelegramBatcher with a unified pipeline that groups
//! incidents by detector+entity, filters per-channel by level, and builds digests.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use crate::config::{ChannelFilterLevel, NotificationPipelineConfig};

// ---------------------------------------------------------------------------
// Incident Group
// ---------------------------------------------------------------------------

/// A group of related incidents (same detector + entity) within a time window.
#[derive(Debug, Clone)]
pub(crate) struct IncidentGroup {
    pub detector: String,
    pub entity_type: EntityType,
    pub entity_value: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u32,
    pub severity_max: Severity,
    pub auto_resolved: bool,
    pub sample_incident_id: String,
    /// Whether the first notification for this group has been dispatched.
    first_notified: bool,
    /// Whether a count-threshold summary has already been emitted.
    threshold_summary_sent: bool,
}

impl IncidentGroup {
    fn new(incident: &Incident, detector: String, entity_type: EntityType, entity_value: String) -> Self {
        Self {
            detector,
            entity_type,
            entity_value,
            first_seen: incident.ts,
            last_seen: incident.ts,
            count: 1,
            severity_max: incident.severity.clone(),
            auto_resolved: false,
            sample_incident_id: incident.incident_id.clone(),
            first_notified: false,
            threshold_summary_sent: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Group Summary (emitted on window close or count threshold)
// ---------------------------------------------------------------------------

/// Summary emitted when a group closes or hits the count threshold.
#[derive(Debug)]
pub(crate) struct GroupSummary {
    pub detector: String,
    pub entity_type: EntityType,
    pub entity_value: String,
    pub count: u32,
    pub severity_max: Severity,
    pub auto_resolved: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl GroupSummary {
    /// Format as HTML for Telegram/Slack.
    pub fn format_html(&self) -> String {
        let status = if self.auto_resolved {
            " [auto-resolved]"
        } else {
            ""
        };
        format!(
            "📊 <b>{}</b>: {} incidents from {} <code>{}</code> ({:?}){status}",
            self.detector, self.count, entity_type_label(&self.entity_type), self.entity_value, self.severity_max,
        )
    }
}

fn entity_type_label(et: &EntityType) -> &'static str {
    match et {
        EntityType::Ip => "IP",
        EntityType::User => "user",
        EntityType::Container => "container",
        EntityType::Path => "path",
        EntityType::Service => "service",
    }
}

// ---------------------------------------------------------------------------
// Grouping result — what the caller should do after inserting
// ---------------------------------------------------------------------------

/// Result of inserting an incident into the grouping engine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GroupAction {
    /// First incident in a new group — notify immediately.
    NotifyImmediately,
    /// Subsequent incident in an existing group — suppress individual notification.
    Suppress,
}

// ---------------------------------------------------------------------------
// Grouping Engine
// ---------------------------------------------------------------------------

const MAX_GROUPS: usize = 1000;

/// Groups incidents by detector+entity within a sliding time window.
pub(crate) struct GroupingEngine {
    groups: HashMap<String, IncidentGroup>,
    window_secs: u64,
    count_threshold: u32,
    digest_stats: DigestStats,
}

impl GroupingEngine {
    pub fn new(config: &NotificationPipelineConfig) -> Self {
        Self {
            groups: HashMap::new(),
            window_secs: config.group_window_secs,
            count_threshold: config.group_count_threshold,
            digest_stats: DigestStats::default(),
        }
    }

    /// Insert an incident. Returns the action the caller should take.
    pub fn insert(&mut self, incident: &Incident) -> GroupAction {
        let (detector, entity_type, entity_value) = extract_group_key(incident);
        let key = format!("{detector}:{entity_type:?}:{entity_value}");

        // Evict oldest groups if at capacity
        if self.groups.len() >= MAX_GROUPS && !self.groups.contains_key(&key) {
            self.evict_oldest();
        }

        let now = incident.ts;

        if let Some(group) = self.groups.get_mut(&key) {
            // Check if existing group's window has expired
            let elapsed = (now - group.first_seen).num_seconds().unsigned_abs();
            if elapsed >= self.window_secs {
                // Window expired — start a new group
                let new_group = IncidentGroup::new(incident, detector, entity_type, entity_value);
                self.groups.insert(key, new_group);
                return GroupAction::NotifyImmediately;
            }

            // Existing group, within window — update and suppress
            group.count += 1;
            group.last_seen = now;
            if severity_rank(&incident.severity) > severity_rank(&group.severity_max) {
                group.severity_max = incident.severity.clone();
            }
            self.digest_stats.suppressed_count += 1;
            GroupAction::Suppress
        } else {
            // New group
            let new_group = IncidentGroup::new(incident, detector, entity_type, entity_value);
            self.groups.insert(key, new_group);
            GroupAction::NotifyImmediately
        }
    }

    /// Mark the group containing this incident as auto-resolved.
    pub fn mark_auto_resolved(&mut self, incident: &Incident) {
        let (detector, entity_type, entity_value) = extract_group_key(incident);
        let key = format!("{detector}:{entity_type:?}:{entity_value}");
        if let Some(group) = self.groups.get_mut(&key) {
            group.auto_resolved = true;
        }
    }

    /// Tick: collect summaries for groups that hit count threshold or expired windows.
    /// Call this periodically (e.g., every few seconds in the agent loop).
    pub fn tick(&mut self) -> Vec<GroupSummary> {
        let now = Utc::now();
        let mut summaries = Vec::new();
        let mut expired_keys = Vec::new();

        for (key, group) in &mut self.groups {
            let elapsed = (now - group.first_seen).num_seconds().unsigned_abs();

            // Count threshold — emit early summary (once)
            if group.count >= self.count_threshold && !group.threshold_summary_sent {
                group.threshold_summary_sent = true;
                summaries.push(GroupSummary {
                    detector: group.detector.clone(),
                    entity_type: group.entity_type.clone(),
                    entity_value: group.entity_value.clone(),
                    count: group.count,
                    severity_max: group.severity_max.clone(),
                    auto_resolved: group.auto_resolved,
                    first_seen: group.first_seen,
                    last_seen: group.last_seen,
                });
            }

            // Window expired — emit final summary and mark for removal
            if elapsed >= self.window_secs {
                // Only emit if we haven't already emitted a threshold summary with the same count,
                // or if more incidents arrived after the threshold summary.
                if !group.threshold_summary_sent || group.count > self.count_threshold {
                    summaries.push(GroupSummary {
                        detector: group.detector.clone(),
                        entity_type: group.entity_type.clone(),
                        entity_value: group.entity_value.clone(),
                        count: group.count,
                        severity_max: group.severity_max.clone(),
                        auto_resolved: group.auto_resolved,
                        first_seen: group.first_seen,
                        last_seen: group.last_seen,
                    });
                }
                expired_keys.push(key.clone());
            }
        }

        for key in &expired_keys {
            if let Some(group) = self.groups.remove(key) {
                self.digest_stats.total_groups_closed += 1;
                if group.auto_resolved {
                    self.digest_stats.auto_resolved_groups += 1;
                } else {
                    self.digest_stats.needs_review_groups += 1;
                }
            }
        }

        summaries
    }

    /// Number of active groups (for dashboard/metrics).
    pub fn active_group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get a snapshot of all active groups (for the dashboard API).
    pub fn active_groups(&self) -> Vec<IncidentGroup> {
        self.groups.values().cloned().collect()
    }

    /// Evict the oldest group (by first_seen) to make room.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.first_seen)
            .map(|(k, _)| k.clone())
        {
            self.groups.remove(&oldest_key);
        }
    }
}

// ---------------------------------------------------------------------------
// Channel filter
// ---------------------------------------------------------------------------

/// Decide whether an incident group should be forwarded to a channel.
pub(crate) fn should_notify_channel(
    group: &IncidentGroup,
    level: ChannelFilterLevel,
) -> bool {
    filter_by_level(level, &group.severity_max, group.auto_resolved)
}

/// Decide whether a group summary should be forwarded to a channel.
pub(crate) fn should_notify_summary(
    summary: &GroupSummary,
    level: ChannelFilterLevel,
) -> bool {
    filter_by_level(level, &summary.severity_max, summary.auto_resolved)
}

fn filter_by_level(level: ChannelFilterLevel, severity: &Severity, auto_resolved: bool) -> bool {
    match level {
        ChannelFilterLevel::All => true,
        ChannelFilterLevel::None => false,
        ChannelFilterLevel::Critical => {
            !auto_resolved
                && matches!(severity, Severity::High | Severity::Critical)
        }
        ChannelFilterLevel::Actionable => {
            if auto_resolved {
                // Auto-resolved → not actionable, UNLESS Critical
                matches!(severity, Severity::Critical)
            } else {
                // Not auto-resolved → actionable
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Environment-aware adjustments
// ---------------------------------------------------------------------------

/// Detectors whose notifications are suppressed on cloud VPS (expected noise).
const CLOUD_SUPPRESSED_DETECTORS: &[&str] = &[
    "firmware_integrity", // timing anomalies from hypervisor jitter
    "rootkit",            // timing-based detection unreliable on cloud
];

/// Detectors whose severity is demoted for known admin UIDs.
const ADMIN_DEMOTED_DETECTORS: &[&str] = &[
    "ssh_bruteforce", // admin ssh is expected
    "sudo_abuse",     // admin sudo is expected
];

/// Check if this incident should be suppressed based on environment profile.
/// Returns true if the incident should NOT generate any notification.
pub(crate) fn should_suppress_for_environment(
    incident: &Incident,
    profile: &crate::environment_profile::EnvironmentProfile,
) -> bool {
    let detector = incident
        .incident_id
        .split(':')
        .next()
        .unwrap_or("unknown");

    // Cloud VPS: suppress timing-based detectors up to High severity.
    // On cloud/VM, hypervisor jitter makes timing analysis unreliable.
    // Only Critical timing anomalies go through (indicating persistent pattern).
    if profile.is_cloud() && CLOUD_SUPPRESSED_DETECTORS.iter().any(|d| detector.contains(d)) {
        if !matches!(incident.severity, Severity::Critical) {
            return true;
        }
    }

    false
}

/// Check if this incident is from a known admin UID and should be demoted.
/// Returns true if the incident should be treated as LOW severity for notification purposes.
pub(crate) fn is_admin_routine(
    incident: &Incident,
    profile: &crate::environment_profile::EnvironmentProfile,
) -> bool {
    let detector = incident
        .incident_id
        .split(':')
        .next()
        .unwrap_or("unknown");

    // Only check admin-demotable detectors
    if !ADMIN_DEMOTED_DETECTORS.iter().any(|d| detector.contains(d)) {
        return false;
    }

    // Check if any entity is a known admin UID
    // The UID would be in an entity of type User with value like "uid:1001" or just "1001"
    for entity in &incident.entities {
        if entity.r#type == innerwarden_core::entities::EntityType::User {
            // Try to parse UID from the value
            let uid_str = entity.value.strip_prefix("uid:").unwrap_or(&entity.value);
            if let Ok(uid) = uid_str.parse::<u32>() {
                if profile.is_human_uid(uid) {
                    return true;
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Digest Stats — accumulated from closed groups
// ---------------------------------------------------------------------------

/// Stats accumulated from closed groups for digest messages.
#[derive(Debug, Default, Clone)]
pub(crate) struct DigestStats {
    /// Total incidents grouped (suppressed individual notifications).
    pub suppressed_count: u32,
    /// Groups that were auto-resolved (obvious gate, abuseipdb, crowdsec).
    pub auto_resolved_groups: u32,
    /// Groups that were NOT auto-resolved (need review).
    pub needs_review_groups: u32,
    /// Total groups closed in this period.
    pub total_groups_closed: u32,
}

impl GroupingEngine {
    /// Drain accumulated digest stats and reset counters.
    pub fn drain_digest_stats(&mut self) -> DigestStats {
        std::mem::take(&mut self.digest_stats)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract (detector, primary_entity_type, primary_entity_value) from an incident.
/// Primary entity: first IP, or first User, or first entity of any type.
fn extract_group_key(incident: &Incident) -> (String, EntityType, String) {
    let parts: Vec<&str> = incident.incident_id.splitn(3, ':').collect();
    let detector = parts.first().unwrap_or(&"unknown").to_string();

    // Pick best entity: prefer IP, then User, then first available
    let entity = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .or_else(|| incident.entities.iter().find(|e| e.r#type == EntityType::User))
        .or_else(|| incident.entities.first());

    match entity {
        Some(e) => (detector, e.r#type.clone(), e.value.clone()),
        None => {
            // Fallback: extract entity from incident_id (e.g., "ssh_bruteforce:1.2.3.4:ts")
            if let Some(middle) = parts.get(1) {
                let middle = *middle;
                if middle.parse::<std::net::IpAddr>().is_ok() {
                    (detector, EntityType::Ip, middle.to_string())
                } else if middle.starts_with("uid") || middle.starts_with("user") {
                    (detector, EntityType::User, middle.to_string())
                } else if middle == "unknown" || middle == "timing" {
                    // Group by detector only — all "rootkit:timing:*" go together
                    (detector, EntityType::Ip, middle.to_string())
                } else {
                    (detector, EntityType::Ip, middle.to_string())
                }
            } else {
                (detector, EntityType::Ip, "unknown".to_string())
            }
        }
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_incident(detector: &str, ip: &str, severity: Severity) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: format!("{detector}:{ip}:test"),
            severity,
            title: format!("{detector} alert"),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn make_incident_at(detector: &str, ip: &str, severity: Severity, ts: DateTime<Utc>) -> Incident {
        let mut inc = make_incident(detector, ip, severity);
        inc.ts = ts;
        inc
    }

    fn default_config() -> NotificationPipelineConfig {
        NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 10,
        }
    }

    #[test]
    fn first_incident_notifies_immediately() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        assert_eq!(engine.insert(&inc), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn subsequent_same_group_suppressed() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::Suppress);
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn different_entity_creates_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "5.6.7.8", Severity::High);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 2);
    }

    #[test]
    fn different_detector_creates_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("port_scan", "1.2.3.4", Severity::Medium);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 2);
    }

    #[test]
    fn window_expiry_starts_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let t0 = Utc::now() - chrono::Duration::hours(2);
        let t1 = Utc::now();

        let inc1 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        let inc2 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t1);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        // Old group replaced by new one
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn tick_emits_count_threshold_summary() {
        let cfg = NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 3,
        };
        let mut engine = GroupingEngine::new(&cfg);

        for i in 0..3 {
            let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
            engine.insert(&inc);
            let _ = i;
        }

        let summaries = engine.tick();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 3);
        assert_eq!(summaries[0].detector, "ssh_bruteforce");
    }

    #[test]
    fn tick_emits_window_expiry_summary() {
        let mut engine = GroupingEngine::new(&NotificationPipelineConfig {
            group_window_secs: 1, // 1 second window for test
            group_count_threshold: 100,
        });

        let t0 = Utc::now() - chrono::Duration::seconds(5);
        let inc = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        engine.insert(&inc);

        let summaries = engine.tick();
        assert_eq!(summaries.len(), 1);
        // Group should be removed after expiry
        assert_eq!(engine.active_group_count(), 0);
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let cfg = NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 10,
        };
        let mut engine = GroupingEngine::new(&cfg);

        // Fill to MAX_GROUPS — use unique detector:IP combos
        for i in 0..MAX_GROUPS {
            let a = (i >> 16) & 0xFF;
            let b = (i >> 8) & 0xFF;
            let c = i & 0xFF;
            let inc = make_incident("ssh_bruteforce", &format!("10.{a}.{b}.{c}"), Severity::High);
            engine.insert(&inc);
        }
        assert_eq!(engine.active_group_count(), MAX_GROUPS);

        // Insert one more — should evict oldest
        let inc = make_incident("ssh_bruteforce", "99.99.99.99", Severity::High);
        assert_eq!(engine.insert(&inc), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), MAX_GROUPS);
    }

    #[test]
    fn severity_max_tracks_highest() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::Low);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::Critical);

        engine.insert(&inc1);
        engine.insert(&inc2);

        let groups = engine.active_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].severity_max, Severity::Critical);
    }

    #[test]
    fn mark_auto_resolved() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        engine.insert(&inc);

        engine.mark_auto_resolved(&inc);
        let groups = engine.active_groups();
        assert!(groups[0].auto_resolved);
    }

    // -- Channel filter tests --

    fn make_group(severity: Severity, auto_resolved: bool) -> IncidentGroup {
        IncidentGroup {
            detector: "test".into(),
            entity_type: EntityType::Ip,
            entity_value: "1.2.3.4".into(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            count: 1,
            severity_max: severity,
            auto_resolved,
            sample_incident_id: "test:1".into(),
            first_notified: false,
            threshold_summary_sent: false,
        }
    }

    #[test]
    fn filter_all_passes_everything() {
        assert!(should_notify_channel(&make_group(Severity::Low, true), ChannelFilterLevel::All));
        assert!(should_notify_channel(&make_group(Severity::Low, false), ChannelFilterLevel::All));
    }

    #[test]
    fn filter_none_blocks_everything() {
        assert!(!should_notify_channel(&make_group(Severity::Critical, false), ChannelFilterLevel::None));
    }

    #[test]
    fn filter_critical_passes_high_unresolved() {
        assert!(should_notify_channel(&make_group(Severity::High, false), ChannelFilterLevel::Critical));
        assert!(should_notify_channel(&make_group(Severity::Critical, false), ChannelFilterLevel::Critical));
        assert!(!should_notify_channel(&make_group(Severity::Medium, false), ChannelFilterLevel::Critical));
        assert!(!should_notify_channel(&make_group(Severity::High, true), ChannelFilterLevel::Critical));
    }

    #[test]
    fn filter_actionable_blocks_auto_resolved_except_critical() {
        // Auto-resolved non-critical → not actionable
        assert!(!should_notify_channel(&make_group(Severity::High, true), ChannelFilterLevel::Actionable));
        // Auto-resolved critical → still actionable
        assert!(should_notify_channel(&make_group(Severity::Critical, true), ChannelFilterLevel::Actionable));
        // Not auto-resolved → actionable
        assert!(should_notify_channel(&make_group(Severity::Low, false), ChannelFilterLevel::Actionable));
    }

    // -- Summary filter tests --

    fn make_summary(severity: Severity, auto_resolved: bool) -> GroupSummary {
        GroupSummary {
            detector: "test".into(),
            entity_type: EntityType::Ip,
            entity_value: "1.2.3.4".into(),
            count: 5,
            severity_max: severity,
            auto_resolved,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn summary_filter_actionable_blocks_auto_resolved() {
        assert!(!should_notify_summary(&make_summary(Severity::High, true), ChannelFilterLevel::Actionable));
        assert!(should_notify_summary(&make_summary(Severity::High, false), ChannelFilterLevel::Actionable));
    }

    #[test]
    fn summary_filter_critical_only_high_and_critical() {
        assert!(should_notify_summary(&make_summary(Severity::Critical, false), ChannelFilterLevel::Critical));
        assert!(!should_notify_summary(&make_summary(Severity::Medium, false), ChannelFilterLevel::Critical));
    }

    #[test]
    fn summary_filter_none_blocks_all() {
        assert!(!should_notify_summary(&make_summary(Severity::Critical, false), ChannelFilterLevel::None));
    }

    #[test]
    fn summary_filter_all_passes_all() {
        assert!(should_notify_summary(&make_summary(Severity::Low, true), ChannelFilterLevel::All));
    }

    // -- Backward compat: default config produces same behavior --

    // -- Digest stats tests --

    #[test]
    fn digest_stats_accumulate_on_suppress() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);

        engine.insert(&inc1); // NotifyImmediately
        engine.insert(&inc2); // Suppress

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.suppressed_count, 1);
    }

    #[test]
    fn digest_stats_accumulate_on_group_close() {
        let mut engine = GroupingEngine::new(&NotificationPipelineConfig {
            group_window_secs: 1,
            group_count_threshold: 100,
        });

        let t0 = Utc::now() - chrono::Duration::seconds(5);
        let inc1 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        engine.insert(&inc1);
        engine.mark_auto_resolved(&inc1);

        let inc2 = make_incident_at("port_scan", "5.6.7.8", Severity::Medium, t0);
        engine.insert(&inc2);

        engine.tick(); // both groups expire

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.total_groups_closed, 2);
        assert_eq!(stats.auto_resolved_groups, 1);
        assert_eq!(stats.needs_review_groups, 1);
    }

    #[test]
    fn drain_resets_digest_stats() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        engine.insert(&inc1);
        engine.insert(&inc2);

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.suppressed_count, 1);

        let stats2 = engine.drain_digest_stats();
        assert_eq!(stats2.suppressed_count, 0);
    }

    // -- Environment suppression tests --

    #[test]
    fn cloud_suppresses_low_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Low);
        assert!(should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn cloud_suppresses_high_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::High);
        assert!(should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn cloud_does_not_suppress_critical_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Critical);
        assert!(!should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn bare_metal_does_not_suppress_timing() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "bare_metal".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Low);
        assert!(!should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn admin_routine_detected() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.human_uids = vec![1001];

        let mut inc = make_incident("sudo_abuse", "1001", Severity::Medium);
        inc.entities = vec![innerwarden_core::entities::EntityRef {
            r#type: innerwarden_core::entities::EntityType::User,
            value: "1001".into(),
        }];
        assert!(is_admin_routine(&inc, &profile));
    }

    #[test]
    fn non_admin_not_demoted() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.human_uids = vec![1001];

        let mut inc = make_incident("sudo_abuse", "9999", Severity::Medium);
        inc.entities = vec![innerwarden_core::entities::EntityRef {
            r#type: innerwarden_core::entities::EntityType::User,
            value: "9999".into(),
        }];
        assert!(!is_admin_routine(&inc, &profile));
    }

    // -- Backward compat --

    #[test]
    fn default_channel_config_is_actionable() {
        let cfg = crate::config::ChannelNotificationConfig::default();
        assert_eq!(cfg.notification_level, ChannelFilterLevel::Actionable);
        // Actionable with auto_resolved=false passes everything (same as current behavior)
        assert!(filter_by_level(cfg.notification_level, &Severity::Low, false));
        assert!(filter_by_level(cfg.notification_level, &Severity::High, false));
        assert!(filter_by_level(cfg.notification_level, &Severity::Critical, false));
    }
}
