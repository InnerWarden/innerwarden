use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityType, incident::Incident};

#[derive(Debug, Clone)]
pub struct IncidentCluster {
    pub pivot: String,
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub incident_ids: Vec<String>,
    pub detector_kinds: Vec<String>,
}

impl IncidentCluster {
    pub fn size(&self) -> usize {
        self.incident_ids.len()
    }
}

#[derive(Debug, Clone)]
pub struct TemporalCorrelator {
    window: Duration,
    max_history: usize,
    watermark: Option<DateTime<Utc>>,
    history: Vec<Incident>,
}

impl TemporalCorrelator {
    pub fn new(window_seconds: u64, max_history: usize) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            max_history,
            watermark: None,
            history: Vec::new(),
        }
    }

    pub fn related_to(&mut self, incident: &Incident, limit: usize) -> Vec<Incident> {
        self.advance_watermark(incident.ts);
        self.prune();

        let mut related: Vec<Incident> = self
            .history
            .iter()
            .filter(|other| {
                other.incident_id != incident.incident_id
                    && within_window(other.ts, incident.ts, self.window)
                    && shares_correlation_pivot(other, incident)
            })
            .cloned()
            .collect();

        related.sort_by(|a, b| b.ts.cmp(&a.ts));
        related.truncate(limit);
        related
    }

    pub fn observe(&mut self, incident: &Incident) {
        self.advance_watermark(incident.ts);
        self.history.push(incident.clone());
        self.prune();
    }

    fn advance_watermark(&mut self, ts: DateTime<Utc>) {
        match self.watermark {
            Some(current) if current >= ts => {}
            _ => self.watermark = Some(ts),
        }
    }

    fn prune(&mut self) {
        let Some(watermark) = self.watermark else {
            return;
        };
        let cutoff = watermark - self.window;
        self.history.retain(|incident| incident.ts >= cutoff);

        if self.history.len() > self.max_history {
            let to_drop = self.history.len() - self.max_history;
            self.history.drain(0..to_drop);
        }
    }
}

pub fn build_clusters(incidents: &[Incident], window_seconds: u64) -> Vec<IncidentCluster> {
    if incidents.is_empty() {
        return Vec::new();
    }

    let window = Duration::seconds(window_seconds as i64);
    let mut ordered: Vec<&Incident> = incidents.iter().collect();
    ordered.sort_by(|a, b| a.ts.cmp(&b.ts));

    let mut working: Vec<WorkingCluster> = Vec::new();

    for incident in ordered {
        let tokens = correlation_tokens(incident);
        let detector_kind = detector_kind(incident);

        let mut selected: Option<usize> = None;
        for (idx, cluster) in working.iter().enumerate() {
            if incident.ts - cluster.end_ts > window {
                continue;
            }
            if !cluster.tokens.is_disjoint(&tokens) {
                match selected {
                    Some(prev) if working[prev].end_ts >= cluster.end_ts => {}
                    _ => selected = Some(idx),
                }
            }
        }

        match selected {
            Some(idx) => {
                let cluster = &mut working[idx];
                cluster.end_ts = incident.ts;
                cluster.tokens.extend(tokens);
                cluster.detector_kinds.insert(detector_kind);
                cluster.incident_ids.push(incident.incident_id.clone());
            }
            None => {
                let mut detector_kinds = BTreeSet::new();
                detector_kinds.insert(detector_kind);

                working.push(WorkingCluster {
                    tokens,
                    start_ts: incident.ts,
                    end_ts: incident.ts,
                    incident_ids: vec![incident.incident_id.clone()],
                    detector_kinds,
                });
            }
        }
    }

    let mut clusters: Vec<IncidentCluster> = working
        .into_iter()
        .map(|cluster| IncidentCluster {
            pivot: select_primary_pivot(&cluster.tokens),
            start_ts: cluster.start_ts,
            end_ts: cluster.end_ts,
            incident_ids: cluster.incident_ids,
            detector_kinds: cluster.detector_kinds.into_iter().collect(),
        })
        .collect();

    clusters.sort_by(|a, b| b.start_ts.cmp(&a.start_ts));
    clusters
}

pub fn detector_kind(incident: &Incident) -> String {
    incident
        .incident_id
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn shares_correlation_pivot(a: &Incident, b: &Incident) -> bool {
    let a_tokens = correlation_tokens(a);
    let b_tokens = correlation_tokens(b);
    !a_tokens.is_disjoint(&b_tokens)
}

fn correlation_tokens(incident: &Incident) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();

    for entity in &incident.entities {
        match entity.r#type {
            EntityType::Ip => {
                tokens.insert(format!("ip:{}", entity.value));
            }
            EntityType::User => {
                tokens.insert(format!("user:{}", entity.value));
            }
            _ => {}
        }
    }

    tokens.insert(format!("detector:{}", detector_kind(incident)));
    tokens
}

fn select_primary_pivot(tokens: &BTreeSet<String>) -> String {
    tokens
        .iter()
        .find(|token| token.starts_with("ip:"))
        .or_else(|| tokens.iter().find(|token| token.starts_with("user:")))
        .or_else(|| tokens.iter().find(|token| token.starts_with("detector:")))
        .cloned()
        .unwrap_or_else(|| "detector:unknown".to_string())
}

fn within_window(a: DateTime<Utc>, b: DateTime<Utc>, window: Duration) -> bool {
    (a - b).num_seconds().abs() <= window.num_seconds()
}

/// Calculate a confidence boost based on cross-detector correlation.
///
/// When the same IP triggers multiple distinct detectors within the correlation
/// window, this is strong evidence of a real attack - not a false positive.
/// The boost multiplies the AI's base confidence:
///
///   1 detector  → 1.0x (no boost)
///   2 detectors → 1.15x (e.g., ssh_bruteforce + port_scan)
///   3 detectors → 1.30x (e.g., + credential_stuffing)
///   4+ detectors → 1.50x (coordinated attack - near certainty)
///
/// The result is clamped to [0.0, 1.0].
pub fn cross_detector_boost(
    correlator: &mut TemporalCorrelator,
    incident: &Incident,
    base_confidence: f64,
) -> (f64, Vec<String>) {
    let related = correlator.related_to(incident, 20);

    if related.is_empty() {
        return (base_confidence, vec![]);
    }

    // Collect distinct detector kinds across related incidents
    let mut detector_kinds: BTreeSet<String> = BTreeSet::new();
    detector_kinds.insert(detector_kind(incident));
    for r in &related {
        detector_kinds.insert(detector_kind(r));
    }

    let distinct_detectors = detector_kinds.len();
    let multiplier = match distinct_detectors {
        0 | 1 => 1.0,
        2 => 1.15,
        3 => 1.30,
        _ => 1.50,
    };

    let boosted = (base_confidence * multiplier).min(1.0);
    let kinds: Vec<String> = detector_kinds.into_iter().collect();

    (boosted, kinds)
}

#[derive(Debug, Clone)]
struct WorkingCluster {
    tokens: BTreeSet<String>,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    incident_ids: Vec<String>,
    detector_kinds: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn incident(ts_offset_secs: i64, incident_id: &str, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: Utc::now() + Duration::seconds(ts_offset_secs),
            host: "h".to_string(),
            incident_id: incident_id.to_string(),
            severity: Severity::High,
            title: "title".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities,
        }
    }

    #[test]
    fn temporal_correlator_links_incidents_by_ip_and_window() {
        let mut correlator = TemporalCorrelator::new(300, 100);

        let first = incident(
            0,
            "ssh_bruteforce:1.2.3.4:a",
            vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
        );
        let second = incident(
            60,
            "credential_stuffing:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4"), EntityRef::user("admin")],
        );

        correlator.observe(&first);
        let related = correlator.related_to(&second, 10);

        assert_eq!(related.len(), 1);
        assert_eq!(related[0].incident_id, first.incident_id);
    }

    #[test]
    fn temporal_correlator_expires_old_history() {
        let mut correlator = TemporalCorrelator::new(60, 100);

        let old = incident(0, "port_scan:1.2.3.4:a", vec![EntityRef::ip("1.2.3.4")]);
        let new_incident = incident(
            120,
            "ssh_bruteforce:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4")],
        );

        correlator.observe(&old);
        let related = correlator.related_to(&new_incident, 10);
        assert!(
            related.is_empty(),
            "old incident must be outside the window"
        );
    }

    #[test]
    fn build_clusters_groups_cross_detector_incidents_by_ip() {
        let incidents = vec![
            incident(
                0,
                "port_scan:1.2.3.4:a",
                vec![EntityRef::ip("1.2.3.4"), EntityRef::user("scan")],
            ),
            incident(
                30,
                "ssh_bruteforce:1.2.3.4:b",
                vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
            ),
            incident(
                600,
                "ssh_bruteforce:9.9.9.9:c",
                vec![EntityRef::ip("9.9.9.9")],
            ),
        ];

        let clusters = build_clusters(&incidents, 120);

        assert_eq!(clusters.len(), 2);
        let merged = clusters
            .iter()
            .find(|cluster| cluster.incident_ids.len() == 2)
            .expect("expected merged cluster");
        assert_eq!(merged.pivot, "ip:1.2.3.4");
        assert!(merged.detector_kinds.iter().any(|kind| kind == "port_scan"));
        assert!(merged
            .detector_kinds
            .iter()
            .any(|kind| kind == "ssh_bruteforce"));
    }

    #[test]
    fn cross_detector_boost_no_correlation() {
        let mut correlator = TemporalCorrelator::new(300, 100);
        let inc = incident(
            0,
            "ssh_bruteforce:1.2.3.4:a",
            vec![EntityRef::ip("1.2.3.4")],
        );
        let (boosted, detectors) = cross_detector_boost(&mut correlator, &inc, 0.7);
        assert_eq!(boosted, 0.7); // no boost
        assert!(detectors.is_empty());
    }

    #[test]
    fn cross_detector_boost_two_detectors() {
        let mut correlator = TemporalCorrelator::new(300, 100);

        let first = incident(0, "port_scan:1.2.3.4:a", vec![EntityRef::ip("1.2.3.4")]);
        correlator.observe(&first);

        let second = incident(
            30,
            "ssh_bruteforce:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4")],
        );
        let (boosted, detectors) = cross_detector_boost(&mut correlator, &second, 0.7);

        // 2 detectors → 1.15x boost: 0.7 * 1.15 = 0.805
        assert!(boosted > 0.8);
        assert_eq!(detectors.len(), 2);
    }

    #[test]
    fn cross_detector_boost_three_detectors() {
        let mut correlator = TemporalCorrelator::new(300, 100);

        correlator.observe(&incident(
            0,
            "port_scan:1.2.3.4:a",
            vec![EntityRef::ip("1.2.3.4")],
        ));
        correlator.observe(&incident(
            15,
            "ssh_bruteforce:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4")],
        ));

        let third = incident(
            30,
            "credential_stuffing:1.2.3.4:c",
            vec![EntityRef::ip("1.2.3.4")],
        );
        let (boosted, detectors) = cross_detector_boost(&mut correlator, &third, 0.7);

        // 3 detectors → 1.30x boost: 0.7 * 1.30 = 0.91
        assert!(boosted > 0.9);
        assert_eq!(detectors.len(), 3);
    }

    #[test]
    fn cross_detector_boost_clamps_to_one() {
        let mut correlator = TemporalCorrelator::new(300, 100);

        correlator.observe(&incident(
            0,
            "port_scan:1.2.3.4:a",
            vec![EntityRef::ip("1.2.3.4")],
        ));
        correlator.observe(&incident(
            10,
            "ssh_bruteforce:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4")],
        ));
        correlator.observe(&incident(
            20,
            "credential_stuffing:1.2.3.4:c",
            vec![EntityRef::ip("1.2.3.4")],
        ));

        let fourth = incident(30, "c2_callback:1.2.3.4:d", vec![EntityRef::ip("1.2.3.4")]);
        let (boosted, _) = cross_detector_boost(&mut correlator, &fourth, 0.95);

        // 4 detectors → 1.50x, but 0.95 * 1.50 = 1.425 → clamped to 1.0
        assert_eq!(boosted, 1.0);
    }

    #[test]
    fn cross_detector_boost_same_detector_no_boost() {
        let mut correlator = TemporalCorrelator::new(300, 100);

        correlator.observe(&incident(
            0,
            "ssh_bruteforce:1.2.3.4:a",
            vec![EntityRef::ip("1.2.3.4")],
        ));

        let second = incident(
            30,
            "ssh_bruteforce:1.2.3.4:b",
            vec![EntityRef::ip("1.2.3.4")],
        );
        let (boosted, _) = cross_detector_boost(&mut correlator, &second, 0.7);

        // Same detector twice → only 1 distinct kind → no boost
        assert_eq!(boosted, 0.7);
    }
}
