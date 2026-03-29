//! Playbook Engine — automated response sequences.
//!
//! Playbooks define ordered sequences of response actions triggered by
//! detector matches, severity thresholds, or correlation chain detections.
//! They replace ad-hoc AI decisions with deterministic, auditable response
//! sequences for known attack patterns.
//!
//! Playbooks are defined in TOML files under `rules/playbooks/`:
//! ```toml
//! [playbook.ransomware]
//! trigger_detector = "ransomware"
//! trigger_min_severity = "high"
//! steps = [
//!   { action = "capture_forensics" },
//!   { action = "kill_process" },
//!   { action = "block_ip" },
//!   { action = "notify", channels = ["telegram", "slack"] },
//! ]
//! ```

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// Playbook definitions
// ---------------------------------------------------------------------------

/// A playbook: trigger condition + ordered response steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
    /// If true, the playbook runs even in dry-run mode (for forensics/notify).
    #[serde(default)]
    pub run_in_dry_run: bool,
}

/// When to trigger a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    /// Detector name to match (from incident_id prefix). Empty = any detector.
    #[serde(default)]
    pub detector: String,
    /// Minimum severity to trigger. Default = "high".
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Correlation chain rule ID to trigger on (e.g., "CL-002"). Empty = not chain-based.
    #[serde(default)]
    pub chain_rule: String,
}

fn default_min_severity() -> String {
    "high".to_string()
}

/// A single step in a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub action: String,
    /// Extra parameters for the action.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

/// Result of executing a playbook step.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub action: String,
    pub status: String, // "ok", "skipped", "failed: ..."
    pub detail: String,
}

/// Result of executing an entire playbook.
#[derive(Debug, Clone, Serialize)]
pub struct PlaybookExecution {
    pub playbook_id: String,
    pub playbook_name: String,
    pub incident_id: String,
    pub triggered_at: DateTime<Utc>,
    pub steps: Vec<StepResult>,
    pub overall_status: String,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The playbook engine: loads and evaluates playbooks.
pub struct PlaybookEngine {
    playbooks: Vec<Playbook>,
    /// Cooldown per playbook ID to prevent re-triggering.
    cooldowns: HashMap<String, DateTime<Utc>>,
    cooldown_duration: Duration,
}

impl PlaybookEngine {
    /// Create a new engine, loading playbooks from `rules_dir` + built-in defaults.
    pub fn new(rules_dir: &Path) -> Self {
        let mut playbooks = load_playbooks(rules_dir);
        playbooks.extend(builtin_playbooks());
        info!(playbooks = playbooks.len(), "playbook engine loaded");
        Self {
            playbooks,
            cooldowns: HashMap::new(),
            cooldown_duration: Duration::seconds(600),
        }
    }

    /// Check if any playbook matches this incident. Returns the first matching
    /// playbook and its planned execution (steps are not actually executed here).
    pub fn evaluate(&mut self, incident: &Incident) -> Option<PlaybookExecution> {
        let now = Utc::now();
        let detector = crate::mitre::detector_from_incident_id(&incident.incident_id);

        for playbook in &self.playbooks {
            // Skip chain-only playbooks (those are triggered via evaluate_chain)
            if !playbook.trigger.chain_rule.is_empty() {
                continue;
            }

            // Check cooldown
            if let Some(&last) = self.cooldowns.get(&playbook.id) {
                if now - last < self.cooldown_duration {
                    continue;
                }
            }

            // Check trigger
            if !matches_trigger(&playbook.trigger, detector, &incident.severity) {
                continue;
            }

            self.cooldowns.insert(playbook.id.clone(), now);

            info!(
                playbook = %playbook.id,
                incident = %incident.incident_id,
                steps = playbook.steps.len(),
                "playbook triggered"
            );

            let steps: Vec<StepResult> = playbook
                .steps
                .iter()
                .map(|step| StepResult {
                    action: step.action.clone(),
                    status: "pending".to_string(),
                    detail: format!("params: {:?}", step.params),
                })
                .collect();

            return Some(PlaybookExecution {
                playbook_id: playbook.id.clone(),
                playbook_name: playbook.name.clone(),
                incident_id: incident.incident_id.clone(),
                triggered_at: now,
                steps,
                overall_status: "pending".to_string(),
            });
        }

        None
    }

    /// Evaluate against a correlation chain rule ID.
    pub fn evaluate_chain(
        &mut self,
        chain_rule_id: &str,
        incident: &Incident,
    ) -> Option<PlaybookExecution> {
        let now = Utc::now();

        for playbook in &self.playbooks {
            if playbook.trigger.chain_rule.is_empty()
                || playbook.trigger.chain_rule != chain_rule_id
            {
                continue;
            }

            if let Some(&last) = self.cooldowns.get(&playbook.id) {
                if now - last < self.cooldown_duration {
                    continue;
                }
            }

            self.cooldowns.insert(playbook.id.clone(), now);

            info!(
                playbook = %playbook.id,
                chain = chain_rule_id,
                "chain-triggered playbook"
            );

            let steps: Vec<StepResult> = playbook
                .steps
                .iter()
                .map(|step| StepResult {
                    action: step.action.clone(),
                    status: "pending".to_string(),
                    detail: format!("params: {:?}", step.params),
                })
                .collect();

            return Some(PlaybookExecution {
                playbook_id: playbook.id.clone(),
                playbook_name: playbook.name.clone(),
                incident_id: incident.incident_id.clone(),
                triggered_at: now,
                steps,
                overall_status: "pending".to_string(),
            });
        }

        None
    }

    /// Number of loaded playbooks.
    #[allow(dead_code)]
    pub fn playbook_count(&self) -> usize {
        self.playbooks.len()
    }
}

// ---------------------------------------------------------------------------
// Trigger matching
// ---------------------------------------------------------------------------

fn matches_trigger(trigger: &PlaybookTrigger, detector: &str, severity: &Severity) -> bool {
    // Check detector match
    if !trigger.detector.is_empty() && trigger.detector != detector {
        return false;
    }

    // Check minimum severity
    let min_rank = severity_rank_str(&trigger.min_severity);
    let incident_rank = severity_rank(severity);
    if incident_rank < min_rank {
        return false;
    }

    true
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

fn severity_rank_str(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn load_playbooks(rules_dir: &Path) -> Vec<Playbook> {
    let playbooks_dir = rules_dir.join("playbooks");
    let entries = match std::fs::read_dir(&playbooks_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut playbooks = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".toml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<PlaybookFile>(&content) {
                Ok(file) => {
                    for (id, pb) in file.playbook {
                        playbooks.push(Playbook {
                            id: id.clone(),
                            name: pb.name.unwrap_or(id),
                            trigger: pb.trigger,
                            steps: pb.steps,
                            run_in_dry_run: pb.run_in_dry_run.unwrap_or(false),
                        });
                    }
                }
                Err(e) => warn!(path = %path.display(), "failed to parse playbook: {e}"),
            },
            Err(e) => warn!(path = %path.display(), "failed to read playbook: {e}"),
        }
    }

    playbooks
}

#[derive(Deserialize)]
struct PlaybookFile {
    playbook: HashMap<String, PlaybookDef>,
}

#[derive(Deserialize)]
struct PlaybookDef {
    name: Option<String>,
    trigger: PlaybookTrigger,
    steps: Vec<PlaybookStep>,
    run_in_dry_run: Option<bool>,
}

// ---------------------------------------------------------------------------
// Built-in playbooks
// ---------------------------------------------------------------------------

fn builtin_playbooks() -> Vec<Playbook> {
    vec![
        Playbook {
            id: "pb-ransomware".into(),
            name: "Ransomware Response".into(),
            trigger: PlaybookTrigger {
                detector: "ransomware".into(),
                min_severity: "high".into(),
                chain_rule: String::new(),
            },
            steps: vec![
                PlaybookStep {
                    action: "capture_forensics".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "kill_process".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "block_ip".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack".into())]
                        .into_iter()
                        .collect(),
                },
            ],
            run_in_dry_run: false,
        },
        Playbook {
            id: "pb-reverse-shell".into(),
            name: "Reverse Shell Response".into(),
            trigger: PlaybookTrigger {
                detector: "reverse_shell".into(),
                min_severity: "critical".into(),
                chain_rule: String::new(),
            },
            steps: vec![
                PlaybookStep {
                    action: "kill_process".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "block_ip".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "capture_forensics".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack".into())]
                        .into_iter()
                        .collect(),
                },
            ],
            run_in_dry_run: false,
        },
        Playbook {
            id: "pb-data-exfil".into(),
            name: "Data Exfiltration Response".into(),
            trigger: PlaybookTrigger {
                detector: "data_exfil_ebpf".into(),
                min_severity: "critical".into(),
                chain_rule: String::new(),
            },
            steps: vec![
                PlaybookStep {
                    action: "block_ip".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "kill_process".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack".into())]
                        .into_iter()
                        .collect(),
                },
                PlaybookStep {
                    action: "escalate".into(),
                    params: [("to".into(), "critical".into())].into_iter().collect(),
                },
            ],
            run_in_dry_run: false,
        },
        Playbook {
            id: "pb-malware-yara".into(),
            name: "Malware Detection Response".into(),
            trigger: PlaybookTrigger {
                detector: "yara_scan".into(),
                min_severity: "high".into(),
                chain_rule: String::new(),
            },
            steps: vec![
                PlaybookStep {
                    action: "kill_process".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "quarantine_file".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "capture_forensics".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack,webhook".into())]
                        .into_iter()
                        .collect(),
                },
            ],
            run_in_dry_run: false,
        },
        // Chain-triggered playbooks
        Playbook {
            id: "pb-chain-recon-exfil".into(),
            name: "Recon-to-Exfil Chain Response".into(),
            trigger: PlaybookTrigger {
                detector: String::new(),
                min_severity: "high".into(),
                chain_rule: "CL-002".into(),
            },
            steps: vec![
                PlaybookStep {
                    action: "block_ip".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "capture_forensics".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "isolate_network".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack,webhook".into())]
                        .into_iter()
                        .collect(),
                },
            ],
            run_in_dry_run: false,
        },
        Playbook {
            id: "pb-chain-firmware-rootkit".into(),
            name: "Firmware-to-Rootkit Chain Response".into(),
            trigger: PlaybookTrigger {
                detector: String::new(),
                min_severity: "critical".into(),
                chain_rule: "CL-001".into(),
            },
            steps: vec![
                PlaybookStep {
                    action: "capture_forensics".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "isolate_network".into(),
                    params: HashMap::new(),
                },
                PlaybookStep {
                    action: "notify".into(),
                    params: [("channels".into(), "telegram,slack,webhook".into())]
                        .into_iter()
                        .collect(),
                },
                PlaybookStep {
                    action: "escalate".into(),
                    params: [
                        ("to".into(), "critical".into()),
                        (
                            "note".into(),
                            "firmware compromise requires physical investigation".into(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
            ],
            run_in_dry_run: true, // Always run forensics even in dry-run
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_incident(detector: &str, severity: Severity) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: format!("{detector}:test:2026-03-29"),
            severity,
            title: format!("{detector} test"),
            summary: String::new(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("10.0.0.1")],
        }
    }

    #[test]
    fn builtin_playbooks_load() {
        let engine = PlaybookEngine::new(Path::new("/nonexistent"));
        assert!(engine.playbook_count() >= 6);
    }

    #[test]
    fn ransomware_playbook_triggers() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("ransomware", Severity::High);
        let exec = engine.evaluate(&incident);
        assert!(exec.is_some());
        let exec = exec.unwrap();
        assert_eq!(exec.playbook_id, "pb-ransomware");
        assert_eq!(exec.steps.len(), 4);
        assert_eq!(exec.steps[0].action, "capture_forensics");
        assert_eq!(exec.steps[1].action, "kill_process");
    }

    #[test]
    fn reverse_shell_playbook_triggers() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("reverse_shell", Severity::Critical);
        let exec = engine.evaluate(&incident);
        assert!(exec.is_some());
        assert_eq!(exec.unwrap().playbook_id, "pb-reverse-shell");
    }

    #[test]
    fn low_severity_does_not_trigger() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("ransomware", Severity::Low);
        assert!(engine.evaluate(&incident).is_none());
    }

    #[test]
    fn unmatched_detector_does_not_trigger() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("ssh_bruteforce", Severity::Critical);
        // No built-in playbook for ssh_bruteforce
        let exec = engine.evaluate(&incident);
        // Might match a chain playbook but not a detector one
        assert!(exec.is_none() || exec.unwrap().playbook_id.contains("chain"));
    }

    #[test]
    fn cooldown_prevents_retrigger() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("ransomware", Severity::Critical);
        assert!(engine.evaluate(&incident).is_some());
        assert!(engine.evaluate(&incident).is_none()); // cooldown
    }

    #[test]
    fn chain_triggered_playbook() {
        let mut engine = PlaybookEngine::new(Path::new("/nonexistent"));
        let incident = make_incident("data_exfiltration", Severity::Critical);
        let exec = engine.evaluate_chain("CL-002", &incident);
        assert!(exec.is_some());
        assert_eq!(exec.unwrap().playbook_id, "pb-chain-recon-exfil");
    }

    #[test]
    fn trigger_matching() {
        let trigger = PlaybookTrigger {
            detector: "ransomware".into(),
            min_severity: "high".into(),
            chain_rule: String::new(),
        };
        assert!(matches_trigger(&trigger, "ransomware", &Severity::Critical));
        assert!(matches_trigger(&trigger, "ransomware", &Severity::High));
        assert!(!matches_trigger(&trigger, "ransomware", &Severity::Medium));
        assert!(!matches_trigger(
            &trigger,
            "ssh_bruteforce",
            &Severity::Critical
        ));
    }

    #[test]
    fn empty_detector_matches_any() {
        let trigger = PlaybookTrigger {
            detector: String::new(),
            min_severity: "critical".into(),
            chain_rule: String::new(),
        };
        assert!(matches_trigger(&trigger, "anything", &Severity::Critical));
        assert!(!matches_trigger(&trigger, "anything", &Severity::High));
    }
}
