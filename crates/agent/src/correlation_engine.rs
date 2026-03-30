//! Cross-Layer Correlation Engine.
//!
//! Correlates events across all layers (firmware, kernel/eBPF, userspace,
//! network, honeypot) to detect multi-stage attack chains that no single
//! detector can see. Uses a rule-based pattern matching engine with entity
//! pivoting and configurable time windows.
//!
//! Example chain: CL-004 MSR Write → Process Injection → Log Tampering
//! Each stage produces an event in a different layer; the engine connects
//! them via shared entities (PID, IP, user) within a time window.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Which system layer produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Firmware,
    Kernel,
    Userspace,
    Network,
    Honeypot,
}

/// A normalized event for cross-layer correlation.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationEvent {
    pub ts: DateTime<Utc>,
    pub layer: Layer,
    pub source: String,
    pub kind: String,
    pub severity: Severity,
    pub entities: Vec<EntityRef>,
    pub details: serde_json::Value,
}

/// A detected multi-stage attack chain.
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub chain_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub start_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
    pub events: Vec<CorrelationEvent>,
    pub stages_matched: usize,
    pub stages_total: usize,
    pub confidence: f32,
    pub layers_involved: Vec<Layer>,
    pub severity: Severity,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/// A correlation rule defines a multi-stage pattern to detect.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub stages: Vec<RuleStage>,
    /// Maximum seconds between first and last stage event.
    pub window_secs: u64,
    /// Minimum confidence to emit the chain as an incident.
    pub min_confidence: f32,
    /// Override severity when chain is detected.
    pub severity: Severity,
}

/// One stage in a correlation rule.
#[derive(Debug, Clone)]
pub struct RuleStage {
    /// Required layer (None = any layer).
    pub layer: Option<Layer>,
    /// Event kind patterns to match (glob-style: "firmware.*", "ssh_bruteforce").
    pub kind_patterns: Vec<String>,
    /// If true, this stage must share at least one entity with the previous stage.
    pub entity_must_match: bool,
}

/// Tracks an in-progress chain match.
#[derive(Debug, Clone)]
struct PendingChain {
    rule_id: String,
    matched_events: Vec<CorrelationEvent>,
    matched_entities: HashSet<String>,
    next_stage: usize,
    started_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The cross-layer correlation engine.
pub struct CorrelationEngine {
    /// Sliding window of recent events (all layers).
    event_window: VecDeque<CorrelationEvent>,
    /// Maximum events to retain in the window.
    max_window_size: usize,
    /// In-progress chain matches.
    pending_chains: Vec<PendingChain>,
    /// Completed chains (drained by the caller).
    completed_chains: Vec<AttackChain>,
    /// Correlation rules.
    rules: Vec<CorrelationRule>,
    /// Cooldown: avoid re-emitting the same chain within N seconds.
    chain_cooldowns: HashMap<String, DateTime<Utc>>,
    /// Chain ID counter.
    next_chain_id: u64,
}

impl CorrelationEngine {
    /// Create a new engine with the built-in rule set.
    pub fn new() -> Self {
        Self {
            event_window: VecDeque::with_capacity(10_000),
            max_window_size: 10_000,
            pending_chains: Vec::new(),
            completed_chains: Vec::new(),
            rules: builtin_rules(),
            chain_cooldowns: HashMap::new(),
            next_chain_id: 1,
        }
    }

    /// Feed a new event into the engine.
    ///
    /// Checks all pending chains and starts new chains if the event matches
    /// the first stage of any rule.
    pub fn observe(&mut self, event: CorrelationEvent) {
        let now = event.ts;

        // Expire old pending chains
        self.pending_chains.retain(|pc| pc.expires_at > now);

        // Expire old cooldowns
        self.chain_cooldowns.retain(|_, expires| *expires > now);

        // Try to advance existing pending chains
        let mut newly_completed = Vec::new();
        for pc in &mut self.pending_chains {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            if pc.next_stage >= rule.stages.len() {
                continue;
            }

            let stage = &rule.stages[pc.next_stage];

            if matches_stage(stage, &event, &pc.matched_entities) {
                pc.matched_events.push(event.clone());
                // Add all entity values to the set for next-stage matching
                for entity in &event.entities {
                    pc.matched_entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }
                pc.next_stage += 1;

                // Check if chain is complete
                if pc.next_stage >= rule.stages.len() {
                    newly_completed.push(pc.clone());
                }
            }
        }

        // Emit completed chains
        for pc in newly_completed {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            // Cooldown check: same rule + same primary entity
            let cooldown_key = format!(
                "{}:{}",
                pc.rule_id,
                pc.matched_entities.iter().next().unwrap_or(&String::new())
            );
            if self.chain_cooldowns.contains_key(&cooldown_key) {
                continue;
            }

            let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
            self.next_chain_id += 1;

            let layers: Vec<Layer> = pc
                .matched_events
                .iter()
                .map(|e| e.layer)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let confidence = if layers.len() >= 3 {
                0.95
            } else if layers.len() >= 2 {
                0.85
            } else {
                0.70
            };

            let start_ts = pc.matched_events.first().map(|e| e.ts).unwrap_or(now);
            let last_ts = pc.matched_events.last().map(|e| e.ts).unwrap_or(now);

            let summary = format!(
                "{}: {} stages across {} layers in {}s",
                rule.name,
                pc.matched_events.len(),
                layers.len(),
                (last_ts - start_ts).num_seconds()
            );

            info!(
                chain_id = %chain_id,
                rule = %rule.id,
                stages = pc.matched_events.len(),
                layers = layers.len(),
                "attack chain detected: {}",
                rule.name
            );

            self.completed_chains.push(AttackChain {
                chain_id,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                start_ts,
                last_ts,
                events: pc.matched_events,
                stages_matched: rule.stages.len(),
                stages_total: rule.stages.len(),
                confidence,
                layers_involved: layers,
                severity: rule.severity.clone(),
                summary,
            });

            // Set cooldown (10 minutes for same rule + entity)
            self.chain_cooldowns
                .insert(cooldown_key, now + chrono::Duration::seconds(600));

            // Remove the completed pending chain
            self.pending_chains
                .retain(|p| p.rule_id != pc.rule_id || p.started_at != pc.started_at);
        }

        // Try to start new chains (event matches first stage of a rule)
        for rule in &self.rules {
            let first_stage = &rule.stages[0];
            if matches_stage(first_stage, &event, &HashSet::new()) {
                let mut entities = HashSet::new();
                for entity in &event.entities {
                    entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }

                self.pending_chains.push(PendingChain {
                    rule_id: rule.id.clone(),
                    matched_events: vec![event.clone()],
                    matched_entities: entities,
                    next_stage: 1,
                    started_at: now,
                    expires_at: now + chrono::Duration::seconds(rule.window_secs as i64),
                });
            }
        }

        // Add to event window
        self.event_window.push_back(event);
        while self.event_window.len() > self.max_window_size {
            self.event_window.pop_front();
        }
    }

    /// Drain completed attack chains. Caller should convert these to incidents.
    pub fn drain_completed(&mut self) -> Vec<AttackChain> {
        std::mem::take(&mut self.completed_chains)
    }

    /// Number of pending (in-progress) chains.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending_chains.len()
    }

    /// Number of rules loaded.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Convert an Event from the sensor into a CorrelationEvent.
    pub fn classify_event(event: &innerwarden_core::event::Event) -> CorrelationEvent {
        let layer = classify_layer(&event.source, &event.kind);
        CorrelationEvent {
            ts: event.ts,
            layer,
            source: event.source.clone(),
            kind: event.kind.clone(),
            severity: event.severity.clone(),
            entities: event.entities.clone(),
            details: event.details.clone(),
        }
    }

    /// Convert an Incident into a CorrelationEvent (using the detector kind).
    pub fn classify_incident(incident: &Incident) -> CorrelationEvent {
        let detector = crate::mitre::detector_from_incident_id(&incident.incident_id);
        let layer = classify_layer("detector", detector);
        CorrelationEvent {
            ts: incident.ts,
            layer,
            source: "detector".to_string(),
            kind: detector.to_string(),
            severity: incident.severity.clone(),
            entities: incident.entities.clone(),
            details: incident.evidence.clone(),
        }
    }

    /// Create a CorrelationEvent from SMM firmware scan results.
    #[allow(dead_code)]
    pub fn firmware_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Firmware,
            source: "smm".to_string(),
            kind: kind.to_string(),
            severity: Severity::High,
            entities: vec![],
            details,
        }
    }
}

// ---------------------------------------------------------------------------
// Matching logic
// ---------------------------------------------------------------------------

fn matches_stage(
    stage: &RuleStage,
    event: &CorrelationEvent,
    previous_entities: &HashSet<String>,
) -> bool {
    // Layer check
    if let Some(required_layer) = stage.layer {
        if event.layer != required_layer {
            return false;
        }
    }

    // Kind pattern check (any pattern matching = success)
    let kind_match = stage.kind_patterns.iter().any(|pattern| {
        if pattern.contains('*') {
            // Glob match: "firmware.*" matches "firmware.msr_write"
            let prefix = pattern.trim_end_matches('*');
            event.kind.starts_with(prefix)
        } else if pattern.contains('|') {
            // OR match: "ssh_bruteforce|credential_stuffing"
            pattern.split('|').any(|p| event.kind == p.trim())
        } else {
            event.kind == *pattern
        }
    });

    if !kind_match {
        return false;
    }

    // Entity matching (if required and previous entities exist)
    if stage.entity_must_match && !previous_entities.is_empty() {
        let current_entities: HashSet<String> = event
            .entities
            .iter()
            .map(|e| format!("{}:{}", entity_type_str(&e.r#type), e.value))
            .collect();

        if current_entities.is_disjoint(previous_entities) {
            return false;
        }
    }

    true
}

fn entity_type_str(et: &EntityType) -> &'static str {
    match et {
        EntityType::Ip => "ip",
        EntityType::User => "user",
        EntityType::Container => "container",
        EntityType::Path => "path",
        EntityType::Service => "service",
    }
}

fn classify_layer(source: &str, kind: &str) -> Layer {
    // Check firmware first (most specific)
    if source == "smm"
        || kind.starts_with("firmware.")
        || kind.contains("msr")
        || kind.contains("acpi")
        || kind.contains("uefi")
        || kind.contains("tpm")
        || kind.contains("spi")
    {
        Layer::Firmware
    // Network before Kernel (eBPF can produce network events)
    } else if kind.starts_with("network.")
        || kind.starts_with("dns.")
        || kind.contains("outbound")
        || kind.contains("bind_listen")
    {
        Layer::Network
    } else if kind.starts_with("honeypot") {
        Layer::Honeypot
    } else if source == "ebpf"
        || kind.starts_with("privilege.")
        || kind.starts_with("lsm.")
        || kind == "kernel_module_load"
        || kind.starts_with("dup.")
        || kind == "mprotect"
    {
        Layer::Kernel
    } else {
        Layer::Userspace
    }
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

fn builtin_rules() -> Vec<CorrelationRule> {
    vec![
        // CL-001: Firmware → Privilege Escalation → Rootkit Module
        CorrelationRule {
            id: "CL-001".into(),
            name: "Firmware to Rootkit Chain".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["kernel_module_load".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-002: Recon → Access → Exfil
        CorrelationRule {
            id: "CL-002".into(),
            name: "Recon to Exfiltration Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["port_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["ssh_bruteforce|credential_stuffing".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["data_exfiltration|outbound_anomaly".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-003: Honeypot → Real Attack
        CorrelationRule {
            id: "CL-003".into(),
            name: "Honeypot to Real Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Honeypot),
                    kind_patterns: vec!["honeypot*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "ssh.*".into(),
                        "network.*".into(),
                        "ssh_bruteforce".into(),
                        "credential_stuffing".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-004: MSR Write → Injection → Log Tampering
        CorrelationRule {
            id: "CL-004".into(),
            name: "MSR Write to Log Tampering".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.msr*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into(), "process_injection".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["log_tampering".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-005: Container Escape → Host Execution → Privesc
        CorrelationRule {
            id: "CL-005".into(),
            name: "Container Escape to Host".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["container_drift".into(), "container_escape".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["shell.command_exec".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-006: Fileless Attack
        CorrelationRule {
            id: "CL-006".into(),
            name: "Fileless Malware Chain".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["fileless".into(), "memfd_create".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["mprotect".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-007: Reverse Shell via eBPF sequence
        CorrelationRule {
            id: "CL-007".into(),
            name: "Reverse Shell (eBPF Sequence)".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["dup.redirect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 10,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-008: Data Exfiltration via eBPF sequence
        CorrelationRule {
            id: "CL-008".into(),
            name: "Data Exfiltration (eBPF Sequence)".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.read_access".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 60,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-009: Silence After Compromise
        // Note: this rule is special — handled by the silence detector
        // in baseline.rs, not by the stage-matching engine.
        // Placeholder here for documentation.
        CorrelationRule {
            id: "CL-009".into(),
            name: "Silence After Compromise".into(),
            stages: vec![RuleStage {
                layer: None,
                kind_patterns: vec!["__silence_placeholder__".into()],
                entity_must_match: false,
            }],
            window_secs: 300,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-010: Multi-Low Elevation
        // Also special — handled by custom logic below, not stage matching.
        CorrelationRule {
            id: "CL-010".into(),
            name: "Multi-Low Severity Elevation".into(),
            stages: vec![RuleStage {
                layer: None,
                kind_patterns: vec!["__multi_low_placeholder__".into()],
                entity_must_match: false,
            }],
            window_secs: 600,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // ── Additional rules (CL-011 to CL-023) ──────────────────────

        // CL-011: Credential theft → Lateral movement
        CorrelationRule {
            id: "CL-011".into(),
            name: "Credential Theft to Lateral Movement".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["credential_harvest".into(), "file.read_access".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_movement".into(), "ssh_key_injection".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-012: Persistence installation chain
        CorrelationRule {
            id: "CL-012".into(),
            name: "Multi-Persistence Installation".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["crontab_persistence".into(), "systemd_persistence".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["ssh_key_injection".into(), "user_creation".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-013: Web shell deployment chain
        CorrelationRule {
            id: "CL-013".into(),
            name: "Web Shell Deployment".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.write_access".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_shell".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-014: Cryptominer deployment
        CorrelationRule {
            id: "CL-014".into(),
            name: "Cryptominer Deployment Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "shell.command_exec".into(),
                        "network.outbound_connect".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["crypto_miner".into(), "cgroup.cpu_abuse".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-015: Log tampering after compromise
        CorrelationRule {
            id: "CL-015".into(),
            name: "Post-Compromise Log Tampering".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "privilege.escalation".into(),
                        "reverse_shell".into(),
                        "ssh_bruteforce".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["log_tampering".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-016: TPM measurement failure → later attack
        CorrelationRule {
            id: "CL-016".into(),
            name: "TPM Integrity Failure Followed by Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.efivar*".into(), "firmware.acpi*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "ransomware".into(),
                        "rootkit".into(),
                        "reverse_shell".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 172800, // 48 hours
            min_confidence: 0.6,
            severity: Severity::Critical,
        },
        // CL-017: io_uring evasion (high io_uring with low visible I/O)
        CorrelationRule {
            id: "CL-017".into(),
            name: "io_uring Evasion Detection".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["io_uring*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 60,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-018: eBPF weaponization chain
        CorrelationRule {
            id: "CL-018".into(),
            name: "eBPF Program Weaponization".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["kernel.bpf_program_loaded".into(), "lsm.bpf*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["privilege.escalation".into(), "process_injection".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-019: Memory injection chain (RWX + connect)
        CorrelationRule {
            id: "CL-019".into(),
            name: "Memory Injection to C2".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["memory.rwx*".into(), "memory.anon*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 120,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-020: Docker image pull → lateral movement
        CorrelationRule {
            id: "CL-020".into(),
            name: "Container as Lateral Movement Vector".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["docker*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["shell.command_exec".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-021: Ransomware chain (encryption detection + file burst)
        CorrelationRule {
            id: "CL-021".into(),
            name: "Ransomware Encryption Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "file.encrypted_write".into(),
                        "file.ransomware_burst".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.realtime_modified".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 60,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-022: YARA match → network callback
        CorrelationRule {
            id: "CL-022".into(),
            name: "Malware Execution with C2 Callback".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["yara_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into(), "c2_callback".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-023: Sigma rule match + privilege escalation
        CorrelationRule {
            id: "CL-023".into(),
            name: "Sigma Alert Escalated by Privilege Change".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["sigma".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // -----------------------------------------------------------------
        // Gym-discovered rules (adversarial RL training insights)
        // -----------------------------------------------------------------
        // CL-024: Fast recon→exploit→exfil chain (gym top pattern)
        // Attacker learned: web exploit is faster than SSH brute force,
        // and short chains (3-5 steps) succeed most often.
        CorrelationRule {
            id: "CL-024".into(),
            name: "Gym: Fast Web Exploit to Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["port_scan".into(), "web_scan".into(), "user_agent_scanner".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["web_shell".into(), "web_scan".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["data_exfiltration".into(), "outbound_anomaly".into(), "dns_tunneling".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300, // 5 min — gym showed short chains are most dangerous
            min_confidence: 0.95,
            severity: Severity::Critical,
        },
        // CL-025: Service enumeration → exploit (gym: ServiceEnum passes undetected 72%)
        // Catches nmap -sV → vulnerability exploitation pattern
        CorrelationRule {
            id: "CL-025".into(),
            name: "Gym: Service Enumeration to Exploitation".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["port_scan".into(), "user_agent_scanner".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "web_shell".into(),
                        "reverse_shell".into(),
                        "ssh_bruteforce".into(),
                        "credential_stuffing".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // CL-026: DNS recon → exfiltration (gym: DnsRecon 73% undetected)
        // Attacker uses DNS for both recon and data exfiltration
        CorrelationRule {
            id: "CL-026".into(),
            name: "Gym: DNS Recon to Data Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["dns_tunneling".into(), "port_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["data_exfiltration".into(), "data_exfil_ebpf".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 900,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-027: Multi-vector initial access (gym: attacker tries web + SSH simultaneously)
        // Same IP attempts both web exploit and SSH brute force
        CorrelationRule {
            id: "CL-027".into(),
            name: "Gym: Multi-Vector Initial Access Attempt".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["ssh_bruteforce".into(), "credential_stuffing".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["web_scan".into(), "web_shell".into(), "user_agent_scanner".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::High,
        },
    ]
}

impl CorrelationEngine {
    /// Check for Multi-Low elevation: 3+ different Low detectors for the same
    /// IP within 600 seconds should elevate to High.
    ///
    /// Called after observe(). Returns an AttackChain if the threshold is met.
    pub fn check_multi_low_elevation(&mut self) -> Option<AttackChain> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(600);

        // Group recent low-severity events by IP
        let mut ip_detectors: HashMap<String, Vec<CorrelationEvent>> = HashMap::new();
        for event in &self.event_window {
            if event.ts < cutoff {
                continue;
            }
            if event.severity != Severity::Low {
                continue;
            }
            for entity in &event.entities {
                if entity.r#type == EntityType::Ip {
                    ip_detectors
                        .entry(entity.value.clone())
                        .or_default()
                        .push(event.clone());
                }
            }
        }

        for (ip, events) in &ip_detectors {
            let unique_kinds: HashSet<&str> = events.iter().map(|e| e.kind.as_str()).collect();
            if unique_kinds.len() >= 3 {
                let cooldown_key = format!("CL-010:ip:{ip}");
                if self.chain_cooldowns.contains_key(&cooldown_key) {
                    continue;
                }

                let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
                self.next_chain_id += 1;

                let summary = format!(
                    "Multi-vector reconnaissance from {}: {} different low-severity detectors in 10 minutes ({})",
                    ip,
                    unique_kinds.len(),
                    unique_kinds.into_iter().collect::<Vec<_>>().join(", ")
                );

                info!(chain_id = %chain_id, ip = %ip, "CL-010 multi-low elevation");

                self.chain_cooldowns
                    .insert(cooldown_key, now + chrono::Duration::seconds(600));

                return Some(AttackChain {
                    chain_id,
                    rule_id: "CL-010".into(),
                    rule_name: "Multi-Low Severity Elevation".into(),
                    start_ts: events.first().map(|e| e.ts).unwrap_or(now),
                    last_ts: events.last().map(|e| e.ts).unwrap_or(now),
                    events: events.clone(),
                    stages_matched: events.len(),
                    stages_total: events.len(),
                    confidence: 0.75,
                    layers_involved: events
                        .iter()
                        .map(|e| e.layer)
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect(),
                    severity: Severity::High,
                    summary,
                });
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_event(layer: Layer, kind: &str, ip: &str) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer,
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
        }
    }

    fn make_event_at(layer: Layer, kind: &str, ip: &str, ts: DateTime<Utc>) -> CorrelationEvent {
        CorrelationEvent {
            ts,
            layer,
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
        }
    }

    #[test]
    fn engine_starts_empty() {
        let engine = CorrelationEngine::new();
        assert_eq!(engine.rule_count(), 27);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn single_event_starts_pending_chain() {
        let mut engine = CorrelationEngine::new();
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        engine.observe(ev);

        // Should have started CL-001 and CL-004 (both start with firmware.*)
        assert!(engine.pending_count() >= 1);
        assert!(engine.drain_completed().is_empty());
    }

    #[test]
    fn complete_chain_cl002_recon_to_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Stage 1: port_scan
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        let _ = engine.drain_completed(); // may trigger partial matches

        // Stage 2: ssh_bruteforce (same IP)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        let _ = engine.drain_completed(); // CL-025 may trigger here

        // Stage 3: data_exfiltration (same IP)
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));

        let chains = engine.drain_completed();
        assert!(chains.iter().any(|c| c.rule_id == "CL-002"),
            "expected CL-002 in {:?}", chains.iter().map(|c| &c.rule_id).collect::<Vec<_>>());
    }

    #[test]
    fn chain_requires_entity_match() {
        let mut engine = CorrelationEngine::new();

        // Stage 1: port_scan from IP A
        engine.observe(make_event(Layer::Network, "port_scan", "10.0.0.1"));

        // Stage 2: ssh_bruteforce from IP B (different IP — should NOT advance CL-002)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.2"));

        // Stage 3: data_exfiltration from IP B
        engine.observe(make_event(Layer::Network, "data_exfiltration", "10.0.0.2"));

        // CL-002 should NOT complete (IP mismatch between stage 1 and 2)
        let chains = engine.drain_completed();
        assert!(chains.iter().all(|c| c.rule_id != "CL-002"));
    }

    #[test]
    fn chain_expires_after_window() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";
        let now = Utc::now();

        // Stage 1 at T=0
        engine.observe(make_event_at(Layer::Network, "port_scan", ip, now));

        // Stage 2 at T=2000s (beyond CL-002 window of 1800s)
        let later = now + chrono::Duration::seconds(2000);
        engine.observe(make_event_at(Layer::Userspace, "ssh_bruteforce", ip, later));

        // Pending chain should have expired
        // New chain started from stage 2, but stage 3 not met
        let chains = engine.drain_completed();
        assert!(chains.is_empty());
    }

    #[test]
    fn multi_low_elevation() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // 3 different low-severity detectors for the same IP
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Userspace, "user_agent_scanner", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Network, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_some());
        let chain = chain.unwrap();
        assert_eq!(chain.rule_id, "CL-010");
        assert_eq!(chain.severity, Severity::High);
    }

    #[test]
    fn multi_low_needs_3_different_kinds() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Same kind twice + one different = only 2 unique kinds
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Network, "port_scan", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Userspace, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_none());
    }

    #[test]
    fn classify_layer_firmware() {
        assert_eq!(classify_layer("smm", "firmware.check"), Layer::Firmware);
        assert_eq!(
            classify_layer("sensor", "firmware.msr_write"),
            Layer::Firmware
        );
    }

    #[test]
    fn classify_layer_kernel() {
        assert_eq!(
            classify_layer("ebpf", "privilege.escalation"),
            Layer::Kernel
        );
    }

    #[test]
    fn classify_layer_network() {
        assert_eq!(
            classify_layer("ebpf", "network.outbound_connect"),
            Layer::Network
        );
    }

    #[test]
    fn classify_layer_honeypot() {
        assert_eq!(classify_layer("honeypot", "honeypot_ssh"), Layer::Honeypot);
    }

    #[test]
    fn cooldown_prevents_duplicate_chains() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Complete CL-002 first time (may also trigger CL-025)
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        let chains = engine.drain_completed();
        assert!(!chains.is_empty(), "expected at least CL-002");
        assert!(chains.iter().any(|c| c.rule_id == "CL-002"));

        // Try same sequence again — should be suppressed by cooldown
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        assert_eq!(engine.drain_completed().len(), 0);
    }

    #[test]
    fn glob_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["firmware.*".into()],
            entity_must_match: false,
        };
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        assert!(matches_stage(&stage, &ev, &HashSet::new()));

        let ev2 = make_event(Layer::Kernel, "privilege.escalation", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev2, &HashSet::new()));
    }

    #[test]
    fn or_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["ssh_bruteforce|credential_stuffing".into()],
            entity_must_match: false,
        };
        let ev1 = make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.1");
        assert!(matches_stage(&stage, &ev1, &HashSet::new()));

        let ev2 = make_event(Layer::Userspace, "credential_stuffing", "10.0.0.1");
        assert!(matches_stage(&stage, &ev2, &HashSet::new()));

        let ev3 = make_event(Layer::Userspace, "port_scan", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev3, &HashSet::new()));
    }
}
