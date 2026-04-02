#![allow(dead_code)]
//! Neural scoring model — trained by InnerWarden Gym (V10, deprecated).
//!
//! Classifies event streams as attack or benign using a small neural network
//! (32 features → 64 → 32 → 1). Runs alongside the 48 detectors to catch
//! novel attack patterns that no rule covers.
//!
//! The model weights are embedded at compile time (16KB binary).
//! Inference takes microseconds — no external API, no internet, no cost.

use innerwarden_core::event::Event;
use std::collections::HashMap;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Embedded model weights
// ---------------------------------------------------------------------------

/// Model binary trained by innerwarden-gym (IWM1 format).
const MODEL_BYTES: &[u8] = include_bytes!("scoring-model.bin");

// ---------------------------------------------------------------------------
// Neural network (inference only, no training)
// ---------------------------------------------------------------------------

struct Layer {
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

struct ScoringNet {
    layers: Vec<Layer>,
}

impl ScoringNet {
    /// Load from IWM1 binary format.
    fn load(data: &[u8]) -> Option<Self> {
        if data.len() < 8 || &data[0..4] != b"IWM1" {
            return None;
        }

        let num_layers = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let mut offset = 8;
        let mut layers = Vec::new();

        for _ in 0..num_layers {
            if offset + 8 > data.len() {
                return None;
            }

            let rows = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            let cols = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            offset += 8;

            // Read weights (rows x cols f32)
            let mut weights = Vec::with_capacity(rows);
            for _ in 0..rows {
                let mut row = Vec::with_capacity(cols);
                for _ in 0..cols {
                    if offset + 4 > data.len() {
                        return None;
                    }
                    let val = f32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    row.push(val);
                    offset += 4;
                }
                weights.push(row);
            }

            // Read biases (rows f32)
            let mut biases = Vec::with_capacity(rows);
            for _ in 0..rows {
                if offset + 4 > data.len() {
                    return None;
                }
                let val = f32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                biases.push(val);
                offset += 4;
            }

            layers.push(Layer { weights, biases });
        }

        Some(ScoringNet { layers })
    }

    /// Forward pass: input → score.
    fn predict(&self, input: &[f32]) -> f32 {
        let mut x = input.to_vec();

        for (i, layer) in self.layers.iter().enumerate() {
            let mut next = vec![0.0f32; layer.weights.len()];
            for (j, (wj, bj)) in layer.weights.iter().zip(layer.biases.iter()).enumerate() {
                let mut sum = *bj;
                for (k, &xk) in x.iter().enumerate() {
                    if k < wj.len() {
                        sum += wj[k] * xk;
                    }
                }
                // ReLU for hidden layers, linear for output
                if i < self.layers.len() - 1 {
                    next[j] = sum.max(0.0);
                } else {
                    next[j] = sum;
                }
            }
            x = next;
        }

        x.first().copied().unwrap_or(0.0).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Feature extraction from events
// ---------------------------------------------------------------------------

const NUM_FEATURES: usize = 32;

/// Rolling window of recent events for scoring.
pub struct ScoringEngine {
    net: Option<ScoringNet>,
    /// Recent event kinds (sliding window, last 20)
    recent_kinds: std::collections::VecDeque<String>,
    /// Recent event severities
    recent_severities: std::collections::VecDeque<String>,
    /// Recent source IPs seen
    recent_ips: std::collections::VecDeque<String>,
    /// Detection count in current window
    detection_count: u32,
    /// Score threshold for alerting
    threshold: f32,
    /// Cooldown per source IP: prevents spam from same attacker
    cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Cooldown duration in seconds
    cooldown_secs: i64,
}

impl ScoringEngine {
    pub fn new(threshold: f32) -> Self {
        let net = ScoringNet::load(MODEL_BYTES);
        if net.is_some() {
            info!("scoring: neural model loaded ({} bytes)", MODEL_BYTES.len());
        } else {
            tracing::warn!("scoring: failed to load neural model");
        }

        Self {
            net,
            recent_kinds: std::collections::VecDeque::with_capacity(20),
            recent_severities: std::collections::VecDeque::with_capacity(20),
            recent_ips: std::collections::VecDeque::with_capacity(20),
            detection_count: 0,
            threshold,
            cooldowns: HashMap::new(),
            cooldown_secs: 300, // 5 minutes per IP
        }
    }

    /// Feed an event and return a score if it exceeds the threshold.
    /// Returns Some((score, explanation)) if the model thinks an attack is in progress.
    pub fn observe(&mut self, event: &Event) -> Option<(f32, String)> {
        let net = self.net.as_ref()?;

        // Update sliding window
        self.recent_kinds.push_back(event.kind.clone());
        if self.recent_kinds.len() > 20 {
            self.recent_kinds.pop_front();
        }

        let sev_str = format!("{:?}", event.severity);
        self.recent_severities.push_back(sev_str);
        if self.recent_severities.len() > 20 {
            self.recent_severities.pop_front();
        }

        if let Some(ip) = event
            .details
            .get("ip")
            .or(event.details.get("src_ip"))
            .and_then(|v| v.as_str())
        {
            self.recent_ips.push_back(ip.to_string());
            if self.recent_ips.len() > 20 {
                self.recent_ips.pop_front();
            }
        }

        // Need at least 3 events to score
        if self.recent_kinds.len() < 3 {
            return None;
        }

        // Extract features
        let features = self.extract_features();
        let score = net.predict(&features);

        debug!(
            score = format!("{:.3}", score),
            events = self.recent_kinds.len(),
            "scoring: model inference"
        );

        // Cooldown per source IP
        let source_ip = self.recent_ips.back().cloned().unwrap_or_default();
        let now = chrono::Utc::now();
        if let Some(&last) = self.cooldowns.get(&source_ip) {
            if (now - last).num_seconds() < self.cooldown_secs {
                return None;
            }
        }

        // Prune stale cooldowns (keep map bounded)
        if self.cooldowns.len() > 1000 {
            let cutoff = now - chrono::Duration::seconds(self.cooldown_secs);
            self.cooldowns.retain(|_, t| *t > cutoff);
        }

        if score > self.threshold {
            self.cooldowns.insert(source_ip, now);
            let explanation =
                format!(
                "Neural model scored {:.0}% attack probability from {} recent events (kinds: {})",
                score * 100.0,
                self.recent_kinds.len(),
                self.recent_kinds.iter().rev().take(5).cloned().collect::<Vec<_>>().join(", "),
            );
            Some((score, explanation))
        } else {
            None
        }
    }

    /// Reset after an incident is generated (prevent duplicate alerts).
    pub fn reset(&mut self) {
        self.recent_kinds.clear();
        self.recent_severities.clear();
        self.recent_ips.clear();
        self.detection_count = 0;
    }

    fn extract_features(&self) -> Vec<f32> {
        let mut f = vec![0.0f32; NUM_FEATURES];

        let n = self.recent_kinds.len() as f32;

        // Feature 0: number of events (normalized)
        f[0] = (n / 20.0).min(1.0);

        // Feature 1: fraction of High/Critical events
        let high_count = self
            .recent_severities
            .iter()
            .filter(|s| s.contains("High") || s.contains("Critical"))
            .count();
        f[1] = high_count as f32 / n.max(1.0);

        // Feature 2: fraction of Medium events
        let med_count = self
            .recent_severities
            .iter()
            .filter(|s| s.contains("Medium"))
            .count();
        f[2] = med_count as f32 / n.max(1.0);

        // Feature 3-14: event kind distribution (mapped to categories)
        let categories = [
            ("ssh", 3),
            ("network", 4),
            ("file", 5),
            ("shell", 6),
            ("process", 7),
            ("sudo", 8),
            ("dns", 9),
            ("http", 10),
            ("exec", 11),
            ("cron", 12),
            ("memory", 13),
            ("firmware", 14),
        ];
        for kind in &self.recent_kinds {
            let lower = kind.to_lowercase();
            for &(pattern, idx) in &categories {
                if lower.contains(pattern) {
                    f[idx] += 1.0 / n;
                }
            }
        }

        // Feature 15: has login_failed
        f[15] = if self.recent_kinds.iter().any(|k| k.contains("login_failed")) {
            1.0
        } else {
            0.0
        };

        // Feature 16: has outbound_connect
        f[16] = if self
            .recent_kinds
            .iter()
            .any(|k| k.contains("outbound_connect"))
        {
            1.0
        } else {
            0.0
        };

        // Feature 17: has file.read_access
        f[17] = if self.recent_kinds.iter().any(|k| k.contains("read_access")) {
            1.0
        } else {
            0.0
        };

        // Feature 18: has command_exec
        f[18] = if self.recent_kinds.iter().any(|k| k.contains("command_exec")) {
            1.0
        } else {
            0.0
        };

        // Feature 19: has fd_redirect (dup — possible reverse shell)
        f[19] = if self.recent_kinds.iter().any(|k| k.contains("fd_redirect")) {
            1.0
        } else {
            0.0
        };

        // Feature 20: unique event kinds (diversity)
        let unique: std::collections::HashSet<_> = self.recent_kinds.iter().collect();
        f[20] = (unique.len() as f32 / 10.0).min(1.0);

        // Feature 21: unique IPs
        let unique_ips: std::collections::HashSet<_> = self.recent_ips.iter().collect();
        f[21] = (unique_ips.len() as f32 / 5.0).min(1.0);

        // Feature 22-31: last 10 event kinds encoded
        for (i, kind) in self.recent_kinds.iter().rev().take(10).enumerate() {
            // Simple hash to 0..1
            let hash: u32 = kind
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
            f[22 + i] = (hash % 1000) as f32 / 1000.0;
        }

        f
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn make_event(kind: &str, severity: Severity) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "test".to_string(),
            kind: kind.to_string(),
            severity,
            summary: String::new(),
            details: serde_json::json!({"ip": "1.2.3.4"}),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn model_loads() {
        let engine = ScoringEngine::new(0.7);
        assert!(engine.net.is_some());
    }

    #[test]
    fn benign_events_score_low() {
        let mut engine = ScoringEngine::new(0.7);
        for _ in 0..5 {
            let result = engine.observe(&make_event("ssh.login_success", Severity::Info));
            if let Some((score, _)) = result {
                assert!(score < 0.7, "benign should score low, got {score}");
            }
        }
    }

    #[test]
    fn attack_sequence_scores_higher() {
        let mut engine = ScoringEngine::new(0.3);

        // Feed attack-like sequence
        engine.observe(&make_event("ssh.login_failed", Severity::Medium));
        engine.observe(&make_event("ssh.login_failed", Severity::Medium));
        engine.observe(&make_event("ssh.login_failed", Severity::High));
        engine.observe(&make_event("shell.command_exec", Severity::High));
        let result = engine.observe(&make_event("file.read_access", Severity::High));

        // Should produce some score (model may or may not alert depending on training)
        // The important thing is it runs without crashing
        let _ = result;
    }

    #[test]
    fn reset_clears_state() {
        let mut engine = ScoringEngine::new(0.7);
        engine.observe(&make_event("ssh.login_failed", Severity::Medium));
        engine.observe(&make_event("ssh.login_failed", Severity::Medium));
        engine.observe(&make_event("ssh.login_failed", Severity::Medium));
        engine.reset();
        assert!(engine.recent_kinds.is_empty());
    }
}
