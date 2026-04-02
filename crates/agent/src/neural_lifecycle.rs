//! Neural anomaly detection lifecycle — Phase 1: autoencoder + rules as teacher.
//!
//! The autoencoder learns "what is normal" for this specific host by training
//! on production events. Novel patterns get high anomaly scores.
//!
//! Lifecycle:
//!   Install → Observation (7 days) → Nightly training → Auto-test → Activation
//!
//! Scoring integration:
//!   final_score = rules(0.4) + killchain(0.3) + anomaly(0.3 × maturity)
//!
//! The rules/killchain act as "teacher": if they say an event is benign but the
//! autoencoder flagged it, the autoencoder learns that pattern is normal.

use innerwarden_core::event::Event;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Feature extraction (mirrored from innerwarden-gym/src/realdata.rs)
// ---------------------------------------------------------------------------

const NUM_FEATURES: usize = 48;
const WINDOW_SIZE: usize = 20;

/// Map event kind to feature index (0-23).
fn kind_index(kind: &str) -> Option<usize> {
    match kind {
        "file.read_access" => Some(0),
        "shell.command_exec" => Some(1),
        "process.exit" => Some(2),
        "process.fd_redirect" => Some(3),
        "process.clone" => Some(4),
        "io_uring.create" => Some(5),
        "firmware.timing_anomaly" => Some(6),
        "network.outbound_connect" => Some(7),
        "sudo.command" => Some(8),
        "network.accept" => Some(9),
        "file.write_access" => Some(10),
        "process.prctl" => Some(11),
        "cgroup.memory_spike" => Some(12),
        "ssh.login_success" => Some(13),
        "ssh.login_failed" => Some(14),
        "memory.rwx_memory" => Some(15),
        "file.timestomp" => Some(16),
        "file.truncate" => Some(17),
        "dns.query" => Some(18),
        "privilege.escalation" => Some(19),
        "process.memfd_create" => Some(20),
        "kernel.new_module_post_boot" => Some(21),
        "filesystem.mount" => Some(22),
        "network.listen" => Some(23),
        _ => None,
    }
}

/// Attack-indicative bigram transitions.
const ATTACK_BIGRAMS: &[(usize, usize, usize)] = &[
    (14, 13, 24), // ssh_failed → ssh_success
    (13, 1, 25),  // ssh_success → shell_exec
    (1, 0, 26),   // shell_exec → file_read
    (0, 7, 27),   // file_read → outbound_connect
    (1, 7, 28),   // shell_exec → outbound_connect
    (8, 0, 29),   // sudo → file_read
    (1, 16, 30),  // shell_exec → timestomp
    (1, 17, 31),  // shell_exec → truncate
    (3, 1, 32),   // fd_redirect → shell_exec
    (19, 1, 33),  // privesc → shell_exec
    (1, 20, 34),  // shell_exec → memfd_create
    (7, 7, 35),   // outbound → outbound (beaconing)
    (1, 1, 36),   // shell → shell (recon burst)
    (21, 1, 37),  // module_load → shell_exec
    (23, 9, 38),  // listen → accept
    (4, 3, 39),   // clone → fd_redirect
];

/// Extract 48 features from a window of event kinds.
fn window_features(kinds: &[Option<usize>]) -> Vec<f32> {
    let mut f = vec![0.0f32; NUM_FEATURES];
    let n = kinds.len() as f32;
    if n == 0.0 {
        return f;
    }

    // Layer 1: kind distribution [0-23]
    for &idx in kinds {
        if let Some(i) = idx {
            f[i] += 1.0 / n;
        }
    }

    // Layer 2: bigram transitions [24-39]
    let n_trans = if kinds.len() > 1 {
        (kinds.len() - 1) as f32
    } else {
        1.0
    };
    for i in 0..kinds.len().saturating_sub(1) {
        if let (Some(from), Some(to)) = (kinds[i], kinds[i + 1]) {
            for &(bf, bt, slot) in ATTACK_BIGRAMS {
                if from == bf && to == bt {
                    f[slot] += 1.0 / n_trans;
                }
            }
        }
    }

    // Layer 3: sequence signals [40-47]

    // 40: kind diversity
    let unique: std::collections::HashSet<_> = kinds.iter().filter_map(|x| *x).collect();
    f[40] = (unique.len() as f32 / 12.0).min(1.0);

    // 41: transition entropy
    {
        let mut bigram_counts = std::collections::HashMap::new();
        let mut total = 0u32;
        for i in 0..kinds.len().saturating_sub(1) {
            if let (Some(from), Some(to)) = (kinds[i], kinds[i + 1]) {
                *bigram_counts.entry((from, to)).or_insert(0u32) += 1;
                total += 1;
            }
        }
        if total > 0 {
            let mut entropy = 0.0f32;
            for &count in bigram_counts.values() {
                let p = count as f32 / total as f32;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            f[41] = (entropy / 9.2).min(1.0);
        }
    }

    // 42: longest consecutive same-kind run
    {
        let mut max_run = 1u32;
        let mut current = 1u32;
        for i in 1..kinds.len() {
            if kinds[i] == kinds[i - 1] && kinds[i].is_some() {
                current += 1;
                max_run = max_run.max(current);
            } else {
                current = 1;
            }
        }
        f[42] = (max_run as f32 / n).min(1.0);
    }

    // 43: has sensitive file read (based on kind index 0 = file.read_access presence)
    // In agent, we only have kind indices — full summary check needs Event objects.
    // Approximation: file.read_access after ssh.login_success = credential harvesting signal
    f[43] = if kinds
        .windows(2)
        .any(|w| w[0] == Some(13) && w[1] == Some(0))
    {
        1.0
    } else {
        0.0
    };

    // 44: kill chain stage progression (how many distinct stages appear in order)
    {
        let mut stages_seen = 0u32;
        let mut last_stage = 0u32;
        for &idx in kinds {
            let stage = match idx {
                Some(14) => 1,            // ssh_failed = recon
                Some(13) => 2,            // ssh_success = access
                Some(1) => 3,             // shell_exec = execution
                Some(10) => 4,            // file_write = persistence
                Some(8) | Some(19) => 5,  // sudo/privesc = escalation
                Some(16) | Some(17) => 6, // timestomp/truncate = evasion
                Some(7) => 7,             // outbound = exfiltration
                _ => 0,
            };
            if stage > 0 && stage > last_stage {
                stages_seen += 1;
                last_stage = stage;
            }
        }
        f[44] = (stages_seen as f32 / 7.0).min(1.0);
    }

    // 45: command diversity (approximated by unique kinds in shell-heavy windows)
    let shell_ratio = kinds.iter().filter(|&&k| k == Some(1)).count() as f32 / n;
    f[45] = shell_ratio.min(1.0);

    // 46: network listener present
    f[46] = if kinds.iter().any(|&k| k == Some(23) || k == Some(9)) {
        1.0
    } else {
        0.0
    };

    // 47: window size normalized
    f[47] = (n / 50.0).min(1.0);

    f
}

// ---------------------------------------------------------------------------
// Autoencoder (inference + training, no external deps)
// ---------------------------------------------------------------------------

/// Simple feedforward layer.
struct Layer {
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

/// Autoencoder neural network [48 → 16 → 8 → 16 → 48].
struct AutoencoderNet {
    layers: Vec<Layer>,
    lr: f32,
}

impl AutoencoderNet {
    /// Initialize with deterministic pseudo-random Xavier weights.
    /// Uses a simple LCG to avoid external rand dependency.
    fn new(layer_sizes: &[usize], lr: f32) -> Self {
        let mut seed: u64 = 42;
        let mut next_f32 = move || -> f32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            // Map to [-1, 1]
            ((seed >> 33) as f32 / (1u64 << 31) as f32) * 2.0 - 1.0
        };

        let mut layers = Vec::new();
        for i in 0..layer_sizes.len() - 1 {
            let fan_in = layer_sizes[i];
            let fan_out = layer_sizes[i + 1];
            let scale = (2.0 / (fan_in + fan_out) as f32).sqrt();

            let weights: Vec<Vec<f32>> = (0..fan_out)
                .map(|_| (0..fan_in).map(|_| next_f32() * scale).collect())
                .collect();
            let biases = vec![0.0f32; fan_out];

            layers.push(Layer { weights, biases });
        }

        Self { layers, lr }
    }

    /// Load from IWAE binary format.
    fn load(data: &[u8]) -> Option<Self> {
        if data.len() < 24 || &data[0..4] != b"IWAE" {
            return None;
        }
        // Skip header: magic(4) + version(4) + baseline_mse(4) + baseline_std(4) + samples(8)
        let net_len = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
        let net_json = &data[28..28 + net_len];

        // Parse the JSON-serialized network
        let net: serde_json::Value = serde_json::from_slice(net_json).ok()?;
        let weights_arr = net.get("weights")?.as_array()?;
        let biases_arr = net.get("biases")?.as_array()?;
        let lr = net.get("lr").and_then(|v| v.as_f64()).unwrap_or(0.001) as f32;

        let mut layers = Vec::new();
        for (w, b) in weights_arr.iter().zip(biases_arr.iter()) {
            let weights: Vec<Vec<f32>> = w
                .as_array()?
                .iter()
                .map(|row| {
                    row.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                        .collect()
                })
                .collect();
            let biases: Vec<f32> = b
                .as_array()?
                .iter()
                .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                .collect();
            layers.push(Layer { weights, biases });
        }

        Some(Self { layers, lr })
    }

    /// Forward pass.
    fn forward(&self, input: &[f32]) -> (Vec<f32>, Vec<Vec<f32>>) {
        let mut activations = vec![input.to_vec()];
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
                if i < self.layers.len() - 1 {
                    next[j] = sum.max(0.0); // ReLU
                } else {
                    next[j] = sum; // Linear output
                }
            }
            x = next;
            activations.push(x.clone());
        }

        (x, activations)
    }

    fn predict(&self, input: &[f32]) -> Vec<f32> {
        self.forward(input).0
    }

    /// Train one step: reconstruct input, backpropagate error.
    fn train_reconstruction(&mut self, input: &[f32]) {
        let (output, activations) = self.forward(input);

        let mut deltas: Vec<f32> = output
            .iter()
            .zip(input.iter())
            .map(|(o, t)| o - t)
            .collect();

        for layer_idx in (0..self.layers.len()).rev() {
            let act_input = &activations[layer_idx];
            let act_output = &activations[layer_idx + 1];

            if layer_idx < self.layers.len() - 1 {
                for (j, d) in deltas.iter_mut().enumerate() {
                    if act_output[j] <= 0.0 {
                        *d = 0.0;
                    }
                }
            }

            let mut prev_deltas = vec![0.0f32; act_input.len()];
            for j in 0..self.layers[layer_idx].weights.len() {
                for k in 0..self.layers[layer_idx].weights[j].len() {
                    prev_deltas[k] += self.layers[layer_idx].weights[j][k] * deltas[j];
                    self.layers[layer_idx].weights[j][k] -= self.lr * deltas[j] * act_input[k];
                }
                self.layers[layer_idx].biases[j] -= self.lr * deltas[j];
            }

            deltas = prev_deltas;
        }
    }

    /// Reconstruction error (MSE).
    fn reconstruction_error(&self, input: &[f32]) -> f32 {
        let output = self.predict(input);
        input
            .iter()
            .zip(output.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            / input.len() as f32
    }
}

// ---------------------------------------------------------------------------
// Public API: AnomalyEngine
// ---------------------------------------------------------------------------

/// Configuration for the neural anomaly engine.
pub struct AnomalyConfig {
    /// Data directory (reads events JSONL, writes model)
    pub data_dir: PathBuf,
    /// Score threshold for anomaly alerts (0.0-1.0)
    pub threshold: f32,
    /// Max training time in seconds
    pub training_timeout_secs: u64,
    /// Max RAM for training in MB
    pub training_max_ram_mb: u64,
    /// Days of event data to use for training
    pub training_retention_days: u32,
    /// Training epochs per session
    pub training_epochs: u64,
    /// How often to train (cron-style, e.g., "0 3 * * *")
    pub training_schedule: String,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/innerwarden"),
            threshold: 0.5,
            training_timeout_secs: 1800, // 30 min
            training_max_ram_mb: 500,
            training_retention_days: 7,
            training_epochs: 50,
            training_schedule: "0 3 * * *".to_string(),
        }
    }
}

/// The anomaly detection engine — integrates into the agent's event loop.
pub struct AnomalyEngine {
    net: Option<AutoencoderNet>,
    /// Sliding window of recent event kind indices.
    window: VecDeque<Option<usize>>,
    /// Baseline MSE from training (what "normal" looks like).
    baseline_mse: f32,
    /// Baseline standard deviation.
    baseline_std: f32,
    /// Maturity: 0.0 (just installed) → 1.0 (fully trained).
    /// Increases with each successful training cycle.
    pub maturity: f32,
    /// Number of training cycles completed.
    pub training_cycles: u32,
    /// Configuration.
    config: AnomalyConfig,
    /// Cooldown per source to prevent spam.
    cooldowns: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
}

impl AnomalyEngine {
    /// Create a new anomaly engine, attempting to load a saved model.
    pub fn new(config: AnomalyConfig) -> Self {
        let model_path = config.data_dir.join("anomaly-model.bin");
        let (net, baseline_mse, baseline_std, maturity, cycles) = if let Ok(data) =
            std::fs::read(&model_path)
        {
            let net = AutoencoderNet::load(&data);
            let mse = if data.len() >= 12 {
                f32::from_le_bytes([data[8], data[9], data[10], data[11]])
            } else {
                0.0
            };
            let std = if data.len() >= 16 {
                f32::from_le_bytes([data[12], data[13], data[14], data[15]])
            } else {
                1.0
            };
            let samples = if data.len() >= 24 {
                u64::from_le_bytes([
                    data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
                ])
            } else {
                0
            };
            // Estimate maturity from samples seen
            let mat = (samples as f32 / 500_000.0).min(1.0);
            let cyc = (samples / 100_000) as u32;
            if net.is_some() {
                info!(
                    "anomaly: loaded model ({} bytes, baseline MSE {:.6}, maturity {:.2})",
                    data.len(),
                    mse,
                    mat
                );
            }
            (net, mse, std, mat, cyc)
        } else {
            info!("anomaly: no saved model found, starting fresh (observation mode)");
            (None, 0.0, 1.0, 0.0, 0)
        };

        Self {
            net,
            window: VecDeque::with_capacity(WINDOW_SIZE),
            baseline_mse,
            baseline_std,
            maturity,
            training_cycles: cycles,
            config,
            cooldowns: std::collections::HashMap::new(),
        }
    }

    /// Feed an event and return anomaly score if above threshold.
    /// Returns Some((score, weight)) where weight = score × maturity.
    pub fn observe(&mut self, event: &Event) -> Option<(f32, f32)> {
        let idx = kind_index(&event.kind);

        // Update sliding window
        self.window.push_back(idx);
        if self.window.len() > WINDOW_SIZE {
            self.window.pop_front();
        }

        // Need full window to score
        if self.window.len() < WINDOW_SIZE {
            return None;
        }

        // Need a trained model
        let net = self.net.as_ref()?;

        // No maturity = no contribution
        if self.maturity < 0.01 {
            return None;
        }

        let kinds: Vec<Option<usize>> = self.window.iter().copied().collect();
        let features = window_features(&kinds);
        let mse = net.reconstruction_error(&features);

        // Normalize to 0-1 via z-score + sigmoid
        let z = if self.baseline_std > 0.0 {
            (mse - self.baseline_mse) / self.baseline_std
        } else {
            if mse > self.baseline_mse {
                3.0
            } else {
                -3.0
            }
        };
        let score = 1.0 / (1.0 + (-z).exp());
        let weighted = score * self.maturity * 0.3; // max contribution = 0.3

        debug!(
            score = format!("{:.3}", score),
            weighted = format!("{:.3}", weighted),
            maturity = format!("{:.2}", self.maturity),
            mse = format!("{:.6}", mse),
            "anomaly: inference"
        );

        if score > self.config.threshold {
            // Cooldown check
            let source = event
                .details
                .get("ip")
                .or(event.details.get("src_ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let now = chrono::Utc::now();
            if let Some(&last) = self.cooldowns.get(&source) {
                if (now - last).num_seconds() < 300 {
                    return None;
                }
            }
            self.cooldowns.insert(source, now);

            // Prune cooldowns
            if self.cooldowns.len() > 500 {
                let cutoff = now - chrono::Duration::seconds(300);
                self.cooldowns.retain(|_, t| *t > cutoff);
            }

            Some((score, weighted))
        } else {
            None
        }
    }

    /// Run nightly training on recent events.
    /// Reads events JSONL from data_dir, trains autoencoder, saves model.
    pub fn train_nightly(&mut self) -> Result<(), String> {
        let start = std::time::Instant::now();
        info!("anomaly: starting nightly training");

        // Check disk space
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("df")
                .arg("-h")
                .arg(self.config.data_dir.to_str().unwrap_or("/"))
                .output()
            {
                let out = String::from_utf8_lossy(&output.stdout);
                if out.contains("100%")
                    || out.contains("99%")
                    || out.contains("98%")
                    || out.contains("97%")
                    || out.contains("96%")
                {
                    warn!("anomaly: disk nearly full, skipping training");
                    return Err("disk full".to_string());
                }
            }
        }

        // Collect events from JSONL files (last N days)
        let cutoff =
            chrono::Utc::now() - chrono::Duration::days(self.config.training_retention_days as i64);
        let mut all_kinds: Vec<Vec<Option<usize>>> = Vec::new();

        let events_dir = &self.config.data_dir;
        let entries = std::fs::read_dir(events_dir).map_err(|e| e.to_string())?;

        let mut total_events = 0u64;
        let mut event_window: Vec<Option<usize>> = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.starts_with("events-") || !name.ends_with(".jsonl") {
                continue;
            }

            // Check RAM budget (rough estimate: 48 floats × 4 bytes × windows)
            let estimated_mb = (all_kinds.len() * NUM_FEATURES * 4) / (1024 * 1024);
            if estimated_mb > self.config.training_max_ram_mb as usize {
                info!("anomaly: RAM budget reached ({}MB), sampling", estimated_mb);
                break;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                let ev: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let kind = ev.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let idx = kind_index(kind);

                event_window.push(idx);
                total_events += 1;

                if event_window.len() >= WINDOW_SIZE {
                    all_kinds.push(event_window.clone());
                    // Stride of 5
                    event_window.drain(..5);
                }

                // Timeout check
                if start.elapsed().as_secs() > self.config.training_timeout_secs {
                    warn!("anomaly: training timeout, using data collected so far");
                    break;
                }
            }
        }

        info!(
            "anomaly: loaded {} events → {} windows for training",
            total_events,
            all_kinds.len()
        );

        if all_kinds.len() < 100 {
            warn!("anomaly: not enough data for training (need 100+ windows)");
            return Err("insufficient data".to_string());
        }

        // Extract features
        let features: Vec<Vec<f32>> = all_kinds.iter().map(|w| window_features(w)).collect();

        // Create or reinitialize network
        let mut net = AutoencoderNet::new(&[NUM_FEATURES, 16, 8, 16, NUM_FEATURES], 0.001);

        // Train
        for epoch in 1..=self.config.training_epochs {
            for f in &features {
                net.train_reconstruction(f);
            }

            if start.elapsed().as_secs() > self.config.training_timeout_secs {
                info!("anomaly: timeout at epoch {}", epoch);
                break;
            }

            if epoch % 10 == 0 {
                let avg_mse: f32 = features
                    .iter()
                    .map(|f| net.reconstruction_error(f))
                    .sum::<f32>()
                    / features.len() as f32;
                info!(
                    "anomaly: epoch {}/{} MSE {:.6}",
                    epoch, self.config.training_epochs, avg_mse
                );
            }
        }

        // Compute baseline
        let errors: Vec<f32> = features
            .iter()
            .map(|f| net.reconstruction_error(f))
            .collect();
        let n = errors.len() as f32;
        let baseline_mse = errors.iter().sum::<f32>() / n;
        let variance = errors
            .iter()
            .map(|e| (e - baseline_mse).powi(2))
            .sum::<f32>()
            / n;
        let baseline_std = variance.sqrt();

        self.baseline_mse = baseline_mse;
        self.baseline_std = baseline_std;
        self.net = Some(net);
        self.training_cycles += 1;

        // Update maturity (increases with each training cycle, maxes at 1.0)
        // Day 1: 0.1, Day 3: 0.3, Day 7: 0.6, Day 30: ~0.9
        self.maturity = (1.0 - (-0.1 * self.training_cycles as f32).exp()).min(1.0);

        info!(
            "anomaly: training complete in {:.1}s — baseline MSE {:.6} ± {:.6}, maturity {:.2}, cycles {}",
            start.elapsed().as_secs_f32(),
            baseline_mse,
            baseline_std,
            self.maturity,
            self.training_cycles
        );

        // Save model (keep previous as backup)
        let model_path = self.config.data_dir.join("anomaly-model.bin");
        let backup_path = self.config.data_dir.join("anomaly-model.prev.bin");
        if model_path.exists() {
            let _ = std::fs::rename(&model_path, &backup_path);
        }

        // Serialize (simple format: IWAE header + JSON weights)
        if let Some(ref net) = self.net {
            let mut data = Vec::new();
            data.extend_from_slice(b"IWAE");
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&self.baseline_mse.to_le_bytes());
            data.extend_from_slice(&self.baseline_std.to_le_bytes());
            let total_samples = total_events;
            data.extend_from_slice(&total_samples.to_le_bytes());

            // Serialize weights as JSON
            let weights: Vec<Vec<Vec<f32>>> =
                net.layers.iter().map(|l| l.weights.clone()).collect();
            let biases: Vec<Vec<f32>> = net.layers.iter().map(|l| l.biases.clone()).collect();
            let net_json = serde_json::json!({
                "weights": weights,
                "biases": biases,
                "lr": net.lr,
            });
            let net_bytes = serde_json::to_vec(&net_json).unwrap_or_default();
            data.extend_from_slice(&(net_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&net_bytes);

            if let Err(e) = std::fs::write(&model_path, &data) {
                warn!("anomaly: failed to save model: {}", e);
            } else {
                info!("anomaly: model saved ({} bytes)", data.len());
            }
        }

        Ok(())
    }

    /// Process feedback from rules: if rules say "benign" but we flagged it,
    /// record as false positive for next training cycle.
    pub fn feedback_benign(&mut self, _event: &Event) {
        // In Phase 1, feedback is implicit: the autoencoder trains on ALL
        // production events (which are mostly benign). Events that rules
        // don't flag as incidents are "benign by omission" and the autoencoder
        // learns their patterns in the next nightly cycle.
        //
        // Phase 2 will add explicit feedback recording.
    }

    /// Get the current maturity level description.
    pub fn maturity_description(&self) -> &str {
        match self.maturity {
            m if m < 0.01 => "observation (no model)",
            m if m < 0.2 => "learning (low confidence)",
            m if m < 0.5 => "training (moderate confidence)",
            m if m < 0.8 => "active (good confidence)",
            _ => "mature (high confidence)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_extraction_correct_size() {
        let kinds = vec![Some(1), Some(7), Some(0), None, Some(14)];
        let f = window_features(&kinds);
        assert_eq!(f.len(), NUM_FEATURES);
    }

    #[test]
    fn bigram_features_nonzero() {
        // ssh_failed → ssh_success should activate bigram feature 24
        let kinds = vec![Some(14), Some(13)];
        let f = window_features(&kinds);
        assert!(
            f[24] > 0.0,
            "bigram ssh_failed→ssh_success should be nonzero"
        );
    }

    #[test]
    fn kill_chain_stage_progression() {
        // Full kill chain: Recon → Access → Exec → Persist → Escalate → Evade → Exfil
        let kinds: Vec<Option<usize>> = vec![
            Some(14), // ssh_failed = stage 1 (recon)
            Some(14), // ssh_failed
            Some(13), // ssh_success = stage 2 (access)
            Some(1),  // shell_exec = stage 3 (execution)
            Some(1),  // shell_exec
            Some(10), // file_write = stage 4 (persistence)
            Some(8),  // sudo = stage 5 (escalation)
            Some(16), // timestomp = stage 6 (evasion)
            Some(7),  // outbound = stage 7 (exfiltration)
            Some(2),  // process_exit
        ];
        let f = window_features(&kinds);
        // Should detect at least 4 sequential stages
        assert!(
            f[44] >= 4.0 / 7.0,
            "kill chain progression should be detected: got {}",
            f[44]
        );
    }

    #[test]
    fn autoencoder_reconstruction() {
        let mut net = AutoencoderNet::new(&[NUM_FEATURES, 16, 8, 16, NUM_FEATURES], 0.01);
        let input = vec![0.5f32; NUM_FEATURES];

        let err_before = net.reconstruction_error(&input);
        for _ in 0..200 {
            net.train_reconstruction(&input);
        }
        let err_after = net.reconstruction_error(&input);

        assert!(
            err_after < err_before,
            "Error should decrease after training: {} → {}",
            err_before,
            err_after
        );
    }

    #[test]
    fn maturity_increases() {
        let config = AnomalyConfig {
            data_dir: PathBuf::from("/tmp/nonexistent"),
            ..Default::default()
        };
        let mut engine = AnomalyEngine::new(config);
        assert_eq!(engine.maturity, 0.0);

        // Simulate training cycles
        engine.training_cycles = 1;
        engine.maturity = (1.0 - (-0.1 * 1.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.0 && engine.maturity < 0.2);

        engine.training_cycles = 7;
        engine.maturity = (1.0 - (-0.1 * 7.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.4);

        engine.training_cycles = 30;
        engine.maturity = (1.0 - (-0.1 * 30.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.9);
    }
}
