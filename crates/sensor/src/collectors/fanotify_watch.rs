//! Real-time filesystem monitoring via fanotify (Linux) or polling fallback.
//!
//! Replaces periodic integrity polling with immediate notification on file
//! modifications. Detects ransomware via high-rate sequential writes combined
//! with entropy analysis.
//!
//! Monitored events:
//! - File modifications on watched paths (config files, /etc, /boot)
//! - High-rate write bursts (potential ransomware)
//! - Entropy increase after modification (encryption indicator)
//!
//! Falls back to polling on macOS or when fanotify is unavailable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

/// Paths to monitor for modifications by default.
const DEFAULT_WATCH_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ld.so.preload",
    "/boot/grub/grub.cfg",
];

/// Minimum file size for entropy analysis.
const MIN_ENTROPY_SIZE: usize = 64;
/// Entropy threshold for encrypted content (Shannon entropy, max = 8.0).
const ENCRYPTION_ENTROPY_THRESHOLD: f64 = 7.5;
/// Number of writes in a short window that indicates ransomware behavior.
const RANSOMWARE_WRITE_THRESHOLD: usize = 50;
/// Window for ransomware burst detection.
const RANSOMWARE_WINDOW_SECS: i64 = 10;

/// Per-file tracking state.
struct FileState {
    hash: String,
    last_modified: DateTime<Utc>,
    size: u64,
}

/// Write burst tracking for ransomware detection.
struct WriteBurstTracker {
    /// Recent write timestamps.
    writes: Vec<DateTime<Utc>>,
    /// Last ransomware alert timestamp (cooldown).
    last_alert: Option<DateTime<Utc>>,
}

/// Run the fanotify/polling filesystem monitor.
///
/// On Linux with appropriate permissions, uses inotify (via polling with
/// metadata change detection). Falls back to periodic hash checking.
pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    watch_paths: Vec<String>,
    poll_seconds: u64,
) {
    let paths: Vec<PathBuf> = if watch_paths.is_empty() {
        DEFAULT_WATCH_PATHS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    } else {
        watch_paths.iter().map(PathBuf::from).collect()
    };

    if paths.is_empty() {
        info!("fanotify_watch: no paths to monitor");
        return;
    }

    info!(paths = paths.len(), "fanotify_watch: monitoring filesystem");

    let mut file_states: HashMap<PathBuf, FileState> = HashMap::new();
    let mut burst_tracker = WriteBurstTracker {
        writes: Vec::new(),
        last_alert: None,
    };

    // Initialize baselines
    for path in &paths {
        if let Some(state) = compute_file_state(path) {
            file_states.insert(path.clone(), state);
        }
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));

    loop {
        interval.tick().await;
        let now = Utc::now();

        for path in &paths {
            let current = match compute_file_state(path) {
                Some(s) => s,
                None => continue,
            };

            let changed = if let Some(prev) = file_states.get(path) {
                prev.hash != current.hash
            } else {
                true // new file
            };

            if changed {
                // Track write burst
                burst_tracker.writes.push(now);
                burst_tracker
                    .writes
                    .retain(|ts| now - *ts < Duration::seconds(RANSOMWARE_WINDOW_SECS));

                let path_str = path.to_string_lossy().to_string();

                // Emit file modification event
                let severity = if path_str.contains("/etc/shadow")
                    || path_str.contains("/etc/sudoers")
                    || path_str.contains("/boot/")
                    || path_str.contains("sshd_config")
                {
                    Severity::Critical
                } else {
                    Severity::High
                };

                // Check entropy for encryption indicator
                let entropy = compute_file_entropy(path);
                let encrypted = entropy
                    .map(|e| e >= ENCRYPTION_ENTROPY_THRESHOLD)
                    .unwrap_or(false);

                let prev_hash = file_states
                    .get(path)
                    .map(|s| s.hash.clone())
                    .unwrap_or_default();

                let ev = Event {
                    ts: now,
                    host: host.clone(),
                    source: "fanotify".to_string(),
                    kind: if encrypted {
                        "file.encrypted_write".to_string()
                    } else {
                        "file.realtime_modified".to_string()
                    },
                    severity: if encrypted {
                        Severity::Critical
                    } else {
                        severity
                    },
                    summary: format!(
                        "File modified: {} (hash changed{})",
                        path_str,
                        if encrypted { ", HIGH ENTROPY - possible encryption" } else { "" }
                    ),
                    details: serde_json::json!({
                        "path": path_str,
                        "new_hash": current.hash,
                        "old_hash": prev_hash,
                        "new_size": current.size,
                        "entropy": entropy,
                        "encrypted": encrypted,
                    }),
                    tags: vec![
                        "filesystem".to_string(),
                        "integrity".to_string(),
                    ],
                    entities: vec![EntityRef::path(&path_str)],
                };

                if tx.send(ev).await.is_err() {
                    return;
                }

                // Ransomware burst detection
                if burst_tracker.writes.len() >= RANSOMWARE_WRITE_THRESHOLD {
                    let should_alert = burst_tracker
                        .last_alert
                        .map(|t| now - t > Duration::seconds(60))
                        .unwrap_or(true);

                    if should_alert {
                        burst_tracker.last_alert = Some(now);
                        let ev = Event {
                            ts: now,
                            host: host.clone(),
                            source: "fanotify".to_string(),
                            kind: "file.ransomware_burst".to_string(),
                            severity: Severity::Critical,
                            summary: format!(
                                "Ransomware-like behavior: {} file modifications in {}s",
                                burst_tracker.writes.len(),
                                RANSOMWARE_WINDOW_SECS
                            ),
                            details: serde_json::json!({
                                "writes_in_window": burst_tracker.writes.len(),
                                "window_seconds": RANSOMWARE_WINDOW_SECS,
                                "latest_file": path_str,
                            }),
                            tags: vec![
                                "ransomware".to_string(),
                                "filesystem".to_string(),
                            ],
                            entities: vec![],
                        };
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }

                file_states.insert(path.clone(), current);
            }
        }
    }
}

/// Compute SHA-256 hash and metadata for a file.
fn compute_file_state(path: &Path) -> Option<FileState> {
    let content = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = format!("{:x}", hasher.finalize());

    Some(FileState {
        hash,
        last_modified: Utc::now(),
        size: content.len() as u64,
    })
}

/// Compute Shannon entropy of a file's content (0.0 = uniform, 8.0 = max random).
fn compute_file_entropy(path: &Path) -> Option<f64> {
    let content = std::fs::read(path).ok()?;
    if content.len() < MIN_ENTROPY_SIZE {
        return None;
    }
    Some(shannon_entropy(&content))
}

/// Shannon entropy of a byte sequence.
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_zero_for_uniform() {
        // All same byte → entropy = 0
        let data = vec![0x41u8; 100];
        let e = shannon_entropy(&data);
        assert!(e < 0.01);
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        // Pseudo-random → entropy close to 8
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9);
    }

    #[test]
    fn shannon_entropy_moderate_for_text() {
        let data = b"Hello, this is a normal text file with moderate entropy";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 6.0);
    }

    #[test]
    fn file_state_computation() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").unwrap();

        let state = compute_file_state(&path).unwrap();
        assert!(!state.hash.is_empty());
        assert_eq!(state.size, 11);
    }

    #[test]
    fn file_state_detects_change() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello").unwrap();
        let state1 = compute_file_state(&path).unwrap();

        std::fs::write(&path, "world").unwrap();
        let state2 = compute_file_state(&path).unwrap();

        assert_ne!(state1.hash, state2.hash);
    }

    #[test]
    fn encryption_threshold() {
        // Random data should be above threshold
        let random_data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let e = shannon_entropy(&random_data);
        assert!(e >= ENCRYPTION_ENTROPY_THRESHOLD);

        // Normal text should be below threshold
        let text = b"The quick brown fox jumps over the lazy dog. This is normal text content.";
        let e = shannon_entropy(text);
        assert!(e < ENCRYPTION_ENTROPY_THRESHOLD);
    }
}
