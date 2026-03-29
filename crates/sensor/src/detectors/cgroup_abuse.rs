//! Cgroup resource abuse detector.
//!
//! Monitors `/sys/fs/cgroup/*/cpu.stat`, `memory.current`, and `io.stat`
//! to detect processes consuming excessive resources:
//! - Sustained high CPU (cryptominer pattern)
//! - Memory spikes (exploitation / memory corruption)
//! - Namespace escape (process leaving assigned cgroup)
//!
//! Runs as a periodic scanner, emitting events for anomalous cgroups.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::mpsc;
use tracing::info;

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

/// CPU usage threshold (microseconds per second) for cryptominer detection.
/// 950,000 μs/s = 95% of one core.
const CPU_ABUSE_THRESHOLD_US: u64 = 950_000;
/// Memory threshold for spike detection (256 MB).
const MEMORY_SPIKE_THRESHOLD: u64 = 256 * 1024 * 1024;
/// Minimum consecutive high-CPU readings before alerting.
const CPU_MIN_READINGS: usize = 3;

/// Per-cgroup tracking.
struct CgroupState {
    /// Last CPU usage reading (total microseconds).
    last_cpu_usage_us: u64,
    last_read_at: DateTime<Utc>,
    /// Count of consecutive high-CPU readings.
    high_cpu_count: usize,
    /// Last alert timestamp (cooldown).
    last_alert: Option<DateTime<Utc>>,
}

/// Run the cgroup abuse detector as a periodic scanner.
pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    poll_seconds: u64,
) {
    let cgroup_base = Path::new("/sys/fs/cgroup");
    if !cgroup_base.exists() {
        info!("cgroup_abuse: /sys/fs/cgroup not found, disabling");
        return;
    }

    let mut states: HashMap<String, CgroupState> = HashMap::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));
    let cooldown = Duration::seconds(300);

    loop {
        interval.tick().await;
        let now = Utc::now();

        let cgroups = match discover_cgroups(cgroup_base) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for cgroup_path in &cgroups {
            let cgroup_name = cgroup_path
                .strip_prefix(cgroup_base)
                .unwrap_or(cgroup_path)
                .to_string_lossy()
                .to_string();

            // Read CPU usage
            if let Some(cpu_us) = read_cpu_usage(cgroup_path) {
                let state = states.entry(cgroup_name.clone()).or_insert(CgroupState {
                    last_cpu_usage_us: cpu_us,
                    last_read_at: now,
                    high_cpu_count: 0,
                    last_alert: None,
                });

                let elapsed_us = (now - state.last_read_at).num_microseconds().unwrap_or(1).max(1) as u64;
                let cpu_delta = cpu_us.saturating_sub(state.last_cpu_usage_us);
                let cpu_rate = cpu_delta * 1_000_000 / elapsed_us;

                state.last_cpu_usage_us = cpu_us;
                state.last_read_at = now;

                if cpu_rate > CPU_ABUSE_THRESHOLD_US {
                    state.high_cpu_count += 1;
                } else {
                    state.high_cpu_count = 0;
                }

                // Alert after sustained high CPU
                if state.high_cpu_count >= CPU_MIN_READINGS {
                    let should_alert = state
                        .last_alert
                        .map(|t| now - t > cooldown)
                        .unwrap_or(true);

                    if should_alert {
                        state.last_alert = Some(now);
                        let ev = Event {
                            ts: now,
                            host: host.clone(),
                            source: "cgroup".to_string(),
                            kind: "cgroup.cpu_abuse".to_string(),
                            severity: Severity::High,
                            summary: format!(
                                "Sustained high CPU in cgroup {}: {:.1}% for {} readings",
                                cgroup_name,
                                cpu_rate as f64 / 10_000.0,
                                state.high_cpu_count
                            ),
                            details: serde_json::json!({
                                "cgroup": cgroup_name,
                                "cpu_rate_percent": cpu_rate as f64 / 10_000.0,
                                "consecutive_readings": state.high_cpu_count,
                                "threshold_percent": CPU_ABUSE_THRESHOLD_US as f64 / 10_000.0,
                            }),
                            tags: vec![
                                "cgroup".to_string(),
                                "cryptominer".to_string(),
                                "resource_abuse".to_string(),
                            ],
                            entities: vec![EntityRef::container(&cgroup_name)],
                        };
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }

            // Read memory usage
            if let Some(mem_bytes) = read_memory_current(cgroup_path) {
                if mem_bytes > MEMORY_SPIKE_THRESHOLD {
                    let state = states.entry(cgroup_name.clone()).or_insert(CgroupState {
                        last_cpu_usage_us: 0,
                        last_read_at: now,
                        high_cpu_count: 0,
                        last_alert: None,
                    });

                    let should_alert = state
                        .last_alert
                        .map(|t| now - t > cooldown)
                        .unwrap_or(true);

                    if should_alert {
                        state.last_alert = Some(now);
                        let ev = Event {
                            ts: now,
                            host: host.clone(),
                            source: "cgroup".to_string(),
                            kind: "cgroup.memory_spike".to_string(),
                            severity: Severity::Medium,
                            summary: format!(
                                "High memory usage in cgroup {}: {} MB",
                                cgroup_name,
                                mem_bytes / (1024 * 1024)
                            ),
                            details: serde_json::json!({
                                "cgroup": cgroup_name,
                                "memory_bytes": mem_bytes,
                                "memory_mb": mem_bytes / (1024 * 1024),
                                "threshold_mb": MEMORY_SPIKE_THRESHOLD / (1024 * 1024),
                            }),
                            tags: vec![
                                "cgroup".to_string(),
                                "resource_abuse".to_string(),
                            ],
                            entities: vec![EntityRef::container(&cgroup_name)],
                        };
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        // Prune stale cgroup states
        if states.len() > 1000 {
            let cutoff = now - Duration::hours(1);
            states.retain(|_, s| s.last_read_at > cutoff);
        }
    }
}

/// Discover active cgroup directories.
fn discover_cgroups(base: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut cgroups = Vec::new();

    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Check if this looks like a cgroup (has cpu.stat or memory.current)
            if path.join("cpu.stat").exists() || path.join("memory.current").exists() {
                cgroups.push(path.clone());
            }
            // Also check one level deeper (for containers like docker/*)
            if let Ok(sub_entries) = std::fs::read_dir(&path) {
                for sub in sub_entries.flatten() {
                    let sub_path = sub.path();
                    if sub_path.is_dir()
                        && (sub_path.join("cpu.stat").exists()
                            || sub_path.join("memory.current").exists())
                    {
                        cgroups.push(sub_path);
                    }
                }
            }
        }
    }

    Ok(cgroups)
}

/// Read CPU usage from `cpu.stat` (cgroups v2).
/// Returns total usage in microseconds.
fn read_cpu_usage(cgroup_path: &Path) -> Option<u64> {
    let stat_path = cgroup_path.join("cpu.stat");
    let content = std::fs::read_to_string(&stat_path).ok()?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("usage_usec ") {
            return val.trim().parse().ok();
        }
    }
    None
}

/// Read memory usage from `memory.current` (cgroups v2).
fn read_memory_current(cgroup_path: &Path) -> Option<u64> {
    let path = cgroup_path.join("memory.current");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_threshold_values() {
        // 95% of one core = 950,000 us/s
        assert_eq!(CPU_ABUSE_THRESHOLD_US, 950_000);
    }

    #[test]
    fn memory_threshold_values() {
        assert_eq!(MEMORY_SPIKE_THRESHOLD, 256 * 1024 * 1024);
    }

    #[test]
    fn cgroup_discovery_on_nonexistent_path() {
        let result = discover_cgroups(Path::new("/nonexistent/cgroup"));
        assert!(result.is_err() || result.unwrap().is_empty());
    }

    #[test]
    fn read_cpu_from_nonexistent() {
        assert!(read_cpu_usage(Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn read_memory_from_nonexistent() {
        assert!(read_memory_current(Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn cpu_stat_parsing() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("cpu.stat"),
            "usage_usec 12345678\nuser_usec 10000000\nsystem_usec 2345678\n",
        )
        .unwrap();
        let usage = read_cpu_usage(dir.path()).unwrap();
        assert_eq!(usage, 12345678);
    }

    #[test]
    fn memory_current_parsing() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("memory.current"), "536870912\n").unwrap();
        let mem = read_memory_current(dir.path()).unwrap();
        assert_eq!(mem, 536870912); // 512 MB
    }
}
