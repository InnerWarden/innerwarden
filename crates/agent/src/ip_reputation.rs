use std::collections::HashMap;
use std::path::Path;

use tracing::warn;

use crate::attacker_intel;

/// Per-IP reputation tracking for adaptive block TTL.
/// Starts neutral (score 0.0); each incident and block increases the score.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalIpReputation {
    /// Total incidents involving this IP.
    pub(crate) total_incidents: u32,
    /// Total times this IP has been blocked.
    pub(crate) total_blocks: u32,
    /// When this IP was first seen by the agent.
    pub(crate) first_seen: chrono::DateTime<chrono::Utc>,
    /// When this IP was last seen by the agent.
    pub(crate) last_seen: chrono::DateTime<chrono::Utc>,
    /// Reputation score: 0.0 = neutral, higher = worse.
    /// Incremented by 1.0 per incident, 2.0 per block.
    pub(crate) reputation_score: f32,
}

impl LocalIpReputation {
    pub(crate) fn new() -> Self {
        let now = chrono::Utc::now();
        Self {
            total_incidents: 0,
            total_blocks: 0,
            first_seen: now,
            last_seen: now,
            reputation_score: 0.0,
        }
    }

    /// Record an incident for this IP.
    pub(crate) fn record_incident(&mut self) {
        self.total_incidents += 1;
        self.last_seen = chrono::Utc::now();
        self.reputation_score += 1.0;
    }

    /// Record a block action for this IP.
    pub(crate) fn record_block(&mut self) {
        self.total_blocks += 1;
        self.last_seen = chrono::Utc::now();
        self.reputation_score += 2.0;
    }
}

/// Adaptive block TTL based on total_blocks count.
///   1st block  → 1 hour
///   2nd block  → 4 hours
///   3rd block  → 24 hours
///   4+ blocks  → 7 days
pub(crate) fn adaptive_block_ttl_secs(total_blocks: u32) -> i64 {
    match total_blocks {
        0 | 1 => 3600, // 1 hour
        2 => 14400,    // 4 hours
        3 => 86400,    // 24 hours
        _ => 604800,   // 7 days
    }
}

/// Append a blocked IP to blocked-ips.txt so the sensor can skip events from it.
/// Uses append mode. Best-effort: errors are logged but not propagated.
pub(crate) fn append_blocked_ip(data_dir: &Path, ip: &str) {
    let path = data_dir.join("blocked-ips.txt");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = writeln!(f, "{ip}") {
                warn!("failed to append to blocked-ips.txt: {e}");
            }
        }
        Err(e) => warn!("failed to open blocked-ips.txt for append: {e}"),
    }
}

/// Write the in-memory reputation map to `ip-reputation.json` so the dashboard
/// (which runs in a separate task) can read it without shared state.
pub(crate) fn persist_ip_reputations(
    data_dir: &Path,
    reputations: &HashMap<String, LocalIpReputation>,
) {
    let path = data_dir.join("ip-reputation.json");
    match serde_json::to_string(reputations) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("failed to write ip-reputation.json: {e}");
            }
        }
        Err(e) => warn!("failed to serialize ip reputations: {e}"),
    }
}

/// Load the reputation map from `ip-reputation.json` at startup.
pub(crate) fn load_ip_reputations(data_dir: &Path) -> HashMap<String, LocalIpReputation> {
    let path = data_dir.join("ip-reputation.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Scan honeypot session files for IPs in attacker profiles and feed session
/// data into their profiles (credentials, commands, IOCs).
pub(crate) fn scan_honeypot_for_profiles(
    data_dir: &Path,
    profiles: &mut HashMap<String, attacker_intel::AttackerProfile>,
) {
    let honeypot_dir = data_dir.join("honeypot");
    let entries = match std::fs::read_dir(&honeypot_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Collect IPs we care about (owned to avoid borrow conflict with get_mut)
    let profile_ips: std::collections::HashSet<String> = profiles.keys().cloned().collect();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("listener-session-") || !name.ends_with(".jsonl") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in content.lines() {
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(peer_ip) = v["peer_ip"].as_str() else {
                continue;
            };
            if !profile_ips.contains(peer_ip as &str) {
                continue;
            }
            if let Some(profile) = profiles.get_mut(peer_ip) {
                let session_id = v["session_id"].as_str().unwrap_or("");
                if !session_id.is_empty() {
                    let already_has = v["shell_commands"]
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|c| c["command"].as_str())
                        .is_some_and(|cmd| profile.commands_executed.contains(&cmd.to_string()));
                    if !already_has {
                        attacker_intel::observe_honeypot(profile, &v);
                    }
                }
            }
        }
    }
}
