//! Persistent state store backed by redb (embedded Rust key-value database).
//!
//! Replaces in-memory HashMaps that grew without limit. Data lives on disk
//! via memory-mapped I/O - the OS caches hot pages, heap stays fixed.
//!
//! Tables:
//!   - ip_reputations:        IP → JSON (LocalIpReputation)
//!   - decision_cooldowns:    key → timestamp_ms (i64)
//!   - notification_cooldowns: key → timestamp_ms (i64)
//!   - block_counts:          IP → count (u32)
//!   - xdp_block_times:       IP → JSON { blocked_at_ms, ttl_secs }
//!   - trust_rules:           "detector:action" → 1
//!   - attacker_profiles:     IP → JSON (AttackerProfile)

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use tracing::{info, warn};

// Table definitions - key and value types must be fixed at compile time.
const IP_REPUTATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("ip_reputations");
const DECISION_COOLDOWNS: TableDefinition<&str, i64> = TableDefinition::new("decision_cooldowns");
const NOTIFICATION_COOLDOWNS: TableDefinition<&str, i64> =
    TableDefinition::new("notification_cooldowns");
const BLOCK_COUNTS: TableDefinition<&str, u32> = TableDefinition::new("block_counts");
const XDP_BLOCK_TIMES: TableDefinition<&str, &[u8]> = TableDefinition::new("xdp_block_times");
const TRUST_RULES: TableDefinition<&str, u8> = TableDefinition::new("trust_rules");
const ATTACKER_PROFILES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("attacker_profiles");

/// Persistent state store for the agent.
pub struct StateStore {
    db: Database,
}

#[allow(dead_code)]
impl StateStore {
    /// Open or create the state database at `data_dir/agent-state.redb`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("agent-state.redb");
        let db = Database::create(&db_path)
            .with_context(|| format!("failed to open state store: {}", db_path.display()))?;

        // Ensure all tables exist
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(IP_REPUTATIONS)?;
            let _ = write_txn.open_table(DECISION_COOLDOWNS)?;
            let _ = write_txn.open_table(NOTIFICATION_COOLDOWNS)?;
            let _ = write_txn.open_table(BLOCK_COUNTS)?;
            let _ = write_txn.open_table(XDP_BLOCK_TIMES)?;
            let _ = write_txn.open_table(TRUST_RULES)?;
            let _ = write_txn.open_table(ATTACKER_PROFILES)?;
        }
        write_txn.commit()?;

        info!(path = %db_path.display(), "state store opened (redb)");
        Ok(Self { db })
    }

    // ── IP Reputations ──────────────────────────────────────────────

    pub fn get_ip_reputation(&self, ip: &str) -> Option<serde_json::Value> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(IP_REPUTATIONS).ok()?;
        let entry = table.get(ip).ok()??;
        serde_json::from_slice(entry.value()).ok()
    }

    pub fn set_ip_reputation(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(IP_REPUTATIONS) {
                let _ = table.insert(ip, data.as_slice());
            }
            let _ = write_txn.commit();
        }
    }

    pub fn all_ip_reputations(&self) -> Vec<(String, serde_json::Value)> {
        let mut result = Vec::new();
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(IP_REPUTATIONS) {
                if let Ok(iter) = table.iter() {
                    for entry in iter.flatten() {
                        let (k, v) = entry;
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(v.value()) {
                            result.push((k.value().to_string(), val));
                        }
                    }
                }
            }
        }
        result
    }

    pub fn ip_reputations_len(&self) -> usize {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = read_txn.open_table(IP_REPUTATIONS) else {
            return 0;
        };
        table.iter().map(|i| i.count()).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping the most recently seen.
    /// Called during slow-loop cleanup.
    pub fn trim_ip_reputations(&self, max: usize) {
        let len = self.ip_reputations_len();
        if len <= max {
            return;
        }
        // Collect all, sort by last_seen, keep top `max`
        let mut all = self.all_ip_reputations();
        all.sort_by(|a, b| {
            let ts_a = a.1["last_seen"].as_str().unwrap_or("");
            let ts_b = b.1["last_seen"].as_str().unwrap_or("");
            ts_b.cmp(ts_a) // newest first
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(IP_REPUTATIONS) {
                for ip in &to_remove {
                    let _ = table.remove(ip.as_str());
                }
            }
            let _ = write_txn.commit();
        }
    }

    // ── Cooldowns (decision + notification) ─────────────────────────

    pub fn get_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let read_txn = self.db.begin_read().ok()?;
        let table = match table_def {
            CooldownTable::Decision => read_txn.open_table(DECISION_COOLDOWNS).ok()?,
            CooldownTable::Notification => read_txn.open_table(NOTIFICATION_COOLDOWNS).ok()?,
        };
        let entry = table.get(key).ok()??;
        let ms = entry.value();
        chrono::DateTime::from_timestamp_millis(ms)
    }

    pub fn set_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let ms = ts.timestamp_millis();
        if let Ok(write_txn) = self.db.begin_write() {
            let result = match table_def {
                CooldownTable::Decision => write_txn.open_table(DECISION_COOLDOWNS).map(|mut t| {
                    let _ = t.insert(key, ms);
                }),
                CooldownTable::Notification => {
                    write_txn.open_table(NOTIFICATION_COOLDOWNS).map(|mut t| {
                        let _ = t.insert(key, ms);
                    })
                }
            };
            let _ = result;
            let _ = write_txn.commit();
        }
    }

    pub fn has_cooldown(&self, table_def: CooldownTable, key: &str) -> bool {
        self.get_cooldown(table_def, key).is_some()
    }

    /// Remove entries older than `cutoff`.
    pub fn retain_cooldowns(
        &self,
        table_def: CooldownTable,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) {
        let cutoff_ms = cutoff.timestamp_millis();
        if let Ok(write_txn) = self.db.begin_write() {
            let keys_to_remove: Vec<String> = {
                let table = match table_def {
                    CooldownTable::Decision => write_txn.open_table(DECISION_COOLDOWNS),
                    CooldownTable::Notification => write_txn.open_table(NOTIFICATION_COOLDOWNS),
                };
                if let Ok(table) = table {
                    table
                        .iter()
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter(|(_, v)| v.value() <= cutoff_ms)
                        .map(|(k, _)| k.value().to_string())
                        .collect()
                } else {
                    Vec::new()
                }
            };
            if !keys_to_remove.is_empty() {
                let table = match table_def {
                    CooldownTable::Decision => write_txn.open_table(DECISION_COOLDOWNS),
                    CooldownTable::Notification => write_txn.open_table(NOTIFICATION_COOLDOWNS),
                };
                if let Ok(mut table) = table {
                    for key in &keys_to_remove {
                        let _ = table.remove(key.as_str());
                    }
                }
            }
            let _ = write_txn.commit();
        }
    }

    // ── Block Counts ────────────────────────────────────────────────

    pub fn get_block_count(&self, ip: &str) -> u32 {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = read_txn.open_table(BLOCK_COUNTS) else {
            return 0;
        };
        table.get(ip).ok().flatten().map(|e| e.value()).unwrap_or(0)
    }

    pub fn increment_block_count(&self, ip: &str) -> u32 {
        let current = self.get_block_count(ip);
        let new_count = current + 1;
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(BLOCK_COUNTS) {
                let _ = table.insert(ip, new_count);
            }
            let _ = write_txn.commit();
        }
        new_count
    }

    pub fn clear_block_counts(&self) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(BLOCK_COUNTS) {
                // Drain all entries
                let keys: Vec<String> = table
                    .iter()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|(k, _)| k.value().to_string())
                    .collect();
                for key in &keys {
                    let _ = table.remove(key.as_str());
                }
            }
            let _ = write_txn.commit();
        }
    }

    pub fn block_counts_len(&self) -> usize {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = read_txn.open_table(BLOCK_COUNTS) else {
            return 0;
        };
        table.iter().map(|i| i.count()).unwrap_or(0)
    }

    // ── XDP Block Times ─────────────────────────────────────────────

    pub fn get_xdp_block_time(&self, ip: &str) -> Option<(chrono::DateTime<chrono::Utc>, i64)> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(XDP_BLOCK_TIMES).ok()?;
        let entry = table.get(ip).ok()??;
        let val: serde_json::Value = serde_json::from_slice(entry.value()).ok()?;
        let blocked_at = val["blocked_at_ms"].as_i64()?;
        let ttl = val["ttl_secs"].as_i64().unwrap_or(0);
        Some((chrono::DateTime::from_timestamp_millis(blocked_at)?, ttl))
    }

    pub fn set_xdp_block_time(
        &self,
        ip: &str,
        blocked_at: chrono::DateTime<chrono::Utc>,
        ttl_secs: i64,
    ) {
        let val = serde_json::json!({
            "blocked_at_ms": blocked_at.timestamp_millis(),
            "ttl_secs": ttl_secs,
        });
        let data = serde_json::to_vec(&val).unwrap_or_default();
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(XDP_BLOCK_TIMES) {
                let _ = table.insert(ip, data.as_slice());
            }
            let _ = write_txn.commit();
        }
    }

    pub fn remove_xdp_block_time(&self, ip: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(XDP_BLOCK_TIMES) {
                let _ = table.remove(ip);
            }
            let _ = write_txn.commit();
        }
    }

    pub fn all_xdp_block_times(&self) -> Vec<(String, chrono::DateTime<chrono::Utc>, i64)> {
        let mut result = Vec::new();
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(XDP_BLOCK_TIMES) {
                if let Ok(iter) = table.iter() {
                    for entry in iter.flatten() {
                        let (k, v) = entry;
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(v.value()) {
                            if let (Some(ms), Some(ttl)) =
                                (val["blocked_at_ms"].as_i64(), val["ttl_secs"].as_i64())
                            {
                                if let Some(dt) = chrono::DateTime::from_timestamp_millis(ms) {
                                    result.push((k.value().to_string(), dt, ttl));
                                }
                            }
                        }
                    }
                }
            }
        }
        result
    }

    // ── Trust Rules ─────────────────────────────────────────────────

    pub fn has_trust_rule(&self, key: &str) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = read_txn.open_table(TRUST_RULES) else {
            return false;
        };
        table.get(key).ok().flatten().is_some()
    }

    pub fn add_trust_rule(&self, key: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(TRUST_RULES) {
                let _ = table.insert(key, 1u8);
            }
            let _ = write_txn.commit();
        }
    }

    // ── Attacker Profiles ────────────────────────────────────────────

    pub fn get_attacker_profile(&self, ip: &str) -> Option<serde_json::Value> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ATTACKER_PROFILES).ok()?;
        let entry = table.get(ip).ok()??;
        serde_json::from_slice(entry.value()).ok()
    }

    pub fn set_attacker_profile(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(ATTACKER_PROFILES) {
                let _ = table.insert(ip, data.as_slice());
            }
            let _ = write_txn.commit();
        }
    }

    pub fn all_attacker_profiles(&self) -> Vec<(String, serde_json::Value)> {
        let mut result = Vec::new();
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(ATTACKER_PROFILES) {
                if let Ok(iter) = table.iter() {
                    for entry in iter.flatten() {
                        let (k, v) = entry;
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(v.value()) {
                            result.push((k.value().to_string(), val));
                        }
                    }
                }
            }
        }
        result
    }

    pub fn remove_attacker_profile(&self, ip: &str) {
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(ATTACKER_PROFILES) {
                let _ = table.remove(ip);
            }
            let _ = write_txn.commit();
        }
    }

    pub fn attacker_profiles_len(&self) -> usize {
        let Ok(read_txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = read_txn.open_table(ATTACKER_PROFILES) else {
            return 0;
        };
        table.iter().map(|i| i.count()).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping those with the highest risk_score.
    pub fn trim_attacker_profiles(&self, max: usize) {
        let len = self.attacker_profiles_len();
        if len <= max {
            return;
        }
        let mut all = self.all_attacker_profiles();
        // Sort by risk_score descending, then last_seen descending
        all.sort_by(|a, b| {
            let score_a = a.1["risk_score"].as_u64().unwrap_or(0);
            let score_b = b.1["risk_score"].as_u64().unwrap_or(0);
            score_b.cmp(&score_a).then_with(|| {
                let ts_a = a.1["last_seen"].as_str().unwrap_or("");
                let ts_b = b.1["last_seen"].as_str().unwrap_or("");
                ts_b.cmp(ts_a)
            })
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(ATTACKER_PROFILES) {
                for ip in &to_remove {
                    let _ = table.remove(ip.as_str());
                }
            }
            let _ = write_txn.commit();
        }
    }

    /// Compact the database file (reclaim disk space).
    pub fn compact(&mut self) {
        if let Err(e) = self.db.compact() {
            warn!(error = %e, "state store compact failed");
        }
    }
}

/// Which cooldown table to operate on.
#[derive(Clone, Copy)]
pub enum CooldownTable {
    Decision,
    Notification,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (TempDir, StateStore) {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn cooldown_insert_and_get() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "test:key", now);
        assert!(store.has_cooldown(CooldownTable::Decision, "test:key"));
        assert!(!store.has_cooldown(CooldownTable::Decision, "other:key"));
    }

    #[test]
    fn block_count_increment() {
        let (_dir, store) = make_store();
        assert_eq!(store.get_block_count("1.2.3.4"), 0);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 1);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 2);
    }

    #[test]
    fn ip_reputation_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"score": 42, "last_seen": "2026-01-01T00:00:00Z"});
        store.set_ip_reputation("10.0.0.1", &val);
        let got = store.get_ip_reputation("10.0.0.1").unwrap();
        assert_eq!(got["score"], 42);
        assert_eq!(store.ip_reputations_len(), 1);
    }

    #[test]
    fn trust_rule_add_and_check() {
        let (_dir, store) = make_store();
        assert!(!store.has_trust_rule("ssh:block"));
        store.add_trust_rule("ssh:block");
        assert!(store.has_trust_rule("ssh:block"));
    }

    #[test]
    fn xdp_block_time_roundtrip() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("5.6.7.8", now, 3600);
        let (dt, ttl) = store.get_xdp_block_time("5.6.7.8").unwrap();
        assert_eq!(ttl, 3600);
        assert!((dt - now).num_seconds().abs() < 1);
    }

    #[test]
    fn retain_cooldowns_removes_old() {
        let (_dir, store) = make_store();
        let old = chrono::Utc::now() - chrono::Duration::hours(3);
        let recent = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "old:key", old);
        store.set_cooldown(CooldownTable::Decision, "new:key", recent);
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(2);
        store.retain_cooldowns(CooldownTable::Decision, cutoff);
        assert!(!store.has_cooldown(CooldownTable::Decision, "old:key"));
        assert!(store.has_cooldown(CooldownTable::Decision, "new:key"));
    }

    #[test]
    fn attacker_profile_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"ip": "10.0.0.1", "risk_score": 75, "last_seen": "2026-03-29T00:00:00Z"});
        store.set_attacker_profile("10.0.0.1", &val);
        let got = store.get_attacker_profile("10.0.0.1").unwrap();
        assert_eq!(got["risk_score"], 75);
        assert_eq!(store.attacker_profiles_len(), 1);
    }

    #[test]
    fn trim_attacker_profiles_keeps_highest_risk() {
        let (_dir, store) = make_store();
        for i in 0..5u64 {
            let val = serde_json::json!({"risk_score": i * 10, "last_seen": "2026-01-01T00:00:00Z"});
            store.set_attacker_profile(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.attacker_profiles_len(), 5);
        store.trim_attacker_profiles(3);
        assert_eq!(store.attacker_profiles_len(), 3);
        // Lowest risk (0, 10) should be removed
        assert!(store.get_attacker_profile("10.0.0.4").is_some()); // risk 40
        assert!(store.get_attacker_profile("10.0.0.0").is_none()); // risk 0
    }

    #[test]
    fn trim_ip_reputations_keeps_newest() {
        let (_dir, store) = make_store();
        for i in 0..5 {
            let val = serde_json::json!({"last_seen": format!("2026-01-0{}T00:00:00Z", i + 1)});
            store.set_ip_reputation(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.ip_reputations_len(), 5);
        store.trim_ip_reputations(3);
        assert_eq!(store.ip_reputations_len(), 3);
    }
}
