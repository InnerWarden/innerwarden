//! Admin action audit trail with SHA-256 hash chaining.
//!
//! Every administrative action (enable, disable, configure, block, login, etc.)
//! is recorded in `admin-actions-YYYY-MM-DD.jsonl` with tamper-evident hash
//! chaining. Same integrity guarantees as the decision audit trail.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Admin action entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActionEntry {
    pub ts: DateTime<Utc>,
    /// Unix username (CLI) or dashboard username
    pub operator: String,
    /// "cli" | "dashboard" | "api" | "system"
    pub source: String,
    /// "enable", "disable", "configure", "block_ip", "login", "logout", "gdpr_erase", etc.
    pub action: String,
    /// Capability id, module name, IP address, config section, username
    pub target: String,
    /// Action-specific parameters
    #[serde(default)]
    pub parameters: serde_json::Value,
    /// "success" | "failure: <reason>" | "dry_run"
    pub result: String,
    /// SHA-256 hash of previous entry (tamper detection chain)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Standalone append (for CTL - open, write, close)
// ---------------------------------------------------------------------------

/// Append a single admin action to the daily JSONL with hash chaining.
/// Opens the file, reads the last hash, writes the entry, and closes.
/// Suitable for CLI commands that don't keep a writer open.
pub fn append_admin_action(data_dir: &Path, entry: &mut AdminActionEntry) -> anyhow::Result<()> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("admin-actions-{today}.jsonl"));

    // Read last hash for chain continuity
    let last_hash = read_last_hash_from_file(&path);
    entry.prev_hash = last_hash;

    let line = serde_json::to_string(&entry)?;

    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

    writeln!(file, "{line}")?;
    file.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the current unix username.
pub fn current_operator() -> String {
    #[cfg(unix)]
    {
        // Safety: getuid() and getpwuid() are standard POSIX, reading only.
        unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if !pw.is_null() {
                let name = std::ffi::CStr::from_ptr((*pw).pw_name);
                return name.to_string_lossy().into_owned();
            }
        }
        "unknown".to_string()
    }
    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}

/// Compute SHA-256 hex digest of a string.
pub fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data.as_bytes());
    hex::encode(hash)
}

/// Read the last hash from a JSONL file for chain continuity.
fn read_last_hash_from_file(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut last_line = String::new();
    for line in reader.lines().map_while(Result::ok) {
        if !line.trim().is_empty() {
            last_line = line;
        }
    }
    if last_line.is_empty() {
        return None;
    }
    Some(sha256_hex(&last_line))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_operator_returns_non_empty() {
        let op = current_operator();
        assert!(!op.is_empty());
    }

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn append_creates_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut e1 = AdminActionEntry {
            ts: Utc::now(),
            operator: "test".into(),
            source: "cli".into(),
            action: "enable".into(),
            target: "block-ip".into(),
            parameters: serde_json::json!({}),
            result: "success".into(),
            prev_hash: None,
        };
        append_admin_action(dir.path(), &mut e1).unwrap();
        assert!(e1.prev_hash.is_none()); // first entry has no prev

        let mut e2 = AdminActionEntry {
            ts: Utc::now(),
            operator: "test".into(),
            source: "cli".into(),
            action: "disable".into(),
            target: "block-ip".into(),
            parameters: serde_json::json!({}),
            result: "success".into(),
            prev_hash: None,
        };
        append_admin_action(dir.path(), &mut e2).unwrap();
        assert!(e2.prev_hash.is_some()); // second entry chains to first
    }
}
