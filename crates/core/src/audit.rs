//! Admin action audit trail with SHA-256 hash chaining.
//!
//! Every administrative action (enable, disable, configure, block, login, etc.)
//! is recorded in `admin-actions-YYYY-MM-DD.jsonl` with tamper-evident hash
//! chaining. Same integrity guarantees as the decision audit trail.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::Context;
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
    // Build a safe filename from the current date (only digits and hyphens)
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    anyhow::ensure!(
        today.len() == 10 && today.chars().all(|c| c.is_ascii_digit() || c == '-'),
        "invalid date format"
    );
    let filename = format!("admin-actions-{today}.jsonl");

    // Canonicalize data_dir (CWE-22); fail if it cannot be resolved.
    let canonical_dir = std::fs::canonicalize(data_dir)
        .with_context(|| format!("cannot resolve data dir: {}", data_dir.display()))?;
    let path = canonical_dir.join(&filename);
    anyhow::ensure!(
        path.starts_with(&canonical_dir),
        "constructed path escapes data directory"
    );

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        // Open with read + append so we can inspect and extend under a lock.
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        // Acquire exclusive advisory lock for the duration of read+append.
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "failed to acquire audit file lock for {:?}",
                path
            ));
        }

        // Read last hash while holding the lock.
        let last_hash = read_last_hash_from_open_file(&file);
        entry.prev_hash = last_hash;
        let line = serde_json::to_string(&entry)?;
        writeln!(file, "{line}")?;
        file.flush()?;

        // Release the lock; OS releases on close anyway.
        let _ = unsafe { libc::flock(fd, libc::LOCK_UN) };
        Ok(())
    }

    #[cfg(not(unix))]
    {
        // Non-Unix fallback: no file locking available.
        let last_hash = read_last_hash_from_file(&path);
        entry.prev_hash = last_hash;
        let line = serde_json::to_string(&entry)?;
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the current unix username (thread-safe via getpwuid_r).
pub fn current_operator() -> String {
    #[cfg(unix)]
    {
        unsafe {
            let uid = libc::getuid();
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let mut buf = vec![0u8; 4096];
            let ret = libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            );
            if ret == 0 && !result.is_null() && !pwd.pw_name.is_null() {
                let name = std::ffi::CStr::from_ptr(pwd.pw_name);
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

/// Read the last hash from an already-open audit file (used under flock).
#[cfg(unix)]
fn read_last_hash_from_open_file(file: &File) -> Option<String> {
    let file = file.try_clone().ok()?;
    let reader = BufReader::new(file);
    let mut last_line = None;
    for line in reader.lines().map_while(Result::ok) {
        if !line.trim().is_empty() {
            last_line = Some(line);
        }
    }
    last_line.map(|l| sha256_hex(&l))
}

/// Read the last hash from a JSONL file for chain continuity.
/// Uses tail-seek to avoid O(n) scan on large files.
#[cfg(not(unix))]
fn read_last_hash_from_file(path: &Path) -> Option<String> {
    use std::io::{Read, Seek};
    if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len == 0 {
        return None;
    }
    // Read only a tail window to avoid scanning the entire file.
    const TAIL_WINDOW: u64 = 8 * 1024;
    let start = file_len.saturating_sub(TAIL_WINDOW);
    file.seek(std::io::SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let content = String::from_utf8_lossy(&buf);
    content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| sha256_hex(line))
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
        assert_eq!(h1.len(), 64);
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
        assert!(e1.prev_hash.is_none());

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
        assert!(e2.prev_hash.is_some());
    }
}
