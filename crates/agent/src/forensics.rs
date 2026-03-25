use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Forensics report - captured from /proc/{pid}/ on High/Critical incidents
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors to enumerate per process.
const MAX_FDS: usize = 200;
/// Maximum number of memory map lines to capture.
const MAX_MAP_LINES: usize = 50;
/// Cooldown: skip re-capture of the same PID within this window (seconds).
const CAPTURE_COOLDOWN_SECS: i64 = 300;

/// Environment variable name patterns that must be redacted.
const REDACT_PATTERNS: &[&str] = &["KEY", "SECRET", "TOKEN", "PASSWORD", "PASS"];

#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicsReport {
    pub pid: u32,
    pub incident_id: String,
    pub timestamp: DateTime<Utc>,
    pub cmdline: Option<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub status: Option<String>,
    pub open_fds: Vec<String>,
    pub network_connections: Vec<String>,
    pub memory_maps: Vec<String>,
    pub env_redacted: Vec<String>,
}

/// Tracks recently captured PIDs to avoid duplicate captures.
pub struct ForensicsCapture {
    data_dir: PathBuf,
    cooldown: HashMap<u32, DateTime<Utc>>,
}

impl ForensicsCapture {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            cooldown: HashMap::new(),
        }
    }

    /// Attempt forensic capture for a process. Returns `Some(report)` on success,
    /// `None` if the PID is in cooldown or the process has already exited.
    ///
    /// All /proc reads are best-effort - the process may exit at any point.
    pub fn try_capture(&mut self, pid: u32, incident_id: &str) -> Option<ForensicsReport> {
        // Cooldown check: skip if we captured this PID recently
        let now = Utc::now();
        if let Some(last) = self.cooldown.get(&pid) {
            if (now - *last).num_seconds() < CAPTURE_COOLDOWN_SECS {
                debug!(pid, incident_id, "forensics: skipping (cooldown active)");
                return None;
            }
        }

        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        if !proc_dir.exists() {
            debug!(
                pid,
                incident_id, "forensics: /proc/{pid} does not exist - process already exited"
            );
            return None;
        }

        info!(
            pid,
            incident_id, "forensics: capturing process state from /proc"
        );

        let report = capture_process(pid, incident_id, &proc_dir);

        // Save to disk
        let out_path = self.data_dir.join(format!("forensics-{incident_id}.json"));
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&out_path, json) {
                    warn!(path = %out_path.display(), "forensics: failed to write report: {e}");
                } else {
                    info!(path = %out_path.display(), "forensics: report saved");
                }
            }
            Err(e) => {
                warn!("forensics: failed to serialize report: {e}");
            }
        }

        // Update cooldown
        self.cooldown.insert(pid, now);

        // Prune stale cooldown entries (older than 2x the cooldown window)
        let cutoff = now - chrono::Duration::seconds(CAPTURE_COOLDOWN_SECS * 2);
        self.cooldown.retain(|_, ts| *ts > cutoff);

        Some(report)
    }
}

/// Capture forensic data from /proc/{pid}/. All reads are best-effort.
fn capture_process(pid: u32, incident_id: &str, proc_dir: &Path) -> ForensicsReport {
    ForensicsReport {
        pid,
        incident_id: incident_id.to_string(),
        timestamp: Utc::now(),
        cmdline: read_cmdline(proc_dir),
        exe: read_symlink(proc_dir, "exe"),
        cwd: read_symlink(proc_dir, "cwd"),
        status: read_file_string(proc_dir, "status"),
        open_fds: read_fds(proc_dir),
        network_connections: read_network(proc_dir),
        memory_maps: read_maps(proc_dir),
        env_redacted: read_environ_redacted(proc_dir),
    }
}

/// Read /proc/{pid}/cmdline - NUL-separated arguments, joined with spaces.
fn read_cmdline(proc_dir: &Path) -> Option<String> {
    let data = std::fs::read(proc_dir.join("cmdline")).ok()?;
    if data.is_empty() {
        return None;
    }
    // Replace NUL bytes with spaces, trim trailing
    let s: String = data
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    Some(s.trim().to_string())
}

/// Read a symbolic link under /proc/{pid}/ (exe, cwd).
fn read_symlink(proc_dir: &Path, name: &str) -> Option<String> {
    std::fs::read_link(proc_dir.join(name))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Read a /proc file as a string (status, etc.).
fn read_file_string(proc_dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(proc_dir.join(name)).ok()
}

/// List open file descriptors from /proc/{pid}/fd/, capped at MAX_FDS.
fn read_fds(proc_dir: &Path) -> Vec<String> {
    let fd_dir = proc_dir.join("fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    let mut fds = Vec::new();
    for entry in entries {
        if fds.len() >= MAX_FDS {
            fds.push(format!("... truncated at {MAX_FDS} entries"));
            break;
        }
        let Ok(entry) = entry else { continue };
        let fd_num = entry.file_name().to_string_lossy().to_string();
        let target = std::fs::read_link(entry.path())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "?".to_string());
        fds.push(format!("{fd_num} -> {target}"));
    }
    fds
}

/// Read open network connections from /proc/{pid}/net/tcp and tcp6.
fn read_network(proc_dir: &Path) -> Vec<String> {
    let mut connections = Vec::new();
    for name in &["net/tcp", "net/tcp6"] {
        let path = proc_dir.join(name);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        for (i, line) in reader.lines().enumerate() {
            // Skip header line
            if i == 0 {
                continue;
            }
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                connections.push(format!("[{name}] {trimmed}"));
            }
            // Cap at 200 connection entries
            if connections.len() >= 200 {
                connections.push("... truncated".to_string());
                return connections;
            }
        }
    }
    connections
}

/// Read /proc/{pid}/maps, capped at MAX_MAP_LINES.
fn read_maps(proc_dir: &Path) -> Vec<String> {
    let path = proc_dir.join("maps");
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    let reader = BufReader::new(file);
    let mut maps = Vec::with_capacity(MAX_MAP_LINES);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        maps.push(line);
        if maps.len() >= MAX_MAP_LINES {
            maps.push(format!("... truncated at {MAX_MAP_LINES} lines"));
            break;
        }
    }
    maps
}

/// Read /proc/{pid}/environ, redacting sensitive values.
/// Environment variables are NUL-separated KEY=VALUE pairs.
fn read_environ_redacted(proc_dir: &Path) -> Vec<String> {
    let data = match std::fs::read(proc_dir.join("environ")) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let raw = String::from_utf8_lossy(&data);
    raw.split('\0')
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if let Some(eq_pos) = entry.find('=') {
                let key = &entry[..eq_pos];
                let key_upper = key.to_uppercase();
                if REDACT_PATTERNS.iter().any(|pat| key_upper.contains(pat)) {
                    format!("{key}=<REDACTED>")
                } else {
                    entry.to_string()
                }
            } else {
                entry.to_string()
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_redact_patterns() {
        let cases = vec![
            (
                "AWS_SECRET_ACCESS_KEY=abc123",
                "AWS_SECRET_ACCESS_KEY=<REDACTED>",
            ),
            ("API_KEY=xyz", "API_KEY=<REDACTED>"),
            ("DB_PASSWORD=hunter2", "DB_PASSWORD=<REDACTED>"),
            ("AUTH_TOKEN=tok", "AUTH_TOKEN=<REDACTED>"),
            ("SUDO_PASS=foo", "SUDO_PASS=<REDACTED>"),
            ("HOME=/root", "HOME=/root"),
            ("PATH=/usr/bin", "PATH=/usr/bin"),
            ("LANG=en_US.UTF-8", "LANG=en_US.UTF-8"),
        ];

        for (input, expected) in cases {
            let entry = input.to_string();
            let eq_pos = entry.find('=').unwrap();
            let key = &entry[..eq_pos];
            let key_upper = key.to_uppercase();
            let result = if REDACT_PATTERNS.iter().any(|pat| key_upper.contains(pat)) {
                format!("{key}=<REDACTED>")
            } else {
                entry.clone()
            };
            assert_eq!(result, expected, "failed for input: {input}");
        }
    }

    #[test]
    fn test_cooldown_prevents_duplicate_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let mut capture = ForensicsCapture::new(tmp.path());

        // Insert a cooldown entry for PID 99999 with current timestamp
        capture.cooldown.insert(99999, Utc::now());

        // Attempting to capture should return None due to cooldown
        let result = capture.try_capture(99999, "test:cooldown:1");
        assert!(result.is_none());
    }

    #[test]
    fn test_nonexistent_pid_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let mut capture = ForensicsCapture::new(tmp.path());

        // PID 4294967295 should not exist
        let result = capture.try_capture(4294967295, "test:nonexistent:1");
        assert!(result.is_none());
    }

    #[test]
    fn test_report_serialization() {
        let report = ForensicsReport {
            pid: 1234,
            incident_id: "test:serialize:1".to_string(),
            timestamp: Utc::now(),
            cmdline: Some("/usr/bin/python3 -c import os".to_string()),
            exe: Some("/usr/bin/python3".to_string()),
            cwd: Some("/tmp".to_string()),
            status: Some("Name:\tpython3\nPid:\t1234\n".to_string()),
            open_fds: vec!["0 -> /dev/null".to_string()],
            network_connections: vec!["[net/tcp] connection line".to_string()],
            memory_maps: vec![
                "00400000-00401000 r-xp 00000000 08:01 123 /usr/bin/python3".to_string()
            ],
            env_redacted: vec!["HOME=/root".to_string(), "API_KEY=<REDACTED>".to_string()],
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"pid\": 1234"));
        assert!(json.contains("test:serialize:1"));
        assert!(json.contains("/usr/bin/python3"));
        assert!(json.contains("<REDACTED>"));
    }

    #[test]
    fn test_report_saved_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let report = ForensicsReport {
            pid: 42,
            incident_id: "test:disk:1".to_string(),
            timestamp: Utc::now(),
            cmdline: None,
            exe: None,
            cwd: None,
            status: None,
            open_fds: vec![],
            network_connections: vec![],
            memory_maps: vec![],
            env_redacted: vec![],
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let path = tmp.path().join("forensics-test:disk:1.json");
        fs::write(&path, &json).unwrap();

        let loaded: ForensicsReport =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.pid, 42);
        assert_eq!(loaded.incident_id, "test:disk:1");
    }
}
