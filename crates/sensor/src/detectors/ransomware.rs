use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects mass file encryption indicators (ransomware behavior).
///
/// Indicators:
///   - Single process writes to > N files within a time window — mass encryption
///   - Files with suspicious extensions: .encrypted, .locked, .crypt, .enc, etc.
///   - Ransom note creation: README.txt, DECRYPT.txt, HOW_TO_DECRYPT in multiple dirs
///   - Commands using openssl enc or gpg --encrypt on many files
///   - Shannon entropy analysis: high-entropy file writes indicate encrypted data
///     (based on arXiv:2409.06452 — ransomware detection via entropy in the Linux kernel)
pub struct RansomwareDetector {
    host: String,
    cooldown: Duration,
    file_threshold: usize,
    window: Duration,
    /// Per-process file write timestamps for mass-write detection.
    write_tracker: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Per-process suspicious extension write count within window.
    suspicious_ext_tracker: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Ransom note file creation — track (directory, filename) pairs.
    ransom_notes: VecDeque<(String, DateTime<Utc>)>,
    /// Cooldown per (comm, alert_key) to avoid flooding.
    alerted: HashMap<String, DateTime<Utc>>,
    /// Per-process count of high-entropy file writes within window.
    high_entropy_writes: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// Per-process unique file paths written within window (rapid multi-file detection).
    rapid_write_paths: HashMap<String, HashSet<String>>,
    /// Shannon entropy threshold — bytes with entropy above this are considered encrypted.
    /// Default 7.5 (max is 8.0 for perfectly random data).
    entropy_threshold: f64,
    /// Number of high-entropy writes before triggering a Critical alert.
    /// Default 3 (detect on first few encrypted files, before mass damage).
    entropy_count_threshold: usize,
}

/// File extensions commonly used by ransomware for encrypted files.
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".locked",
    ".crypt",
    ".enc",
    ".ransom",
    ".crypto",
    ".locky",
    ".cerber",
    ".zepto",
    ".thor",
    ".aes",
    ".rsa",
    ".crypted",
    ".cryptolocker",
];

/// Ransom note filenames (case-insensitive comparison).
const RANSOM_NOTE_NAMES: &[&str] = &[
    "readme.txt",
    "decrypt.txt",
    "how_to_decrypt",
    "ransom_note",
    "!readme!",
    "how_to_recover",
    "restore_files",
    "decrypt_instruction",
    "your_files_are_encrypted",
];

/// Extensions that indicate encrypted content when appended to an existing file extension
/// (e.g., original.docx.encrypted). Checked separately from RANSOMWARE_EXTENSIONS because
/// the pattern is "double extension" — the original extension is preserved.
const ENCRYPTED_APPEND_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".locked",
    ".crypt",
    ".enc",
    ".crypto",
    ".aes",
    ".rsa",
    ".crypted",
    ".locky",
    ".cerber",
    ".zepto",
    ".thor",
    ".ransom",
];

struct EmitParams<'a> {
    severity: Severity,
    comm: &'a str,
    pid: u32,
    uid: u32,
    detail: &'a str,
    title: &'a str,
    alert_key: &'a str,
    recommended_checks: Vec<String>,
}

/// Compute Shannon entropy (bits per byte) of a byte slice.
///
/// Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly uniform distribution).
/// Encrypted / compressed data typically has entropy > 7.5, while normal text files are 4-6.
///
/// Based on the approach described in arXiv:2409.06452 for kernel-level ransomware detection.
///
/// This function is public so the DNA correlation engine and other detectors can reuse it.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check if a filename has a "double extension" pattern indicating ransomware appended
/// an encryption extension to the original file (e.g., report.docx.encrypted).
fn has_appended_encrypted_extension(filename: &str) -> bool {
    let basename = filename.rsplit('/').next().unwrap_or(filename);
    for ext in ENCRYPTED_APPEND_EXTENSIONS {
        if let Some(prefix) = basename.strip_suffix(ext) {
            // The prefix must itself contain a dot (i.e., an original extension exists)
            if prefix.contains('.') {
                return true;
            }
        }
    }
    false
}

impl RansomwareDetector {
    pub fn new(
        host: impl Into<String>,
        file_threshold: usize,
        window_seconds: u64,
        cooldown_seconds: u64,
        entropy_threshold: f64,
        entropy_count_threshold: usize,
    ) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            file_threshold,
            window: Duration::seconds(window_seconds as i64),
            write_tracker: HashMap::new(),
            suspicious_ext_tracker: HashMap::new(),
            ransom_notes: VecDeque::new(),
            alerted: HashMap::new(),
            high_entropy_writes: HashMap::new(),
            rapid_write_paths: HashMap::new(),
            entropy_threshold,
            entropy_count_threshold,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "file.write_access" => self.check_file_write(event),
            "shell.command_exec" => self.check_command(event),
            _ => None,
        }
    }

    fn check_file_write(&mut self, event: &Event) -> Option<Incident> {
        let filename = event.details.get("filename")?.as_str()?;
        let comm = event.details.get("comm")?.as_str()?;
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let now = event.ts;

        // ── Check 0: Shannon entropy on raw data (if available) ──────────
        // Some eBPF collectors include a data_sample or content_preview field
        // with a base64-encoded or raw byte sample of the file write.
        if let Some(entropy_incident) = self.check_entropy(event, comm, pid, uid, filename, now) {
            return Some(entropy_incident);
        }

        // Check for ransom note creation
        let basename = filename.rsplit('/').next().unwrap_or(filename);
        let basename_lower = basename.to_lowercase();
        if RANSOM_NOTE_NAMES.iter().any(|n| basename_lower.contains(n)) {
            // Track ransom note creation
            self.ransom_notes.push_back((filename.to_string(), now));
            // Prune old entries
            while let Some(front) = self.ransom_notes.front() {
                if now - front.1 > self.window {
                    self.ransom_notes.pop_front();
                } else {
                    break;
                }
            }
            // If ransom notes appear in multiple directories (>= 3), it's ransomware
            let unique_dirs: std::collections::HashSet<&str> = self
                .ransom_notes
                .iter()
                .filter_map(|(path, _)| path.rsplit_once('/').map(|(dir, _)| dir))
                .collect();
            if unique_dirs.len() >= 3 {
                return self.emit(
                    event,
                    EmitParams {
                        severity: Severity::Critical,
                        comm,
                        pid,
                        uid,
                        detail: &format!(
                            "Ransom notes created in {} directories within {}s",
                            unique_dirs.len(),
                            self.window.num_seconds()
                        ),
                        title: &format!("Ransom note creation: {basename} in multiple directories"),
                        alert_key: "ransom_note",
                        recommended_checks: vec![
                            format!("CRITICAL: Ransom notes detected in {0} directories by {comm}", unique_dirs.len()),
                            "Immediately isolate the host from the network".to_string(),
                            format!("Kill the process: kill -9 {pid}"),
                            "Check for encrypted files and assess damage".to_string(),
                            "Investigate infection vector: check recent downloads and email attachments".to_string(),
                        ],
                    },
                );
            }
        }

        // ── Check for suspicious ransomware extensions ───────────────────
        let has_suspicious_ext = RANSOMWARE_EXTENSIONS
            .iter()
            .any(|ext| filename.ends_with(ext));

        // ── Check for double-extension pattern (e.g., file.docx.encrypted) ──
        let has_appended_ext = has_appended_encrypted_extension(filename);

        if has_suspicious_ext {
            let tracker = self
                .suspicious_ext_tracker
                .entry(comm.to_string())
                .or_default();
            tracker.push_back(now);

            // Prune old entries
            while let Some(front) = tracker.front() {
                if now - *front > self.window {
                    tracker.pop_front();
                } else {
                    break;
                }
            }

            // Even a few suspicious extension writes are concerning
            let count = tracker.len();

            // If this is also a double-extension write, boost severity —
            // fewer writes needed to trigger (entropy-informed heuristic).
            let effective_threshold = if has_appended_ext { 3 } else { 5 };

            if count >= effective_threshold {
                let window_secs = self.window.num_seconds();
                let severity = if has_appended_ext {
                    Severity::Critical
                } else if count >= 5 {
                    Severity::Critical
                } else {
                    Severity::High
                };
                return self.emit(
                    event,
                    EmitParams {
                        severity,
                        comm,
                        pid,
                        uid,
                        detail: &format!(
                            "{comm} wrote {count} files with ransomware extensions in {window_secs}s"
                        ),
                        title: &format!(
                            "Ransomware extension detected: {comm} wrote {count} suspicious files"
                        ),
                        alert_key: "ransomware_ext",
                        recommended_checks: vec![
                            format!("CRITICAL: {comm} writing files with ransomware extensions"),
                            format!("Kill the process immediately: kill -9 {pid}"),
                            "Isolate the host from the network".to_string(),
                            "Check backup integrity and assess encrypted file count".to_string(),
                        ],
                    },
                );
            }
        }

        // Track all file writes per process for mass-write detection
        let tracker = self.write_tracker.entry(comm.to_string()).or_default();
        tracker.push_back(now);

        // Prune old entries outside window
        while let Some(front) = tracker.front() {
            if now - *front > self.window {
                tracker.pop_front();
            } else {
                break;
            }
        }

        // Mass file write detection
        let count = tracker.len();
        let threshold = self.file_threshold;
        if count >= threshold {
            let window_secs = self.window.num_seconds();
            return self.emit(
                event,
                EmitParams {
                    severity: Severity::High,
                    comm,
                    pid,
                    uid,
                    detail: &format!("{comm} modified {count} files in {window_secs}s"),
                    title: &format!(
                        "Possible ransomware: {comm} modified {count} files in {window_secs}s"
                    ),
                    alert_key: "mass_write",
                    recommended_checks: vec![
                        format!(
                            "Investigate mass file writes by {comm} (pid={pid}): {count} files in {window_secs}s"
                        ),
                        "Check if files are being encrypted: file <path>".to_string(),
                        format!("Check process: ps -p {pid} -o comm=,args="),
                        "If ransomware confirmed: kill process, isolate host, restore from backup"
                            .to_string(),
                    ],
                },
            );
        }

        None
    }

    /// Shannon entropy analysis for file write events.
    ///
    /// When a `data_sample` or `content_preview` field is present in the event details,
    /// compute Shannon entropy on the raw bytes. Encrypted data has entropy close to 8.0.
    ///
    /// When raw data is not available, use heuristic signals:
    /// - Double-extension pattern (file.docx.encrypted) combined with rapid multi-file writes
    /// - Same process writing to many unique file paths in rapid succession with encrypted extensions
    ///
    /// If a process accumulates >= entropy_count_threshold high-entropy writes within the window,
    /// emit a Critical incident — this catches ransomware on the first few encrypted files.
    fn check_entropy(
        &mut self,
        event: &Event,
        comm: &str,
        pid: u32,
        uid: u32,
        filename: &str,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        // Path 1: Direct entropy measurement from raw data.
        // The data_sample / content_preview field can be:
        //   - A JSON array of byte values (u8), e.g. [0, 127, 255, ...] — raw eBPF capture
        //   - A string — measured directly as UTF-8 bytes
        let mut measured_high_entropy = false;
        if let Some(data_field) = event
            .details
            .get("data_sample")
            .or_else(|| event.details.get("content_preview"))
        {
            if let Some(arr) = data_field.as_array() {
                // JSON array of byte values — highest fidelity
                let bytes: Vec<u8> = arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                if !bytes.is_empty() {
                    let entropy = shannon_entropy(&bytes);
                    if entropy > self.entropy_threshold {
                        measured_high_entropy = true;
                    }
                }
            } else if let Some(data_str) = data_field.as_str() {
                // String — measure entropy of the UTF-8 bytes directly
                let bytes = data_str.as_bytes();
                if !bytes.is_empty() {
                    let entropy = shannon_entropy(bytes);
                    if entropy > self.entropy_threshold {
                        measured_high_entropy = true;
                    }
                }
            }
        }

        // If we measured high entropy from actual data, track it per-process
        if measured_high_entropy {
            let tracker = self
                .high_entropy_writes
                .entry(comm.to_string())
                .or_default();
            tracker.push_back(now);

            // Prune old entries outside window
            while let Some(front) = tracker.front() {
                if now - *front > self.window {
                    tracker.pop_front();
                } else {
                    break;
                }
            }

            let count = tracker.len();
            if count >= self.entropy_count_threshold {
                return self.emit_entropy(event, comm, pid, uid, count);
            }

            // Not enough high-entropy writes yet — don't emit, but do return
            // to prevent double-counting with extension checks below
            return None;
        }

        // Path 2: Heuristic — double-extension + rapid multi-file writes (no raw data available)
        // When a process writes to many unique file paths with encrypted-looking double
        // extensions (e.g., report.docx.encrypted), treat this as a ransomware entropy signal
        // even without measuring the actual file content.
        if has_appended_encrypted_extension(filename) {
            let paths = self.rapid_write_paths.entry(comm.to_string()).or_default();
            paths.insert(filename.to_string());

            let path_count = paths.len();
            if path_count >= self.entropy_count_threshold {
                return self.emit_entropy(event, comm, pid, uid, path_count);
            }
        }

        None
    }

    fn check_command(&mut self, event: &Event) -> Option<Incident> {
        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

        let cmd_lower = command.to_lowercase();

        // Detect bulk encryption commands
        let is_openssl_enc = cmd_lower.contains("openssl enc") || cmd_lower.contains("openssl aes");
        let is_gpg_encrypt = cmd_lower.contains("gpg --encrypt")
            || cmd_lower.contains("gpg -e")
            || cmd_lower.contains("gpg --symmetric");

        if is_openssl_enc || is_gpg_encrypt {
            let tool = if is_openssl_enc { "openssl" } else { "gpg" };
            return self.emit(
                event,
                EmitParams {
                    severity: Severity::High,
                    comm,
                    pid,
                    uid,
                    detail: command,
                    title: &format!("Encryption command detected: {tool}"),
                    alert_key: "enc_command",
                    recommended_checks: vec![
                        format!("Investigate encryption command by {comm} (pid={pid}): {command}"),
                        "Check what files are being encrypted".to_string(),
                        format!("Review process tree: pstree -p {pid}"),
                        "If unauthorized: kill process immediately".to_string(),
                    ],
                },
            );
        }

        None
    }

    /// Emit a ransomware entropy detection incident.
    /// Called both from measured-entropy (raw data) and heuristic (double-extension) paths.
    fn emit_entropy(
        &mut self,
        event: &Event,
        comm: &str,
        pid: u32,
        uid: u32,
        count: usize,
    ) -> Option<Incident> {
        self.emit(
            event,
            EmitParams {
                severity: Severity::Critical,
                comm,
                pid,
                uid,
                detail: &format!(
                    "Ransomware entropy: {comm} writing encrypted data to {count} files"
                ),
                title: &format!(
                    "Ransomware entropy detected: {comm} encrypted {count} files"
                ),
                alert_key: "entropy",
                recommended_checks: vec![
                    format!(
                        "CRITICAL: {comm} (pid={pid}) writing high-entropy (encrypted) data to multiple files"
                    ),
                    format!("Kill the process immediately: kill -9 {pid}"),
                    "Isolate the host from the network".to_string(),
                    "Shannon entropy of written data is near 8.0 bits/byte — indicates encryption".to_string(),
                    "Check backup integrity and begin incident response".to_string(),
                ],
            },
        )
    }

    fn emit(&mut self, event: &Event, params: EmitParams<'_>) -> Option<Incident> {
        let EmitParams {
            severity,
            comm,
            pid,
            uid,
            detail,
            title,
            alert_key,
            recommended_checks,
        } = params;
        let now = event.ts;

        let cooldown_key = format!("{comm}:{alert_key}");
        if let Some(&last) = self.alerted.get(&cooldown_key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(cooldown_key, now);

        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        let container_id = event.details["container_id"]
            .as_str()
            .map(|s| s.to_string());

        let mut tags = vec!["ransomware".to_string(), alert_key.to_string()];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "ransomware:{comm}:{alert_key}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: title.to_string(),
            summary: format!("Ransomware indicator: {title} — {comm} (pid={pid}, uid={uid})"),
            evidence: serde_json::json!([{
                "kind": event.kind,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "detail": detail,
                "container_id": container_id,
            }]),
            recommended_checks,
            tags,
            entities,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector(file_threshold: usize, window: u64, cooldown: u64) -> RansomwareDetector {
        RansomwareDetector::new("test", file_threshold, window, cooldown, 7.5, 3)
    }

    fn make_detector_with_entropy(
        file_threshold: usize,
        window: u64,
        cooldown: u64,
        entropy_threshold: f64,
        entropy_count_threshold: usize,
    ) -> RansomwareDetector {
        RansomwareDetector::new(
            "test",
            file_threshold,
            window,
            cooldown,
            entropy_threshold,
            entropy_count_threshold,
        )
    }

    fn file_write_event(comm: &str, filename: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} writing {filename}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": true,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    /// Create a file write event with a data_sample as a JSON array of byte values.
    /// This simulates raw eBPF capture of file write data.
    fn file_write_event_with_bytes(
        comm: &str,
        filename: &str,
        pid: u32,
        ts: DateTime<Utc>,
        data_bytes: &[u8],
    ) -> Event {
        let byte_array: Vec<serde_json::Value> = data_bytes
            .iter()
            .map(|&b| serde_json::Value::Number(serde_json::Number::from(b)))
            .collect();
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} writing {filename}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": true,
                "data_sample": byte_array,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    /// Create a file write event with a data_sample as a string.
    fn file_write_event_with_str_data(
        comm: &str,
        filename: &str,
        pid: u32,
        ts: DateTime<Utc>,
        data_sample: &str,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} writing {filename}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": true,
                "data_sample": data_sample,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    /// Generate high-entropy byte data simulating encrypted file content.
    /// All 256 byte values uniformly distributed -> entropy = 8.0.
    fn encrypted_byte_sample() -> Vec<u8> {
        let mut data = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        data
    }

    fn cmd_event(command: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Command: {command}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    // ── Existing tests (updated for new constructor) ────────────────────

    #[test]
    fn detects_mass_file_write() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        // Write 49 files — should not trigger
        for i in 0..49 {
            let inc = det.process(&file_write_event(
                "evil",
                &format!("/home/user/doc{i}.pdf"),
                1000,
                now + Duration::milliseconds(i * 100),
            ));
            assert!(inc.is_none(), "Should not trigger on {i} writes");
        }

        // 50th write triggers
        let inc = det.process(&file_write_event(
            "evil",
            "/home/user/doc50.pdf",
            1000,
            now + Duration::milliseconds(49 * 100),
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("50 files"));
    }

    #[test]
    fn detects_ransomware_extensions() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        // Write files with .encrypted extension
        for i in 0..4 {
            assert!(det
                .process(&file_write_event(
                    "cryptor",
                    &format!("/home/user/file{i}.encrypted"),
                    2000,
                    now + Duration::seconds(i),
                ))
                .is_none());
        }

        // 5th suspicious extension triggers Critical
        let inc = det.process(&file_write_event(
            "cryptor",
            "/home/user/file5.encrypted",
            2000,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_locked_extension() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        for i in 0..5 {
            det.process(&file_write_event(
                "locker",
                &format!("/data/file{i}.locked"),
                3000,
                now + Duration::seconds(i),
            ));
        }

        let inc = det.process(&file_write_event(
            "locker",
            "/data/file5.locked",
            3000,
            now + Duration::seconds(5),
        ));
        // Should have triggered on the 5th
        // The 6th may or may not depending on cooldown
        // Let's check the alerted map is populated
        assert!(!det.alerted.is_empty());
    }

    #[test]
    fn detects_ransom_notes_in_multiple_dirs() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        det.process(&file_write_event(
            "ransomware",
            "/home/user/README.txt",
            4000,
            now,
        ));
        det.process(&file_write_event(
            "ransomware",
            "/home/user/documents/README.txt",
            4000,
            now + Duration::seconds(1),
        ));
        let inc = det.process(&file_write_event(
            "ransomware",
            "/home/user/photos/README.txt",
            4000,
            now + Duration::seconds(2),
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("Ransom note"));
    }

    #[test]
    fn detects_decrypt_note() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        det.process(&file_write_event("evil", "/dir1/DECRYPT.txt", 5000, now));
        det.process(&file_write_event(
            "evil",
            "/dir2/DECRYPT.txt",
            5000,
            now + Duration::seconds(1),
        ));
        let inc = det.process(&file_write_event(
            "evil",
            "/dir3/DECRYPT.txt",
            5000,
            now + Duration::seconds(2),
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_openssl_enc_command() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        let inc = det.process(&cmd_event(
            "openssl enc -aes-256-cbc -in file.pdf -out file.pdf.enc",
            "bash",
            6000,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_gpg_encrypt_command() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        let inc = det.process(&cmd_event(
            "gpg --encrypt --recipient attacker@evil.com secret.doc",
            "bash",
            6001,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn ignores_normal_file_writes() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        // A few normal writes should not trigger anything
        for i in 0..5 {
            assert!(det
                .process(&file_write_event(
                    "vim",
                    &format!("/home/user/file{i}.txt"),
                    7000,
                    now + Duration::seconds(i),
                ))
                .is_none());
        }
    }

    #[test]
    fn cooldown_suppresses_mass_write_duplicate() {
        let mut det = make_detector(5, 30, 60);
        let now = Utc::now();

        // Trigger mass write
        for i in 0..5 {
            det.process(&file_write_event(
                "evil",
                &format!("/data/f{i}.dat"),
                8000,
                now + Duration::milliseconds(i * 100),
            ));
        }

        // Should have fired. Now more writes should be suppressed by cooldown.
        let inc = det.process(&file_write_event(
            "evil",
            "/data/f99.dat",
            8000,
            now + Duration::seconds(10),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_unrelated_event_kinds() {
        let mut det = make_detector(50, 30, 60);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "connection".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn window_expires_old_writes() {
        let mut det = make_detector(5, 30, 60);
        let now = Utc::now();

        // Write 4 files at time 0
        for i in 0..4 {
            det.process(&file_write_event(
                "app",
                &format!("/data/old{i}.dat"),
                9000,
                now + Duration::seconds(i),
            ));
        }

        // Write 1 file at time 35 (beyond 30s window from first writes)
        let inc = det.process(&file_write_event(
            "app",
            "/data/new.dat",
            9000,
            now + Duration::seconds(35),
        ));
        // Only 2 writes within window (the last from the first batch + this one)
        // so should not trigger (threshold=5)
        assert!(inc.is_none());
    }

    // ── Shannon entropy tests ───────────────────────────────────────────

    #[test]
    fn entropy_random_bytes_near_eight() {
        // 256 distinct byte values equally distributed → entropy = 8.0
        let data: Vec<u8> = (0..=255).collect();
        // Repeat to get a large sample for stable entropy
        let mut large_data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            large_data.extend_from_slice(&data);
        }
        let e = shannon_entropy(&large_data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "expected entropy ~8.0 for uniform random bytes, got {e}"
        );
    }

    #[test]
    fn entropy_all_zeros_is_zero() {
        let data = vec![0u8; 1024];
        let e = shannon_entropy(&data);
        assert!(
            e.abs() < 0.001,
            "expected entropy 0.0 for all-zero bytes, got {e}"
        );
    }

    #[test]
    fn entropy_english_text_midrange() {
        // Typical English prose has entropy around 4-5 bits/byte
        let text = b"The quick brown fox jumps over the lazy dog. \
            Shannon entropy measures the average information content per symbol \
            in a message. For natural language English text, this value typically \
            falls between four and five bits per byte, reflecting the redundancy \
            inherent in human language patterns and letter frequency distributions.";
        let e = shannon_entropy(text);
        assert!(
            e > 3.5 && e < 6.0,
            "expected entropy 3.5-6.0 for English text, got {e}"
        );
    }

    #[test]
    fn entropy_empty_data_is_zero() {
        let e = shannon_entropy(&[]);
        assert!(
            e.abs() < 0.001,
            "expected entropy 0.0 for empty data, got {e}"
        );
    }

    #[test]
    fn high_entropy_data_sample_triggers_critical() {
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        // Simulated encrypted data — all 256 byte values uniformly distributed (entropy = 8.0)
        let encrypted_bytes = encrypted_byte_sample();

        // Write 3 files with high-entropy data_sample — should trigger on the 3rd
        for i in 0..2 {
            let inc = det.process(&file_write_event_with_bytes(
                "cryptor",
                &format!("/home/user/file{i}.dat"),
                3000,
                now + Duration::seconds(i as i64),
                &encrypted_bytes,
            ));
            assert!(
                inc.is_none(),
                "should not trigger on {i} high-entropy writes"
            );
        }

        let inc = det.process(&file_write_event_with_bytes(
            "cryptor",
            "/home/user/file2.dat",
            3000,
            now + Duration::seconds(2),
            &encrypted_bytes,
        ));
        assert!(
            inc.is_some(),
            "expected entropy alert on 3rd high-entropy write"
        );
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("entropy"));
        assert!(inc.tags.contains(&"entropy".to_string()));
    }

    #[test]
    fn multiple_high_entropy_writes_trigger_critical() {
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        let encrypted_bytes = encrypted_byte_sample();

        // First two writes: no alert yet
        det.process(&file_write_event_with_bytes(
            "evil_proc",
            "/data/report.pdf",
            5000,
            now,
            &encrypted_bytes,
        ));
        det.process(&file_write_event_with_bytes(
            "evil_proc",
            "/data/photos.zip",
            5000,
            now + Duration::seconds(1),
            &encrypted_bytes,
        ));

        // Third write triggers Critical
        let inc = det.process(&file_write_event_with_bytes(
            "evil_proc",
            "/data/backup.tar",
            5000,
            now + Duration::seconds(2),
            &encrypted_bytes,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(
            inc.title.contains("encrypted 3 files"),
            "title should mention count: {}",
            inc.title
        );
    }

    #[test]
    fn normal_writes_do_not_trigger_entropy_alert() {
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        // Normal text data has low entropy (~4-5 bits/byte) — should not trigger
        let normal_text = "This is a normal log entry with typical English text content. \
            Nothing encrypted here, just regular application output.";

        for i in 0..10 {
            let inc = det.process(&file_write_event_with_str_data(
                "app",
                &format!("/var/log/app{i}.log"),
                4000,
                now + Duration::seconds(i as i64),
                normal_text,
            ));
            assert!(
                inc.is_none(),
                "normal text write should not trigger entropy alert"
            );
        }
    }

    #[test]
    fn entropy_threshold_configurable() {
        let now = Utc::now();

        // Moderate entropy byte data: 16 distinct values repeated -> entropy = 4.0
        let moderate_bytes: Vec<u8> = (0..512).map(|i| (i % 16) as u8).collect();

        // With a very low threshold (3.0), moderate data triggers
        let mut det_low = make_detector_with_entropy(50, 30, 60, 3.0, 3);
        for i in 0..3 {
            det_low.process(&file_write_event_with_bytes(
                "proc",
                &format!("/data/f{i}.dat"),
                1000,
                now + Duration::seconds(i as i64),
                &moderate_bytes,
            ));
        }
        // The low-threshold detector should have recorded high-entropy writes
        assert!(
            det_low
                .high_entropy_writes
                .get("proc")
                .map_or(0, |v| v.len())
                >= 3,
            "low threshold should flag moderate-entropy data"
        );

        // With default threshold (7.5), same data does NOT trigger
        let mut det_high = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        for i in 0..3 {
            let inc = det_high.process(&file_write_event_with_bytes(
                "proc",
                &format!("/data/f{i}.dat"),
                1000,
                now + Duration::seconds(i as i64),
                &moderate_bytes,
            ));
            assert!(
                inc.is_none(),
                "high threshold should not flag moderate-entropy data"
            );
        }
        assert!(
            det_high.high_entropy_writes.get("proc").is_none(),
            "high threshold detector should not have tracked any high-entropy writes"
        );
    }

    #[test]
    fn mixed_encrypted_and_normal_writes_only_flags_encrypted_process() {
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        let encrypted_bytes = encrypted_byte_sample();
        let normal_text = "Just a regular text file with normal content.";

        // Normal process writes normal data — never triggers
        for i in 0..5 {
            let inc = det.process(&file_write_event_with_str_data(
                "vim",
                &format!("/home/user/notes{i}.txt"),
                1000,
                now + Duration::seconds(i as i64),
                normal_text,
            ));
            assert!(inc.is_none(), "vim should not trigger entropy alert");
        }

        // Evil process writes encrypted data — triggers on 3rd write
        for i in 0..2 {
            det.process(&file_write_event_with_bytes(
                "ransomware",
                &format!("/home/user/doc{i}.pdf"),
                2000,
                now + Duration::seconds(i as i64),
                &encrypted_bytes,
            ));
        }
        let inc = det.process(&file_write_event_with_bytes(
            "ransomware",
            "/home/user/doc2.pdf",
            2000,
            now + Duration::seconds(2),
            &encrypted_bytes,
        ));
        assert!(
            inc.is_some(),
            "ransomware process should trigger entropy alert"
        );

        // vim should still not have any entropy alerts
        assert!(
            det.high_entropy_writes.get("vim").is_none(),
            "vim should have no high-entropy writes tracked"
        );
    }

    #[test]
    fn double_extension_heuristic_triggers_entropy() {
        // When raw data is not available, double-extension patterns combined with
        // rapid multi-file writes should trigger entropy-based detection
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        // Write files with double extensions (file.docx.encrypted) — no data_sample
        for i in 0..2 {
            let inc = det.process(&file_write_event(
                "cryptor",
                &format!("/home/user/document{i}.docx.encrypted"),
                3000,
                now + Duration::seconds(i as i64),
            ));
            // First two might not trigger entropy (depending on path accumulation)
            // but should not trigger entropy Critical yet
            if let Some(ref inc) = inc {
                // If it triggered, it should be from ransomware_ext, not entropy
                assert!(
                    !inc.tags.contains(&"entropy".to_string()),
                    "should not trigger entropy on fewer than 3 double-ext writes"
                );
            }
        }

        // 3rd double-extension write should trigger entropy detection
        let inc = det.process(&file_write_event(
            "cryptor",
            "/home/user/spreadsheet.xlsx.encrypted",
            3000,
            now + Duration::seconds(2),
        ));
        assert!(inc.is_some(), "3rd double-extension write should trigger");
        let inc = inc.unwrap();
        // Should be entropy-based Critical
        assert_eq!(inc.severity, Severity::Critical);
        assert!(
            inc.tags.contains(&"entropy".to_string()),
            "should be tagged as entropy detection"
        );
    }

    #[test]
    fn entropy_count_threshold_configurable() {
        let now = Utc::now();

        let encrypted_bytes = encrypted_byte_sample();

        // With entropy_count_threshold = 5, need 5 writes to trigger
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 5);
        for i in 0..4 {
            let inc = det.process(&file_write_event_with_bytes(
                "proc",
                &format!("/data/f{i}.dat"),
                1000,
                now + Duration::seconds(i as i64),
                &encrypted_bytes,
            ));
            assert!(
                inc.is_none(),
                "should not trigger with count_threshold=5 at {i} writes"
            );
        }

        // 5th write triggers
        let inc = det.process(&file_write_event_with_bytes(
            "proc",
            "/data/f4.dat",
            1000,
            now + Duration::seconds(4),
            &encrypted_bytes,
        ));
        assert!(
            inc.is_some(),
            "5th write should trigger with count_threshold=5"
        );
    }

    #[test]
    fn content_preview_field_also_works() {
        // The entropy check should work with content_preview field (as byte array)
        let mut det = make_detector_with_entropy(50, 30, 60, 7.5, 3);
        let now = Utc::now();

        let encrypted_bytes = encrypted_byte_sample();
        let byte_array: Vec<serde_json::Value> = encrypted_bytes
            .iter()
            .map(|&b| serde_json::Value::Number(serde_json::Number::from(b)))
            .collect();

        // Use content_preview instead of data_sample
        for i in 0..3 {
            let event = Event {
                ts: now + Duration::seconds(i as i64),
                host: "test".to_string(),
                source: "ebpf".to_string(),
                kind: "file.write_access".to_string(),
                severity: Severity::Info,
                summary: format!("proc writing file{i}"),
                details: serde_json::json!({
                    "pid": 5000,
                    "uid": 1000,
                    "ppid": 1,
                    "comm": "encryptor",
                    "filename": format!("/data/file{i}.bin"),
                    "write": true,
                    "content_preview": byte_array,
                }),
                tags: vec!["ebpf".to_string()],
                entities: vec![],
            };
            let inc = det.process(&event);
            if i == 2 {
                assert!(
                    inc.is_some(),
                    "content_preview should trigger entropy detection"
                );
            }
        }
    }
}
