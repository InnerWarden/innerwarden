use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects mass file encryption indicators (ransomware behavior).
///
/// Indicators:
///   - Single process writes to > N files within a time window — mass encryption
///   - Files with suspicious extensions: .encrypted, .locked, .crypt, .enc, etc.
///   - Ransom note creation: README.txt, DECRYPT.txt, HOW_TO_DECRYPT in multiple dirs
///   - Commands using openssl enc or gpg --encrypt on many files
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

impl RansomwareDetector {
    pub fn new(
        host: impl Into<String>,
        file_threshold: usize,
        window_seconds: u64,
        cooldown_seconds: u64,
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

        // Check for suspicious ransomware extensions
        let has_suspicious_ext = RANSOMWARE_EXTENSIONS
            .iter()
            .any(|ext| filename.ends_with(ext));

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
            if count >= 5 {
                let window_secs = self.window.num_seconds();
                return self.emit(
                    event,
                    EmitParams {
                        severity: Severity::Critical,
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

    #[test]
    fn detects_mass_file_write() {
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 5, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 50, 30, 60);
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
        let mut det = RansomwareDetector::new("test", 5, 30, 60);
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
}
