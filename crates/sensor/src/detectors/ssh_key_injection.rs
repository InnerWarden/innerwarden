use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects unauthorized SSH key modifications.
///
/// SSH key injection is a common persistence technique: an attacker writes
/// their public key into `~/.ssh/authorized_keys` to maintain access even
/// after the original vulnerability is patched.
///
/// Detection patterns:
///   - File write to any path containing `.ssh/authorized_keys`
///   - File write to `/etc/ssh/sshd_config` by non-root non-sshd process
///   - Command containing `ssh-keygen` + `authorized_keys`
///   - Command containing `echo` + `>>.*authorized_keys`
///
/// Allowlisted processes (legitimate key managers):
///   sshd, ssh-keygen, cloud-init, waagent
pub struct SshKeyInjectionDetector {
    host: String,
    cooldown: Duration,
    /// Suppress re-alerts per (key) within cooldown window.
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Processes that legitimately modify SSH keys.
const ALLOWED_PROCESSES: &[&str] = &["sshd", "ssh-keygen", "cloud-init", "waagent"];

impl SshKeyInjectionDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
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
        let filename = event.details.get("filename").and_then(|v| v.as_str())?;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip allowlisted processes
        if ALLOWED_PROCESSES.contains(&comm) {
            return None;
        }

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

        // Pattern 1: authorized_keys modification
        if filename.contains(".ssh/authorized_keys") {
            return self.emit_incident(
                event.ts,
                "authorized_keys_write",
                Severity::Critical,
                comm,
                pid,
                uid,
                filename,
                &format!(
                    "Unauthorized write to {filename} by {comm} (pid={pid}, uid={uid}) \
                     — possible SSH key injection for persistence"
                ),
            );
        }

        // Pattern 2: sshd_config modification by non-root non-sshd
        if filename == "/etc/ssh/sshd_config" && uid != 0 {
            return self.emit_incident(
                event.ts,
                "sshd_config_write",
                Severity::High,
                comm,
                pid,
                uid,
                filename,
                &format!(
                    "Non-root process {comm} (pid={pid}, uid={uid}) modified {filename} \
                     — possible SSH configuration tampering"
                ),
            );
        }

        None
    }

    fn check_command(&mut self, event: &Event) -> Option<Incident> {
        let command = event.details.get("command").and_then(|v| v.as_str())?;
        if command.is_empty() {
            return None;
        }

        let lower = command.to_lowercase();
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip allowlisted processes
        if ALLOWED_PROCESSES.contains(&comm) {
            return None;
        }

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

        // Pattern 3: ssh-keygen + authorized_keys
        if lower.contains("ssh-keygen") && lower.contains("authorized_keys") {
            return self.emit_incident(
                event.ts,
                "ssh_keygen_authorized_keys",
                Severity::Critical,
                comm,
                pid,
                uid,
                command,
                &format!(
                    "Command combines ssh-keygen with authorized_keys modification \
                     (pid={pid}, uid={uid}): {command}"
                ),
            );
        }

        // Pattern 4: echo >> authorized_keys
        if lower.contains("echo") && lower.contains("authorized_keys") && lower.contains(">>") {
            return self.emit_incident(
                event.ts,
                "echo_append_authorized_keys",
                Severity::Critical,
                comm,
                pid,
                uid,
                command,
                &format!(
                    "Command appends to authorized_keys via echo \
                     (pid={pid}, uid={uid}): {command}"
                ),
            );
        }

        None
    }

    fn emit_incident(
        &mut self,
        ts: DateTime<Utc>,
        pattern: &str,
        severity: Severity,
        comm: &str,
        pid: u32,
        uid: u32,
        target: &str,
        summary: &str,
    ) -> Option<Incident> {
        let key = format!("{pattern}:{comm}:{target}");

        // Cooldown check
        if let Some(&last) = self.alerted.get(&key) {
            if ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, ts);

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = ts - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        // Truncate target for display
        let display_target = if target.len() > 200 {
            format!("{}...", &target[..200])
        } else {
            target.to_string()
        };

        Some(Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "ssh_key_injection:{pattern}:{pid}:{}",
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("SSH key injection ({pattern}): {display_target}"),
            summary: summary.to_string(),
            evidence: serde_json::json!([{
                "kind": "ssh_key_injection",
                "pattern": pattern,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "target": target,
            }]),
            recommended_checks: vec![
                "Review authorized_keys for unknown public keys: cat ~/.ssh/authorized_keys"
                    .to_string(),
                format!("Investigate process {comm} (pid={pid}) and its parent"),
                "Check for other persistence: crontab -l, systemctl list-unit-files".to_string(),
                "Verify sshd_config has not been weakened: PermitRootLogin, PasswordAuthentication"
                    .to_string(),
                "Audit recent logins: last, lastlog".to_string(),
            ],
            tags: vec!["ssh_key_injection".to_string(), "persistence".to_string()],
            entities: vec![EntityRef::path(target)],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn file_write_event(comm: &str, filename: &str, uid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Sev::Info,
            summary: format!("{comm} writing {filename}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": uid,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": true,
                "flags": 1,
                "cgroup_id": 0,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn command_event(comm: &str, command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Sev::Info,
            summary: format!("Command: {command}"),
            details: serde_json::json!({
                "pid": 5678,
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
    fn detects_authorized_keys_write() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "vim",
                "/home/user/.ssh/authorized_keys",
                1000,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("authorized_keys_write"));
    }

    #[test]
    fn detects_root_authorized_keys_write() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "bash",
                "/root/.ssh/authorized_keys",
                0,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_sshd_config_write_by_non_root() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event("vim", "/etc/ssh/sshd_config", 1000, now))
            .unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("sshd_config_write"));
    }

    #[test]
    fn allows_root_sshd_config_write() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        // root (uid=0) writing sshd_config is considered normal
        assert!(det
            .process(&file_write_event("vim", "/etc/ssh/sshd_config", 0, now))
            .is_none());
    }

    #[test]
    fn detects_ssh_keygen_authorized_keys_command() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det
            .process(&command_event(
                "bash",
                "ssh-keygen -t rsa -f /tmp/key && cat /tmp/key.pub >> ~/.ssh/authorized_keys",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ssh_keygen_authorized_keys"));
    }

    #[test]
    fn detects_echo_append_authorized_keys() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det
            .process(&command_event(
                "bash",
                "echo 'ssh-rsa AAAA...' >> /home/user/.ssh/authorized_keys",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("echo_append_authorized_keys"));
    }

    #[test]
    fn allows_sshd_process() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "sshd",
                "/home/user/.ssh/authorized_keys",
                0,
                now
            ))
            .is_none());
    }

    #[test]
    fn allows_cloud_init() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "cloud-init",
                "/home/ubuntu/.ssh/authorized_keys",
                0,
                now
            ))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "vim",
                "/home/user/.ssh/authorized_keys",
                1000,
                now
            ))
            .is_some());
        assert!(det
            .process(&file_write_event(
                "vim",
                "/home/user/.ssh/authorized_keys",
                1000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "vim",
                "/home/user/.ssh/authorized_keys",
                1000,
                now
            ))
            .is_some());
        assert!(det
            .process(&file_write_event(
                "vim",
                "/home/user/.ssh/authorized_keys",
                1000,
                now + Duration::seconds(601)
            ))
            .is_some());
    }

    #[test]
    fn ignores_irrelevant_events() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Sev::Info,
            summary: "network event".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn ignores_normal_file_writes() {
        let mut det = SshKeyInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event("vim", "/tmp/notes.txt", 1000, now))
            .is_none());
        assert!(det
            .process(&file_write_event("vim", "/home/user/file.txt", 1000, now))
            .is_none());
    }
}
