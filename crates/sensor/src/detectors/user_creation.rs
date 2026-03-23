use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects unauthorized user and group creation or modification.
///
/// Indicators:
///   - useradd, adduser, usermod, groupadd, addgroup commands
///   - File writes to /etc/passwd, /etc/group, /etc/shadow by non-standard processes
///   - New user with UID 0 (root equivalent) — Critical
///   - usermod adding user to sudo/wheel/admin group — Critical
///
/// Allowlist: useradd/adduser/usermod called by apt, dpkg, cloud-init, puppet, chef, ansible
pub struct UserCreationDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Commands that create or modify users/groups.
const USER_MGMT_COMMANDS: &[&str] = &["useradd", "adduser", "usermod", "groupadd", "addgroup"];

/// Sensitive identity files — writes by non-standard processes are suspicious.
const IDENTITY_FILES: &[&str] = &["/etc/passwd", "/etc/group", "/etc/shadow"];

/// Processes that legitimately write identity files (package managers, config mgmt).
const ALLOWLISTED_PARENTS: &[&str] = &[
    "apt",
    "apt-get",
    "dpkg",
    "cloud-init",
    "puppet",
    "chef-client",
    "chef",
    "ansible",
    "ansible-playboo", // truncated to 15 chars
    "salt-minion",
    "salt-call",
    "snap",
    "snapd",
    "useradd",
    "adduser",
    "usermod",
    "groupadd",
    "addgroup",
    "passwd",
    "chpasswd",
    "newusers",
    "vipw",
    "vigr",
];

/// Privileged groups — adding a user to these is Critical.
const PRIVILEGED_GROUPS: &[&str] = &["sudo", "wheel", "admin", "root", "docker"];

impl UserCreationDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" | "process.exec" => self.check_command(event),
            "file.write_access" => self.check_file_write(event),
            _ => None,
        }
    }

    fn check_command(&mut self, event: &Event) -> Option<Incident> {
        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;
        let ppid_comm = event.details["ppid_comm"].as_str().unwrap_or("");

        // Check if the command involves user/group management
        let cmd_lower = command.to_lowercase();
        let is_user_mgmt = USER_MGMT_COMMANDS.iter().any(|c| {
            comm == *c || cmd_lower.starts_with(c) || cmd_lower.contains(&format!("/{c} "))
        });

        if !is_user_mgmt {
            return None;
        }

        // Skip if parent is an allowlisted process (package manager, config mgmt)
        if !ppid_comm.is_empty() && ALLOWLISTED_PARENTS.contains(&ppid_comm) {
            return None;
        }

        // Detect root-equivalent user creation (UID 0)
        if (cmd_lower.contains("useradd") || cmd_lower.contains("adduser"))
            && (cmd_lower.contains("-o -u 0")
                || cmd_lower.contains("--uid 0")
                || cmd_lower.contains("-u 0"))
        {
            return self.emit(
                event,
                Severity::Critical,
                comm,
                pid,
                uid,
                command,
                "Root-equivalent user creation (UID 0)",
                "uid0_creation",
                vec![
                    format!("CRITICAL: {comm} creating user with UID 0 (root equivalent)"),
                    "Check /etc/passwd for unauthorized UID 0 accounts".to_string(),
                    format!("Review process tree: pstree -p {pid}"),
                    "This is a strong indicator of backdoor creation".to_string(),
                ],
            );
        }

        // Detect adding user to privileged group
        if cmd_lower.contains("usermod") {
            for group in PRIVILEGED_GROUPS {
                if cmd_lower.contains(&format!("-ag {group}"))
                    || cmd_lower.contains(&format!("-a -g {group}"))
                    || cmd_lower.contains(&format!("--append --groups {group}"))
                    || cmd_lower.contains(&format!("-g {group}"))
                    || command.contains(&format!("-aG {group}"))
                    || command.contains(&format!("-a -G {group}"))
                    || command.contains(&format!("-G {group}"))
                {
                    return self.emit(
                        event,
                        Severity::Critical,
                        comm,
                        pid,
                        uid,
                        command,
                        &format!("User added to privileged group: {group}"),
                        "priv_group_add",
                        vec![
                            format!("CRITICAL: user added to {group} group via {comm}"),
                            format!("Check group membership: getent group {group}"),
                            format!("Review process tree: pstree -p {pid}"),
                            "Verify this was an authorized administrative action".to_string(),
                        ],
                    );
                }
            }
        }

        // General user/group creation — High
        self.emit(
            event,
            Severity::High,
            comm,
            pid,
            uid,
            command,
            "User/group management command executed",
            "user_mgmt",
            vec![
                format!("Investigate user management command by {comm} (pid={pid})"),
                "Check /etc/passwd and /etc/group for new entries".to_string(),
                format!("Review process tree: pstree -p {pid}"),
                "Verify this was an authorized administrative action".to_string(),
            ],
        )
    }

    fn check_file_write(&mut self, event: &Event) -> Option<Incident> {
        let filename = event.details.get("filename")?.as_str()?;
        if !IDENTITY_FILES.contains(&filename) {
            return None;
        }

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

        // Skip allowlisted processes
        if ALLOWLISTED_PARENTS.contains(&comm) {
            return None;
        }

        let severity = if filename == "/etc/shadow" {
            Severity::Critical
        } else {
            Severity::High
        };

        self.emit(
            event,
            severity,
            comm,
            pid,
            uid,
            filename,
            &format!("Direct write to {filename} by {comm}"),
            "identity_file_write",
            vec![
                format!("Investigate {comm} (pid={pid}) writing to {filename}"),
                format!("Check file integrity: stat {filename}"),
                "Compare with backup: diff /etc/passwd /etc/passwd-".to_string(),
                "Review recent user/group changes: last, lastlog".to_string(),
            ],
        )
    }

    fn emit(
        &mut self,
        event: &Event,
        severity: Severity,
        comm: &str,
        pid: u32,
        uid: u32,
        detail: &str,
        title: &str,
        alert_key: &str,
        recommended_checks: Vec<String>,
    ) -> Option<Incident> {
        let now = event.ts;

        let cooldown_key = format!("{comm}:{alert_key}:{pid}");
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

        let mut tags = vec!["user_creation".to_string(), alert_key.to_string()];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "user_creation:{comm}:{alert_key}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: title.to_string(),
            summary: format!("{title} — {comm} (pid={pid}, uid={uid}): {detail}"),
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

    fn cmd_event(command: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        cmd_event_with_ppid(command, comm, pid, "", ts)
    }

    fn cmd_event_with_ppid(
        command: &str,
        comm: &str,
        pid: u32,
        ppid_comm: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Command: {command}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 0,
                "ppid": 1,
                "ppid_comm": ppid_comm,
                "comm": comm,
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
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
                "uid": 0,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": true,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_useradd() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("useradd -m hacker", "useradd", 1000, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_adduser() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("adduser newuser", "adduser", 1001, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_uid_zero_creation() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event(
            "useradd -o -u 0 -g 0 backdoor",
            "useradd",
            1002,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("UID 0"));
    }

    #[test]
    fn detects_sudo_group_addition() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("usermod -aG sudo hacker", "usermod", 1003, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("sudo"));
    }

    #[test]
    fn detects_wheel_group_addition() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("usermod -aG wheel hacker", "usermod", 1004, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_etc_passwd_write() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event("vim", "/etc/passwd", 2000, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_etc_shadow_write_critical() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event("python3", "/etc/shadow", 2001, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn allowlists_dpkg_parent() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event_with_ppid(
            "useradd -r sysuser",
            "useradd",
            1005,
            "dpkg",
            now,
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn allowlists_useradd_writing_passwd() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event("useradd", "/etc/passwd", 2002, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_normal_commands() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&cmd_event("ls -la /home", "ls", 3000, now))
            .is_none());
        assert!(det
            .process(&cmd_event("cat /etc/passwd", "cat", 3001, now))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&cmd_event("useradd hacker", "useradd", 1000, now))
            .is_some());
        assert!(det
            .process(&cmd_event(
                "useradd hacker",
                "useradd",
                1000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn detects_groupadd() {
        let mut det = UserCreationDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("groupadd newgroup", "groupadd", 1006, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }
}
