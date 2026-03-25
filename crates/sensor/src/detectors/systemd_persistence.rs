use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects backdoor persistence via systemd service/timer/socket creation.
///
/// Indicators:
///   - File writes to /etc/systemd/system/*.service, *.timer, *.socket
///   - File writes to /usr/lib/systemd/system/
///   - File writes to ~/.config/systemd/user/
///   - "systemctl enable" or "systemctl daemon-reload" commands
///   - Service files with ExecStart pointing to /tmp, /dev/shm, or hidden paths
///
/// Allowlist: apt, dpkg, pip, snap, systemd-sysv-install
pub struct SystemdPersistenceDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Directories where systemd unit files live.
const SYSTEMD_DIRS: &[&str] = &[
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/.config/systemd/user/", // matches any home dir path containing this
];

/// Systemd unit file extensions we care about.
const UNIT_EXTENSIONS: &[&str] = &[".service", ".timer", ".socket"];

/// Processes that legitimately create systemd units.
const ALLOWLISTED_PROCESSES: &[&str] = &[
    "apt",
    "apt-get",
    "dpkg",
    "pip",
    "pip3",
    "snap",
    "snapd",
    "systemd-sysv-in", // systemd-sysv-install truncated to 15 chars
    "systemd-sysv-install",
    "systemctl", // systemctl itself for enable/link operations
    "systemd",
    "puppet",
    "chef-client",
    "chef",
    "ansible",
    "ansible-playboo",
    "salt-minion",
    "salt-call",
];

/// Suspicious paths in ExecStart - strong indicator of backdoor.
const SUSPICIOUS_EXEC_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

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

impl SystemdPersistenceDetector {
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

        // Check if the file is in a systemd directory
        let in_systemd_dir = SYSTEMD_DIRS.iter().any(|dir| filename.contains(dir));
        if !in_systemd_dir {
            return None;
        }

        // Check if it has a unit file extension
        let is_unit_file = UNIT_EXTENSIONS.iter().any(|ext| filename.ends_with(ext));
        if !is_unit_file {
            return None;
        }

        // Skip allowlisted processes
        if ALLOWLISTED_PROCESSES.contains(&comm) {
            return None;
        }

        // Determine if the path is especially suspicious
        let is_hidden_path = filename
            .rsplit('/')
            .next()
            .map(|name| name.starts_with('.'))
            .unwrap_or(false);

        // Check if the filename itself suggests a suspicious path
        // (We can't read the file content from eBPF events, but we can flag
        // suspicious unit file names and paths)
        let severity = if is_hidden_path {
            Severity::Critical
        } else {
            Severity::High
        };

        self.emit(
            event,
            EmitParams {
                severity,
                comm,
                pid,
                uid,
                detail: filename,
                title: &format!("Systemd unit file created: {filename}"),
                alert_key: "unit_file_write",
                recommended_checks: vec![
                    format!(
                        "Investigate systemd unit file creation by {comm} (pid={pid}): {filename}"
                    ),
                    format!("Review unit file content: cat {filename}"),
                    "Check ExecStart for suspicious paths (/tmp, /dev/shm, hidden dirs)"
                        .to_string(),
                    "List recently modified units: find /etc/systemd/system -mmin -30".to_string(),
                    format!(
                        "Check if service is enabled: systemctl is-enabled $(basename {filename})"
                    ),
                ],
            },
        )
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

        let cmd_lower = command.to_lowercase();

        // Detect "systemctl enable" or "systemctl daemon-reload"
        if !cmd_lower.contains("systemctl") {
            return None;
        }

        let is_enable = cmd_lower.contains("enable");
        let is_daemon_reload = cmd_lower.contains("daemon-reload");

        if !is_enable && !is_daemon_reload {
            return None;
        }

        // Skip if parent is allowlisted
        if !ppid_comm.is_empty() && ALLOWLISTED_PROCESSES.contains(&ppid_comm) {
            return None;
        }

        // Check for suspicious ExecStart paths in the command context
        let has_suspicious_path = SUSPICIOUS_EXEC_PATHS.iter().any(|p| cmd_lower.contains(p));

        let severity = if has_suspicious_path {
            Severity::Critical
        } else {
            Severity::High
        };

        let action = if is_enable { "enable" } else { "daemon-reload" };

        self.emit(
            event,
            EmitParams {
                severity,
                comm,
                pid,
                uid,
                detail: command,
                title: &format!("systemctl {action} executed"),
                alert_key: &format!("systemctl_{action}"),
                recommended_checks: vec![
                    format!("Investigate systemctl {action} by {comm} (pid={pid})"),
                    "List recently modified systemd units: systemctl list-unit-files --state=enabled"
                        .to_string(),
                    "Check for new or modified service files in /etc/systemd/system/".to_string(),
                    format!("Review process tree: pstree -p {pid}"),
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

        let mut tags = vec![
            "systemd_persistence".to_string(),
            "persistence".to_string(),
            alert_key.to_string(),
        ];
        let mut entities = vec![EntityRef::path(detail)];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "systemd_persistence:{comm}:{alert_key}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: title.to_string(),
            summary: format!(
                "Systemd persistence detected: {title} - {comm} (pid={pid}, uid={uid})"
            ),
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

    #[test]
    fn detects_service_file_creation() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "python3",
            "/etc/systemd/system/backdoor.service",
            1000,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_timer_file_creation() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "bash",
            "/etc/systemd/system/evil.timer",
            1001,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_socket_file_creation() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "curl",
            "/usr/lib/systemd/system/revshell.socket",
            1002,
            now,
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn detects_hidden_service_critical() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "wget",
            "/etc/systemd/system/.hidden-backdoor.service",
            1003,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_systemctl_enable() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event(
            "systemctl enable backdoor.service",
            "systemctl",
            2000,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_systemctl_daemon_reload() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("systemctl daemon-reload", "bash", 2001, now));
        assert!(inc.is_some());
    }

    #[test]
    fn allowlists_dpkg() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "dpkg",
            "/etc/systemd/system/nginx.service",
            3000,
            now,
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn allowlists_apt_parent() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event_with_ppid(
            "systemctl enable nginx.service",
            "systemctl",
            3001,
            "apt",
            now,
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_non_systemd_paths() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event("python3", "/tmp/test.service", 4000, now))
            .is_none());
        assert!(det
            .process(&file_write_event(
                "python3",
                "/etc/nginx/nginx.conf",
                4001,
                now
            ))
            .is_none());
    }

    #[test]
    fn ignores_non_unit_extensions() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "vim",
                "/etc/systemd/system/test.conf",
                4002,
                now
            ))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "python3",
                "/etc/systemd/system/evil.service",
                1000,
                now
            ))
            .is_some());
        assert!(det
            .process(&file_write_event(
                "python3",
                "/etc/systemd/system/evil.service",
                1000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn detects_user_systemd_dir() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_write_event(
            "bash",
            "/home/user/.config/systemd/user/miner.service",
            5000,
            now,
        ));
        assert!(inc.is_some());
    }

    #[test]
    fn ignores_unrelated_commands() {
        let mut det = SystemdPersistenceDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&cmd_event("systemctl status nginx", "systemctl", 6000, now))
            .is_none());
        assert!(det
            .process(&cmd_event("ls /etc/systemd/system/", "ls", 6001, now))
            .is_none());
    }
}
