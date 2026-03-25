use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects credential harvesting from other processes.
///
/// Indicators:
///   - Reading /proc/{pid}/mem (memory dumping)
///   - Reading /proc/{pid}/maps (scanning for credentials in memory layout)
///   - Reading /proc/{pid}/environ (stealing environment variables / tokens)
///   - Known credential harvesting tools: mimipenguin, lazagne, linpeas.sh, pspy
///   - Commands containing "strings /proc" or "cat /proc/*/environ"
///
/// Allowlist: perf, bpftool (legitimate system profiling tools)
pub struct CredentialHarvestDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Known credential harvesting tools.
const CREDENTIAL_TOOLS: &[&str] = &[
    "mimipenguin",
    "lazagne",
    "linpeas.sh",
    "linpeas",
    "pspy",
    "pspy32",
    "pspy64",
    "linux-exploit-",  // linux-exploit-suggester truncated
    "linux-smart-enu", // linux-smart-enumeration truncated
    "les.sh",
    "lse.sh",
    "procdump",
    "memdump",
    "credsniper",
    "keylogger",
];

/// Proc subpaths that indicate credential harvesting when accessed for another PID.
const SENSITIVE_PROC_SUBPATHS: &[&str] = &["mem", "maps", "environ"];

/// Legitimate system profiling/debugging tools that may access /proc.
/// strace is NOT allowlisted here (covered separately by process_injection detector).
const ALLOWLISTED_PROCESSES: &[&str] = &[
    "perf",
    "bpftool",
    "bpftrace",
    "systemd",
    "systemd-journal",
    "node_exporter",
    "prometheus",
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

impl CredentialHarvestDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "file.read_access" => self.check_proc_read(event),
            "shell.command_exec" | "process.exec" => self.check_command(event),
            _ => None,
        }
    }

    fn check_proc_read(&mut self, event: &Event) -> Option<Incident> {
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

        // Match /proc/{target_pid}/{subpath}
        if !filename.starts_with("/proc/") {
            return None;
        }

        let rest = filename.strip_prefix("/proc/")?;
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }

        let target_pid_str = parts[0];
        let subpath = parts[1];

        // Must be a numeric PID
        if !target_pid_str.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }

        // Only flag sensitive subpaths
        if !SENSITIVE_PROC_SUBPATHS.contains(&subpath) {
            return None;
        }

        // Skip self-access
        let target_pid: u32 = target_pid_str.parse().ok()?;
        if target_pid == pid {
            return None;
        }

        // Skip allowlisted processes
        if ALLOWLISTED_PROCESSES.contains(&comm) {
            return None;
        }

        let severity = match subpath {
            "mem" => Severity::Critical,
            "environ" => Severity::High,
            "maps" => Severity::High,
            _ => Severity::High,
        };

        let description = match subpath {
            "mem" => "memory dump (credential extraction)",
            "environ" => "environment variable theft (tokens/secrets)",
            "maps" => "memory layout scanning (credential location)",
            _ => "sensitive proc access",
        };

        self.emit(
            event,
            EmitParams {
                severity,
                comm,
                pid,
                uid,
                detail: &format!("{comm} reading /proc/{target_pid}/{subpath} - {description}"),
                title: &format!("Credential harvest: {comm} reading /proc/{target_pid}/{subpath}"),
                alert_key: &format!("proc_{subpath}_read"),
                recommended_checks: vec![
                    format!("Investigate {comm} (pid={pid}) reading /proc/{target_pid}/{subpath}"),
                    format!("Identify target process: ps -p {target_pid} -o comm=,args="),
                    format!("Check for credential tools: ls -la /proc/{pid}/exe"),
                    "Review the process for known credential harvesting behavior".to_string(),
                    "Check if sensitive data (tokens, passwords) may have been extracted"
                        .to_string(),
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

        let cmd_lower = command.to_lowercase();

        // Check for known credential tools by comm name
        let is_known_tool = CREDENTIAL_TOOLS
            .iter()
            .any(|tool| comm.to_lowercase().contains(tool) || cmd_lower.contains(tool));

        if is_known_tool {
            return self.emit(
                event,
                EmitParams {
                    severity: Severity::Critical,
                    comm,
                    pid,
                    uid,
                    detail: command,
                    title: &format!("Known credential harvesting tool: {comm}"),
                    alert_key: "known_tool",
                    recommended_checks: vec![
                        format!("CRITICAL: Known credential tool {comm} detected (pid={pid})"),
                        format!("Kill immediately: kill -9 {pid}"),
                        "Check what data was accessed or exfiltrated".to_string(),
                        "Rotate all credentials on this host".to_string(),
                        "Review audit logs for lateral movement".to_string(),
                    ],
                },
            );
        }

        // Check for "strings /proc" patterns
        if cmd_lower.contains("strings /proc") || cmd_lower.contains("strings  /proc") {
            return self.emit(
                event,
                EmitParams {
                    severity: Severity::High,
                    comm,
                    pid,
                    uid,
                    detail: command,
                    title: &format!("Process memory string extraction: {command}"),
                    alert_key: "strings_proc",
                    recommended_checks: vec![
                        format!("Investigate memory string extraction by {comm} (pid={pid})"),
                        "Check if credentials were extracted from process memory".to_string(),
                        format!("Review process tree: pstree -p {pid}"),
                    ],
                },
            );
        }

        // Check for "cat /proc/*/environ" or similar patterns
        if cmd_lower.contains("/proc/") && cmd_lower.contains("/environ") {
            // Skip self-referencing /proc/self/environ (common in shell scripts)
            if !cmd_lower.contains("/proc/self/environ") {
                return self.emit(
                    event,
                    EmitParams {
                        severity: Severity::High,
                        comm,
                        pid,
                        uid,
                        detail: command,
                        title: &format!("Process environment variable theft: {command}"),
                        alert_key: "cat_environ",
                        recommended_checks: vec![
                            format!(
                                "Investigate environment variable access by {comm} (pid={pid})"
                            ),
                            "Check if tokens or secrets were read from other processes".to_string(),
                            "Review what processes had their environment dumped".to_string(),
                        ],
                    },
                );
            }
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

        let mut tags = vec!["credential_harvest".to_string(), alert_key.to_string()];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "credential_harvest:{comm}:{alert_key}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: title.to_string(),
            summary: format!("Credential harvesting: {title} - {comm} (pid={pid}, uid={uid})"),
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

    fn file_read_event(comm: &str, filename: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.read_access".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} reading {filename}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": false,
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
    fn detects_proc_mem_read() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("evil", "/proc/1234/mem", 5000, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("mem"));
    }

    #[test]
    fn detects_proc_environ_read() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("spy", "/proc/4567/environ", 5001, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("environ"));
    }

    #[test]
    fn detects_proc_maps_read() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("scanner", "/proc/7890/maps", 5002, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn ignores_self_access() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        // pid 1234 reading its own /proc/1234/mem
        let inc = det.process(&file_read_event("app", "/proc/1234/mem", 1234, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_allowlisted_process() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("perf", "/proc/1234/maps", 5003, now));
        assert!(inc.is_none());

        let inc = det.process(&file_read_event("bpftool", "/proc/1234/mem", 5004, now));
        assert!(inc.is_none());
    }

    #[test]
    fn detects_mimipenguin() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("./mimipenguin.sh", "mimipenguin", 6000, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("mimipenguin"));
    }

    #[test]
    fn detects_lazagne() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("python3 lazagne.py all", "python3", 6001, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_strings_proc() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("strings /proc/1234/mem", "bash", 7000, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_cat_environ() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("cat /proc/1234/environ", "bash", 7001, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn ignores_proc_self_environ_command() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("cat /proc/self/environ", "bash", 7002, now));
        assert!(inc.is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&file_read_event("evil", "/proc/1234/mem", 5000, now))
            .is_some());
        assert!(det
            .process(&file_read_event(
                "evil",
                "/proc/1234/mem",
                5000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn ignores_non_numeric_proc_path() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("cat", "/proc/self/environ", 5000, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_non_sensitive_proc_subpath() {
        let mut det = CredentialHarvestDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_read_event("cat", "/proc/1234/status", 5000, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_unrelated_events() {
        let mut det = CredentialHarvestDetector::new("test", 600);
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
}
