use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects ptrace-based process injection and LD_PRELOAD attacks.
///
/// Indicators:
///   - gdb, strace, ltrace attaching to another process (gdb -p, strace -p)
///   - Commands containing ptrace + ATTACH/POKETEXT/POKEDATA
///   - eBPF openat events accessing /proc/{pid}/mem or /proc/{pid}/maps (pid != self)
///   - LD_PRELOAD injection targeting a specific running process
pub struct ProcessInjectionDetector {
    host: String,
    cooldown: Duration,
    /// Per (comm, target_key) cooldown to suppress duplicate alerts.
    alerted: HashMap<String, DateTime<Utc>>,
}

/// Debugging tools that can be used for process injection when targeting other PIDs.
const DEBUG_TOOLS: &[&str] = &["gdb", "strace", "ltrace"];

/// Arguments that indicate attaching to another process.
const ATTACH_ARGS: &[&str] = &["-p", "--pid"];

/// ptrace operations that indicate injection rather than tracing.
const PTRACE_INJECT_OPS: &[&str] = &["ATTACH", "POKETEXT", "POKEDATA"];

impl ProcessInjectionDetector {
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
            "file.read_access" | "file.write_access" => self.check_proc_access(event),
            _ => None,
        }
    }

    /// Check shell/process exec events for debug tool attachment or ptrace injection.
    fn check_command(&mut self, event: &Event) -> Option<Incident> {
        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

        let cmd_lower = command.to_lowercase();

        // Check for LD_PRELOAD injection
        if cmd_lower.contains("ld_preload=") {
            return self.emit_incident(
                event,
                Severity::High,
                comm,
                pid,
                uid,
                command,
                "LD_PRELOAD injection",
                "ld_preload",
                vec![
                    format!("Investigate LD_PRELOAD injection by {comm} (pid={pid})"),
                    format!("Check loaded libraries: cat /proc/{pid}/maps"),
                    "Review the preloaded library for malicious code".to_string(),
                    "Check if the target process has been compromised".to_string(),
                ],
            );
        }

        // Check for debugging tools attaching to other processes
        if DEBUG_TOOLS.contains(&comm) || DEBUG_TOOLS.iter().any(|t| cmd_lower.starts_with(t)) {
            let has_attach = ATTACH_ARGS.iter().any(|arg| cmd_lower.contains(arg));
            if has_attach {
                return self.emit_incident(
                    event,
                    Severity::High,
                    comm,
                    pid,
                    uid,
                    command,
                    "Debug tool attached to running process",
                    "debug_attach",
                    vec![
                        format!("Investigate {comm} attaching to another process (pid={pid})"),
                        "Check if the target process handles sensitive data".to_string(),
                        "Review who initiated the debugging session".to_string(),
                        format!("Check parent process: ps -o ppid= -p {pid}"),
                    ],
                );
            }
        }

        // Check for ptrace syscall with injection operations
        if cmd_lower.contains("ptrace") {
            let has_inject_op = PTRACE_INJECT_OPS.iter().any(|op| command.contains(op));
            if has_inject_op {
                return self.emit_incident(
                    event,
                    Severity::Critical,
                    comm,
                    pid,
                    uid,
                    command,
                    "ptrace injection operation detected",
                    "ptrace_inject",
                    vec![
                        format!("CRITICAL: ptrace injection by {comm} (pid={pid})"),
                        "Immediately investigate the target process for code injection".to_string(),
                        format!("Check process memory: cat /proc/{pid}/maps"),
                        "Consider killing the attacker process immediately".to_string(),
                    ],
                );
            }
        }

        None
    }

    /// Check eBPF file access events for /proc/{pid}/mem or /proc/{pid}/maps access.
    fn check_proc_access(&mut self, event: &Event) -> Option<Incident> {
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

        // Match /proc/{target_pid}/mem or /proc/{target_pid}/maps
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

        // Must be a numeric PID (not "self", "net", etc.)
        if !target_pid_str.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }

        // Only flag mem and maps access
        if subpath != "mem" && subpath != "maps" {
            return None;
        }

        // Skip if accessing own process (self-debugging)
        let target_pid: u32 = target_pid_str.parse().ok()?;
        if target_pid == pid {
            return None;
        }

        let is_write = event.kind == "file.write_access";
        let severity = if subpath == "mem" && is_write {
            Severity::Critical
        } else if subpath == "mem" {
            Severity::High
        } else {
            Severity::High
        };

        let access_type = if is_write { "writing to" } else { "reading" };
        let detail = format!("{comm} {access_type} {filename} (target pid={target_pid})");

        self.emit_incident(
            event,
            severity,
            comm,
            pid,
            uid,
            &detail,
            &format!("Process memory access: {access_type} {subpath} of pid {target_pid}"),
            "proc_mem_access",
            vec![
                format!("Investigate {comm} (pid={pid}) accessing /proc/{target_pid}/{subpath}"),
                format!("Identify target process: ps -p {target_pid} -o comm=,args="),
                format!("Check for injection: cat /proc/{target_pid}/maps"),
                "Review if this is legitimate debugging or an attack".to_string(),
            ],
        )
    }

    fn emit_incident(
        &mut self,
        event: &Event,
        severity: Severity,
        comm: &str,
        pid: u32,
        uid: u32,
        detail: &str,
        title_prefix: &str,
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

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        let container_id = event.details["container_id"]
            .as_str()
            .map(|s| s.to_string());

        let mut tags = vec!["process_injection".to_string(), alert_key.to_string()];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "process_injection:{comm}:{alert_key}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("{title_prefix}: {comm} (pid={pid})"),
            summary: format!(
                "Process injection detected: {detail} — {comm} (pid={pid}, uid={uid})"
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

    fn cmd_event(command: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
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

    fn file_event(
        comm: &str,
        filename: &str,
        pid: u32,
        is_write: bool,
        ts: DateTime<Utc>,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: if is_write {
                "file.write_access".to_string()
            } else {
                "file.read_access".to_string()
            },
            severity: Severity::Info,
            summary: format!("{comm} accessing {filename}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 1000,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "write": is_write,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_gdb_attach() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("gdb -p 1234", "gdb", 5000, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("gdb"));
    }

    #[test]
    fn detects_strace_attach() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("strace -p 4567", "strace", 5001, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("strace"));
    }

    #[test]
    fn detects_gdb_pid_flag() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event("gdb --pid 1234", "gdb", 5002, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_ptrace_poketext() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event(
            "python3 ptrace_inject.py ptrace POKETEXT 1234",
            "python3",
            6000,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_ptrace_attach() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event(
            "inject_tool ptrace ATTACH 5678",
            "inject_tool",
            6001,
            now,
        ));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_ld_preload_injection() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&cmd_event(
            "LD_PRELOAD=/tmp/evil.so /usr/bin/sshd",
            "bash",
            7000,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.summary.contains("LD_PRELOAD"));
    }

    #[test]
    fn detects_proc_mem_write() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_event("evil", "/proc/1234/mem", 5000, true, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn detects_proc_maps_read() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_event("scanner", "/proc/1234/maps", 5000, false, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn ignores_self_proc_access() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        // pid 1234 accessing /proc/1234/mem — self access, should be ignored
        let inc = det.process(&file_event("app", "/proc/1234/mem", 1234, false, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_normal_gdb_without_attach() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        // gdb on a binary, not attaching to a running process
        let inc = det.process(&cmd_event("gdb ./myapp", "gdb", 5000, now));
        assert!(inc.is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&cmd_event("gdb -p 1234", "gdb", 5000, now))
            .is_some());
        assert!(det
            .process(&cmd_event(
                "gdb -p 1234",
                "gdb",
                5000,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        assert!(det
            .process(&cmd_event("gdb -p 1234", "gdb", 5000, now))
            .is_some());
        assert!(det
            .process(&cmd_event(
                "gdb -p 1234",
                "gdb",
                5000,
                now + Duration::seconds(601)
            ))
            .is_some());
    }

    #[test]
    fn ignores_non_numeric_proc_path() {
        let mut det = ProcessInjectionDetector::new("test", 600);
        let now = Utc::now();
        let inc = det.process(&file_event("cat", "/proc/self/mem", 5000, false, now));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_non_matching_event_kind() {
        let mut det = ProcessInjectionDetector::new("test", 600);
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
