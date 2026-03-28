use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// io_uring opcode names for human-readable output.
const OPCODE_NAMES: &[(u8, &str)] = &[
    (9, "SENDMSG"),
    (10, "RECVMSG"),
    (13, "ACCEPT"),
    (16, "CONNECT"),
    (18, "OPENAT"),
    (22, "READ"),
    (23, "WRITE"),
    (26, "SEND"),
    (27, "RECV"),
    (28, "OPENAT2"),
    (35, "RENAMEAT"),
    (36, "UNLINKAT"),
    (45, "SOCKET"),
    (46, "URING_CMD"),
    (53, "SEND_ZC"),
];

/// Security-relevant opcodes that always generate alerts.
const HIGH_RISK_OPCODES: &[u8] = &[
    16, // CONNECT — outbound network (C2, exfil)
    13, // ACCEPT — inbound network (reverse shell, backdoor)
    18, // OPENAT — file access (credential theft)
    46, // URING_CMD — passthrough to device driver (always dangerous)
];

/// Critical opcodes — always Critical severity.
const CRITICAL_OPCODES: &[u8] = &[
    46, // URING_CMD — device passthrough, potential kernel exploit
];

/// Processes that legitimately use io_uring.
const ALLOWED_PROCESSES: &[&str] = &[
    // High-performance web servers
    "nginx",
    "caddy",
    "haproxy",
    "envoy",
    // Databases
    "postgres",
    "mysqld",
    "mariadbd",
    "mongod",
    "redis-server",
    "clickhouse",
    "scylladb",
    // Runtimes with io_uring support
    "io_uring",
    "tokio",
    "java",
    // System
    "systemd-journal",
];

/// Detects io_uring usage that may indicate evasion of syscall-based monitoring.
///
/// io_uring submits operations via shared ring buffers, bypassing traditional
/// syscall interception (seccomp, ptrace, audit). Attackers use this to perform
/// file I/O, network connections, and data exfiltration invisible to most tools.
///
/// Reference: ARMO "curing" rootkit (2023-2024).
pub struct IoUringAnomalyDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    /// Track which processes have created io_uring instances
    ring_creators: HashMap<u32, DateTime<Utc>>,
}

impl IoUringAnomalyDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            ring_creators: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "io_uring.create" => self.handle_create(event),
            "io_uring.submit" => self.handle_submit(event),
            _ => None,
        }
    }

    fn handle_create(&mut self, event: &Event) -> Option<Incident> {
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Track the creator
        self.ring_creators.insert(pid, event.ts);

        // Skip allowlisted
        if is_allowed(comm) {
            return None;
        }

        let key = format!("io_uring_create:{comm}:{pid}");
        if self.is_cooldown(&key, event.ts) {
            return None;
        }
        self.alerted.insert(key, event.ts);

        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let sq_entries = event
            .details
            .get("sq_entries")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "io_uring_create:{comm}:{pid}:{}",
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Medium,
            title: format!("io_uring ring created by {comm} (pid {pid})"),
            summary: format!(
                "Process '{comm}' (pid={pid}, uid={uid}) created an io_uring instance \
                 with {sq_entries} SQ entries. io_uring bypasses syscall-based monitoring \
                 (seccomp, audit, many eBPF tools). Most legitimate processes do not use \
                 io_uring. Verify this is expected."
            ),
            evidence: serde_json::json!([{
                "kind": "io_uring_create",
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "sq_entries": sq_entries,
            }]),
            recommended_checks: vec![
                format!("Verify process: ps -p {pid} -o pid,ppid,user,comm,args"),
                "Check if this process normally uses io_uring".to_string(),
                format!("Check process binary: ls -la /proc/{pid}/exe"),
            ],
            tags: vec![
                "io_uring".to_string(),
                "evasion".to_string(),
                "syscall_bypass".to_string(),
            ],
            entities: vec![],
        })
    }

    fn handle_submit(&mut self, event: &Event) -> Option<Incident> {
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let opcode = event
            .details
            .get("opcode")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Skip allowlisted
        if is_allowed(comm) {
            return None;
        }

        // Only alert on high-risk opcodes
        if !HIGH_RISK_OPCODES.contains(&opcode) {
            return None;
        }

        let opcode_name = opcode_to_name(opcode);
        let key = format!("io_uring_submit:{comm}:{opcode_name}");
        if self.is_cooldown(&key, event.ts) {
            return None;
        }
        self.alerted.insert(key, event.ts);

        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let fd = event
            .details
            .get("fd")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        let severity = if CRITICAL_OPCODES.contains(&opcode) {
            Severity::Critical
        } else {
            Severity::High
        };

        let risk_desc = match opcode {
            16 => "outbound connection via io_uring (potential C2/exfil, invisible to syscall monitors)",
            13 => "accepting inbound connection via io_uring (potential reverse shell/backdoor)",
            18 => "file open via io_uring (potential credential theft, invisible to audit)",
            46 => "io_uring passthrough command to device driver (high privilege, potential exploit)",
            _ => "security-relevant io_uring operation",
        };

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "io_uring_anomaly:{comm}:{opcode_name}:{}",
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("io_uring {opcode_name} by {comm} (pid {pid})"),
            summary: format!(
                "Process '{comm}' (pid={pid}, uid={uid}) submitted io_uring \
                 {opcode_name} (opcode {opcode}, fd={fd}). {risk_desc}."
            ),
            evidence: serde_json::json!([{
                "kind": "io_uring_submit",
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "opcode": opcode,
                "opcode_name": opcode_name,
                "fd": fd,
            }]),
            recommended_checks: vec![
                format!("Investigate process: ps -p {pid} -o pid,ppid,user,comm,args"),
                format!("Check open fds: ls -la /proc/{pid}/fd/"),
                format!("Check network: ss -tnp | grep {pid}"),
                "Review io_uring usage: bpftool prog list | grep io_uring".to_string(),
            ],
            tags: vec![
                "io_uring".to_string(),
                "evasion".to_string(),
                opcode_name.to_lowercase(),
            ],
            entities: vec![],
        })
    }

    fn is_cooldown(&self, key: &str, ts: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            ts - last < self.cooldown
        } else {
            false
        }
    }
}

fn is_allowed(comm: &str) -> bool {
    ALLOWED_PROCESSES
        .iter()
        .any(|p| comm == *p || comm.starts_with(p))
}

fn opcode_to_name(opcode: u8) -> &'static str {
    OPCODE_NAMES
        .iter()
        .find(|(op, _)| *op == opcode)
        .map(|(_, name)| *name)
        .unwrap_or("UNKNOWN")
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn create_event(comm: &str, sq_entries: u64) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "io_uring.create".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} created io_uring"),
            details: serde_json::json!({
                "comm": comm, "pid": 1234, "uid": 1000,
                "sq_entries": sq_entries, "cq_entries": sq_entries * 2,
                "flags": 0, "ring_fd": 5,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn submit_event(comm: &str, opcode: u8) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "io_uring.submit".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} io_uring submit opcode {opcode}"),
            details: serde_json::json!({
                "comm": comm, "pid": 1234, "uid": 1000,
                "opcode": opcode, "fd": 3, "sqe_flags": 0,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_ring_creation() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = create_event("evil", 128);
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn allows_nginx_ring_creation() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = create_event("nginx", 256);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn detects_connect_via_uring() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = submit_event("malware", 16); // IORING_OP_CONNECT
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn detects_uring_cmd_critical() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = submit_event("exploit", 46); // IORING_OP_URING_CMD
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn ignores_non_risk_opcode() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = submit_event("app", 22); // IORING_OP_READ — not high-risk alone
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_postgres_submit() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = submit_event("postgres", 16); // CONNECT from postgres — allowed
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_works() {
        let mut det = IoUringAnomalyDetector::new("test", 300);
        let ev = submit_event("evil", 16);
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none()); // cooldown
    }

    #[test]
    fn opcode_name_lookup() {
        assert_eq!(opcode_to_name(16), "CONNECT");
        assert_eq!(opcode_to_name(46), "URING_CMD");
        assert_eq!(opcode_to_name(99), "UNKNOWN");
    }
}
