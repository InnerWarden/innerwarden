//! Property-based tests for v0.6.0 detectors.
//!
//! These tests verify invariants that must hold for ALL possible inputs,
//! not just specific cases. They use proptest to generate random events
//! and check that security properties are never violated.

use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use proptest::prelude::*;

fn make_event(kind: &str, details: serde_json::Value) -> Event {
    Event {
        ts: Utc::now(),
        host: "test".to_string(),
        source: "ebpf".to_string(),
        kind: kind.to_string(),
        severity: Severity::Info,
        summary: "test event".to_string(),
        details,
        tags: vec![],
        entities: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Sensitive Write Detector — property tests
// ══════���═══════════════��════════════════════════════════════════════════

mod sensitive_write {
    use super::*;
    use innerwarden_sensor::detectors::sensitive_write::SensitiveWriteDetector;

    /// INVARIANT: Any write to /etc/shadow by a non-allowlisted process
    /// MUST generate a Critical incident.
    #[test]
    fn shadow_write_always_critical() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            pid in 100u64..65535,
            uid in 0u64..65535
        )| {
            // Skip known-allowlisted
            let allowlisted = ["dpkg", "apt", "passwd", "useradd", "usermod",
                               "chpasswd", "visudo", "sudo", "sshd", "systemd",
                               "cron", "yum", "dnf", "rpm", "snap", "groupadd",
                               "groupmod", "groupdel", "userdel", "cloud", "puppet",
                               "chef", "ansible", "salt", "vipw", "vigr", "chsh",
                               "chfn", "adduser", "deluser", "pam", "faillock",
                               "nscd", "sss", "innerwarden"];
            if allowlisted.iter().any(|a| comm.starts_with(a)) {
                return Ok(());
            }

            let mut det = SensitiveWriteDetector::new("test", 0); // 0 cooldown
            let ev = make_event("file.write_access", serde_json::json!({
                "filename": "/etc/shadow",
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "flags": 1,
            }));
            let incident = det.process(&ev);
            prop_assert!(incident.is_some(), "write to /etc/shadow by '{}' should generate incident", comm);
            prop_assert_eq!(incident.unwrap().severity, Severity::Critical);
        });
    }

    /// INVARIANT: Any write to authorized_keys by a non-allowlisted process
    /// MUST generate an incident.
    #[test]
    fn ssh_key_write_always_detected() {
        proptest!(|(
            user in "[a-z]{3,8}",
            comm in "[a-z]{3,8}"
        )| {
            let allowlisted = ["dpkg", "apt", "passwd", "useradd", "usermod",
                               "sshd", "sudo", "systemd", "cron", "yum", "rpm",
                               "cloud", "puppet", "chef", "ansible", "salt",
                               "innerwarden"];
            if allowlisted.iter().any(|a| comm.starts_with(a)) {
                return Ok(());
            }

            let mut det = SensitiveWriteDetector::new("test", 0);
            let ev = make_event("file.write_access", serde_json::json!({
                "filename": format!("/home/{}/.ssh/authorized_keys", user),
                "comm": comm,
                "pid": 1234,
                "uid": 1000,
                "flags": 1,
            }));
            let incident = det.process(&ev);
            prop_assert!(incident.is_some(), "write to authorized_keys by '{}' should generate incident", comm);
        });
    }

    /// INVARIANT: Read events NEVER generate incidents (only writes).
    #[test]
    fn reads_never_generate_incidents() {
        proptest!(|(
            filename in "/etc/(shadow|passwd|sudoers|crontab)",
            comm in "[a-z]{3,8}"
        )| {
            let mut det = SensitiveWriteDetector::new("test", 0);
            let ev = make_event("file.read_access", serde_json::json!({
                "filename": filename,
                "comm": comm,
                "pid": 1234,
                "uid": 0,
                "flags": 0,
            }));
            prop_assert!(det.process(&ev).is_none(), "read event should never generate incident");
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════
// io_uring Anomaly Detector — property tests
// ═��═════════════════════════════════════════════════════════════════════

mod io_uring {
    use super::*;
    use innerwarden_sensor::detectors::io_uring_anomaly::IoUringAnomalyDetector;

    /// INVARIANT: URING_CMD (opcode 46) from non-allowlisted process
    /// ALWAYS generates a Critical incident.
    #[test]
    fn uring_cmd_always_critical() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            pid in 100u64..65535
        )| {
            let allowlisted = ["nginx", "caddy", "haproxy", "envoy", "postgres",
                               "mysqld", "mariadbd", "mongod", "redis", "clickhouse",
                               "scylladb", "io_uring", "tokio", "java", "systemd"];
            if allowlisted.iter().any(|a| comm.starts_with(a)) {
                return Ok(());
            }

            let mut det = IoUringAnomalyDetector::new("test", 0);
            let ev = make_event("io_uring.submit", serde_json::json!({
                "comm": comm,
                "pid": pid,
                "uid": 0,
                "opcode": 46,
                "fd": 3,
                "sqe_flags": 0,
            }));
            let incident = det.process(&ev);
            prop_assert!(incident.is_some(), "URING_CMD by '{}' should generate incident", comm);
            prop_assert_eq!(incident.unwrap().severity, Severity::Critical);
        });
    }

    /// INVARIANT: Non-high-risk opcodes NEVER generate incidents
    /// (regardless of the process name).
    #[test]
    fn safe_opcodes_never_alert() {
        // Non-high-risk opcodes: READ(22), WRITE(23), NOP(0), TIMEOUT(11), etc.
        let safe_opcodes: Vec<u8> = (0..=53)
            .filter(|op| ![9, 10, 13, 16, 18, 46].contains(op))
            .collect();

        proptest!(|(
            comm in "[a-z]{3,8}",
            opcode_idx in 0..safe_opcodes.len()
        )| {
            let opcode = safe_opcodes[opcode_idx];
            let mut det = IoUringAnomalyDetector::new("test", 0);
            let ev = make_event("io_uring.submit", serde_json::json!({
                "comm": comm,
                "pid": 1234,
                "uid": 0,
                "opcode": opcode,
                "fd": 3,
                "sqe_flags": 0,
            }));
            prop_assert!(det.process(&ev).is_none(),
                "opcode {} should not generate incident (non-high-risk)", opcode);
        });
    }

    /// INVARIANT: Allowlisted processes NEVER generate incidents
    /// (even for high-risk opcodes).
    #[test]
    fn allowlisted_never_alert() {
        let allowed = ["nginx", "postgres", "redis-server", "clickhouse"];
        let high_risk = [13u8, 16, 18, 46];

        proptest!(|(
            proc_idx in 0..allowed.len(),
            op_idx in 0..high_risk.len()
        )| {
            let mut det = IoUringAnomalyDetector::new("test", 0);
            let ev = make_event("io_uring.submit", serde_json::json!({
                "comm": allowed[proc_idx],
                "pid": 1234,
                "uid": 0,
                "opcode": high_risk[op_idx],
                "fd": 3,
                "sqe_flags": 0,
            }));
            prop_assert!(det.process(&ev).is_none(),
                "{} should be allowlisted even for opcode {}", allowed[proc_idx], high_risk[op_idx]);
        });
    }
}

// ═════════════════���═════════════════════════════════════════════════════
// Container Drift Detector — property tests
// ═══════════════════════════════════════════════════════════════════════

mod container_drift {
    use super::*;
    use innerwarden_sensor::detectors::container_drift::ContainerDriftDetector;

    /// INVARIANT: Any exec from overlay upper layer in a container
    /// by a non-allowlisted process MUST generate a Critical incident.
    #[test]
    fn drift_always_critical() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            filename in "/tmp/[a-z]{3,12}"
        )| {
            let allowlisted = ["apt", "dpkg", "yum", "dnf", "rpm", "apk",
                               "pip", "npm", "yarn", "gem", "cargo", "go",
                               "gcc", "cc", "ld", "make", "cmake", "rustc", "javac"];
            if allowlisted.iter().any(|a| comm.starts_with(a)) {
                return Ok(());
            }

            let mut det = ContainerDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "container_id": "abc123def456",
                "cgroup_id": 12345,
                "overlay_upper": true,
            }));
            let incident = det.process(&ev);
            prop_assert!(incident.is_some(),
                "drift exec by '{}' of '{}' should generate incident", comm, filename);
            prop_assert_eq!(incident.unwrap().severity, Severity::Critical);
        });
    }

    /// INVARIANT: Events WITHOUT overlay_upper=true NEVER generate incidents.
    #[test]
    fn non_drift_never_alerts() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            filename in "/usr/bin/[a-z]{3,12}"
        )| {
            let mut det = ContainerDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "container_id": "abc123",
                "cgroup_id": 12345,
                "overlay_upper": false,
            }));
            prop_assert!(det.process(&ev).is_none(),
                "non-drift event should never generate incident");
        });
    }

    /// INVARIANT: Events outside containers NEVER generate incidents.
    #[test]
    fn host_events_ignored() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            filename in "/tmp/[a-z]{3,12}"
        )| {
            let mut det = ContainerDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "container_id": "",
                "cgroup_id": 0,
                "overlay_upper": true,
            }));
            prop_assert!(det.process(&ev).is_none(),
                "host event with drift flag should be ignored");
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Host Drift Detector — property tests
// ════════════════════════════════════════════════════════════��══════════

mod host_drift {
    use super::*;
    use innerwarden_sensor::detectors::host_drift::HostDriftDetector;

    /// INVARIANT: Execution from /tmp/ by non-allowlisted process
    /// on the host ALWAYS generates a Critical incident.
    #[test]
    fn tmp_exec_always_critical() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            filename in "/tmp/[a-z]{3,12}"
        )| {
            let allowlisted = ["ld-linux", "ld.so", "ldconfig", "update",
                               "dpkg", "apt", "rpm", "yum", "snap", "flatpak",
                               "pip", "npm", "cargo", "go", "python", "node",
                               "java", "innerwarden"];
            if allowlisted.iter().any(|a| comm.starts_with(a)) {
                return Ok(());
            }

            let mut det = HostDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "cgroup_id": 0,
                "container_id": "",
            }));
            let incident = det.process(&ev);
            prop_assert!(incident.is_some(),
                "exec from /tmp by '{}' should generate incident", comm);
            prop_assert_eq!(incident.unwrap().severity, Severity::Critical);
        });
    }

    /// INVARIANT: Execution from trusted paths NEVER generates incidents.
    #[test]
    fn trusted_paths_never_alert() {
        let trusted = [
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/local/bin/",
            "/bin/",
            "/sbin/",
            "/opt/",
            "/snap/",
        ];

        proptest!(|(
            comm in "[a-z]{3,8}",
            path_idx in 0..trusted.len(),
            binary in "[a-z]{3,12}"
        )| {
            let filename = format!("{}{}", trusted[path_idx], binary);
            let mut det = HostDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "cgroup_id": 0,
                "container_id": "",
            }));
            prop_assert!(det.process(&ev).is_none(),
                "exec from trusted path '{}' should not alert", filename);
        });
    }

    /// INVARIANT: Container events NEVER trigger host drift.
    #[test]
    fn container_events_ignored() {
        proptest!(|(
            comm in "[a-z]{3,8}",
            filename in "/tmp/[a-z]{3,12}"
        )| {
            let mut det = HostDriftDetector::new("test", 0);
            let ev = make_event("shell.command_exec", serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "cgroup_id": 12345,
                "container_id": "abc123",
            }));
            prop_assert!(det.process(&ev).is_none(),
                "container event should not trigger host drift");
        });
    }
}
