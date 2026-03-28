use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Directories where package managers install binaries.
const TRUSTED_PATHS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/opt/",
    "/snap/",
];

/// Paths where executables are expected but not from package managers.
/// These are NOT flagged as drift.
const DEVELOPMENT_PATHS: &[&str] = &[
    "/home/",           // user binaries, development
    "/root/",           // root home
    "/var/lib/docker/", // container layers
    "/run/",            // runtime mounts
    "/proc/",           // procfs
    "/sys/",            // sysfs
];

/// Processes that legitimately execute from non-standard paths.
const ALLOWED_PROCESSES: &[&str] = &[
    "ld-linux",
    "ld.so",
    "ldconfig",
    "update-alternatives",
    "dpkg",
    "apt",
    "rpm",
    "yum",
    "snap",
    "flatpak",
    "pip",
    "npm",
    "cargo",
    "go",
    "python",
    "node",
    "java",
    "innerwarden",
];

/// Detects execution of binaries from unexpected filesystem locations.
///
/// On a well-managed server, binaries should come from package managers
/// (installed in /usr/bin, /usr/sbin, /opt, etc). A binary executed from
/// /tmp, /dev/shm, /var/tmp, or a writable directory outside the trusted
/// paths is suspicious — possible malware, web shell, or post-exploitation.
///
/// This detector complements LSM exec blocking (which blocks /tmp, /dev/shm)
/// by also flagging executions from other non-standard paths that aren't
/// blocked but are suspicious.
pub struct HostDriftDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    /// Known good paths from a baseline scan (populated on startup)
    known_paths: HashSet<String>,
}

impl HostDriftDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            known_paths: HashSet::new(),
        }
    }

    /// Add a known-good executable path to the baseline.
    /// Called during startup from a dpkg/rpm scan.
    #[allow(dead_code)]
    pub fn add_known_path(&mut self, path: String) {
        self.known_paths.insert(path);
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        // Only process host events (not containers)
        let cgroup_id = event
            .details
            .get("cgroup_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let container_id = event
            .details
            .get("container_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !container_id.is_empty() || cgroup_id != 0 {
            return None; // Container events handled by container_drift detector
        }

        let filename = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("command").and_then(|v| v.as_str()))
            .unwrap_or("");
        if filename.is_empty() {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip allowlisted processes
        if is_allowed_process(comm) {
            return None;
        }

        // Skip if in trusted path
        if is_trusted_path(filename) || is_development_path(filename) {
            return None;
        }

        // Skip if in the known-good baseline
        if self.known_paths.contains(filename) {
            return None;
        }

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Classify severity based on path
        let severity = classify_path_severity(filename);

        let key = format!("host_drift:{filename}");
        if let Some(&last) = self.alerted.get(&key) {
            if event.ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, event.ts);

        if self.alerted.len() > 500 {
            let cutoff = event.ts - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!("host_drift:{comm}:{}", event.ts.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Host drift: {comm} executed from non-standard path"),
            summary: format!(
                "Binary '{filename}' was executed from a non-standard location. \
                 Process: {comm} (pid={pid}, uid={uid}). This path is not in the \
                 trusted package manager directories (/usr/bin, /usr/sbin, /opt, etc.) \
                 and was not in the system baseline."
            ),
            evidence: serde_json::json!([{
                "kind": "host_drift",
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "uid": uid,
            }]),
            recommended_checks: vec![
                format!("Inspect binary: file {filename} && sha256sum {filename}"),
                format!("Check provenance: dpkg -S {filename} || rpm -qf {filename}"),
                format!("Check process: ps -p {pid} -o pid,ppid,user,comm,args"),
                format!("Check file age: stat {filename}"),
            ],
            tags: vec!["host_drift".to_string(), "unexpected_binary".to_string()],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

fn is_trusted_path(path: &str) -> bool {
    TRUSTED_PATHS.iter().any(|p| path.starts_with(p))
}

fn is_development_path(path: &str) -> bool {
    DEVELOPMENT_PATHS.iter().any(|p| path.starts_with(p))
}

fn is_allowed_process(comm: &str) -> bool {
    ALLOWED_PROCESSES
        .iter()
        .any(|p| comm == *p || comm.starts_with(p))
}

fn classify_path_severity(path: &str) -> Severity {
    // High-risk temp directories (malware staging)
    if path.starts_with("/tmp/") || path.starts_with("/dev/shm/") || path.starts_with("/var/tmp/") {
        return Severity::Critical;
    }
    // World-writable or unusual locations
    if path.starts_with("/var/www/")
        || path.starts_with("/var/cache/")
        || path.contains("/.hidden")
        || path.contains("/...")
    {
        return Severity::High;
    }
    Severity::Medium
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn exec_event(comm: &str, filename: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} exec {filename}"),
            details: serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "cgroup_id": 0,
                "container_id": "",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_tmp_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("evil", "/tmp/payload");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_devshm_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("miner", "/dev/shm/xmrig");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_webroot_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("php", "/var/www/html/shell.php");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn allows_trusted_path() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("bash", "/usr/bin/bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_opt_path() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("innerwarden-sensor", "/opt/innerwarden/bin/sensor");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_container_events() {
        let mut det = HostDriftDetector::new("test", 300);
        let mut ev = exec_event("evil", "/tmp/payload");
        ev.details["container_id"] = serde_json::json!("abc123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn known_path_baseline() {
        let mut det = HostDriftDetector::new("test", 300);
        det.add_known_path("/custom/bin/mytool".to_string());
        let ev = exec_event("mytool", "/custom/bin/mytool");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_package_manager() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("dpkg", "/tmp/dpkg-tmp.123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_works() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("evil", "/tmp/payload");
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none());
    }
}
