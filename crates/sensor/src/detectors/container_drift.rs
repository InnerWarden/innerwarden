use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Containers that legitimately drop and execute binaries at runtime.
#[allow(dead_code)]
const ALLOWED_IMAGES: &[&str] = &[
    // CI/CD builders
    "docker.io/library/docker",
    "gcr.io/kaniko-project",
    "quay.io/buildah",
    // Package installer containers
    "docker.io/library/node",
    "docker.io/library/python",
    "docker.io/library/ruby",
    "docker.io/library/golang",
];

/// Processes that legitimately create executables inside containers.
const ALLOWED_PROCESSES: &[&str] = &[
    // Package managers
    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "pip", "pip3", "npm", "yarn", "gem",
    "cargo", "go", // Build tools
    "gcc", "cc", "ld", "make", "cmake", "rustc", "javac",
];

/// Detects execution of binaries not present in the original container image.
///
/// When a container runs, its image layers are mounted as read-only overlayfs
/// lower layers. Any file created or modified at runtime goes to the writable
/// upper layer. A binary in the upper layer that wasn't in the image is drift —
/// likely a dropped payload, web shell, or post-exploitation tool.
///
/// Detection: the eBPF execve hook checks `inode->i_sb->s_magic == OVERLAYFS_SUPER_MAGIC`
/// and then reads `ovl_inode.__upperdentry` to determine layer membership.
/// The `is_upper_layer` flag is set in the ExecveEvent and propagated here.
pub struct ContainerDriftDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

impl ContainerDriftDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process execve events with the upper_layer flag
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        // Check if the event has the overlay drift flag
        let is_upper = event
            .details
            .get("overlay_upper")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !is_upper {
            return None;
        }

        // Must be inside a container (cgroup_id != 0 or container_id present)
        let container_id = event
            .details
            .get("container_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cgroup_id = event
            .details
            .get("cgroup_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if container_id.is_empty() && cgroup_id == 0 {
            return None; // Not in a container
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let filename = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("command").and_then(|v| v.as_str()))
            .unwrap_or("unknown");
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

        // Skip allowlisted processes (package managers, build tools)
        if is_allowed_process(comm) {
            return None;
        }

        // Cooldown
        let key = format!("container_drift:{container_id}:{filename}");
        if let Some(&last) = self.alerted.get(&key) {
            if event.ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, event.ts);

        // Prune stale
        if self.alerted.len() > 500 {
            let cutoff = event.ts - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        let container_display = if container_id.is_empty() {
            format!("cgroup:{cgroup_id}")
        } else {
            container_id[..container_id.len().min(12)].to_string()
        };

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "container_drift:{container_display}:{comm}:{}",
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Container drift: {comm} executed from overlay upper layer in {container_display}"
            ),
            summary: format!(
                "Binary '{filename}' was executed inside container {container_display} \
                 but was NOT in the original image (found in overlayfs upper layer). \
                 Process: {comm} (pid={pid}, uid={uid}). This indicates a binary was \
                 dropped after container start — possible payload delivery, web shell, \
                 or post-exploitation tool."
            ),
            evidence: serde_json::json!([{
                "kind": "container_drift",
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "container_id": container_id,
                "cgroup_id": cgroup_id,
                "overlay_upper": true,
            }]),
            recommended_checks: vec![
                format!("Inspect the binary: docker exec {container_display} ls -la {filename}"),
                format!("Check container diff: docker diff {container_display} | grep {filename}"),
                "Review container image for expected executables".to_string(),
                format!("Check process tree: docker exec {container_display} ps -ef"),
            ],
            tags: vec![
                "container_drift".to_string(),
                "container".to_string(),
                "persistence".to_string(),
                "dropped_executable".to_string(),
            ],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

fn is_allowed_process(comm: &str) -> bool {
    ALLOWED_PROCESSES
        .iter()
        .any(|p| comm == *p || comm.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn drift_event(comm: &str, filename: &str, container_id: &str) -> Event {
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
                "container_id": container_id,
                "cgroup_id": 12345,
                "overlay_upper": true,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn normal_event(comm: &str, filename: &str) -> Event {
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
                "container_id": "abc123",
                "cgroup_id": 12345,
                "overlay_upper": false,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_drift() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev = drift_event("malware", "/tmp/payload", "abc123def456");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"container_drift".to_string()));
    }

    #[test]
    fn ignores_lower_layer() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev = normal_event("nginx", "/usr/sbin/nginx");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_host_process() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let mut ev = drift_event("malware", "/tmp/payload", "");
        // No container_id AND cgroup_id = 0 → host
        ev.details["cgroup_id"] = serde_json::json!(0);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_package_manager() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev = drift_event("apt-get", "/usr/bin/new-tool", "abc123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_build_tool() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev = drift_event("gcc", "/tmp/a.out", "builder123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_works() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev = drift_event("evil", "/tmp/shell", "abc123");
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn different_files_not_suppressed() {
        let mut det = ContainerDriftDetector::new("test", 300);
        let ev1 = drift_event("evil", "/tmp/shell1", "abc123");
        let ev2 = drift_event("evil", "/tmp/shell2", "abc123");
        assert!(det.process(&ev1).is_some());
        assert!(det.process(&ev2).is_some());
    }
}
