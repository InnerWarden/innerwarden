use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Standard kernel modules that are commonly loaded by the system.
/// These are allowlisted to reduce false positives.
const ALLOWED_MODULES: &[&str] = &[
    "ext4",
    "xfs",
    "btrfs",
    "nfs",
    "nfsd",
    "ip_tables",
    "ip6_tables",
    "iptable_filter",
    "iptable_nat",
    "nf_conntrack",
    "nf_nat",
    "nf_tables",
    "nft_chain_nat",
    "veth",
    "overlay",
    "bridge",
    "br_netfilter",
    "dm_mod",
    "dm_crypt",
    "loop",
    "fuse",
    "tun",
    "tap",
    "bonding",
    "8021q",
    "vxlan",
    "wireguard",
];

/// Prefixes for standard modules that come in families (virtio_*, kvm*, hv_*).
const ALLOWED_PREFIXES: &[&str] = &["virtio_", "kvm", "hv_", "xen_", "vmw_", "nf_"];

/// Suspicious paths — loading from these indicates a rootkit or exploit.
const SUSPICIOUS_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/home/", "/var/tmp/"];

/// Detects runtime kernel module loading via insmod/modprobe/rmmod.
///
/// Kernel module loading at runtime can indicate rootkit installation or
/// privilege escalation. Standard system modules are allowlisted; anything
/// else raises High severity. Loading from /tmp, /dev/shm, or /home raises
/// Critical severity as a rootkit indicator.
pub struct KernelModuleLoadDetector {
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl KernelModuleLoadDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Check if a module name is in the allowlist.
    fn is_allowed_module(module: &str) -> bool {
        if ALLOWED_MODULES.contains(&module) {
            return true;
        }
        for prefix in ALLOWED_PREFIXES {
            if module.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Check if the command involves loading from a suspicious path.
    fn has_suspicious_path(command: &str) -> bool {
        SUSPICIOUS_PATHS.iter().any(|p| command.contains(p))
    }

    /// Extract the module name from the command string.
    /// Handles: "insmod /path/to/module.ko", "modprobe module_name", "rmmod module_name"
    fn extract_module_name(command: &str) -> Option<&str> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        // Find the argument after insmod/modprobe/rmmod
        for (i, part) in parts.iter().enumerate() {
            let base = part.rsplit('/').next().unwrap_or(part);
            if base == "insmod" || base == "modprobe" || base == "rmmod" {
                // Get the next non-flag argument
                for arg in &parts[i + 1..] {
                    if arg.starts_with('-') {
                        continue;
                    }
                    // For insmod, the argument is a path — extract the filename
                    if base == "insmod" {
                        let filename = arg.rsplit('/').next().unwrap_or(arg);
                        return Some(
                            filename.strip_suffix(".ko").unwrap_or(
                                filename.strip_suffix(".ko.xz").unwrap_or(
                                    filename.strip_suffix(".ko.zst").unwrap_or(filename),
                                ),
                            ),
                        );
                    }
                    return Some(arg);
                }
            }
        }
        None
    }

    /// Check if the command is a kernel module operation.
    fn is_module_command(command: &str) -> bool {
        let lower = command.to_lowercase();
        lower.contains("insmod") || lower.contains("modprobe") || lower.contains("rmmod")
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() || !Self::is_module_command(command) {
            return None;
        }

        let module_name = Self::extract_module_name(command).unwrap_or("unknown");

        // Skip allowlisted modules
        if Self::is_allowed_module(module_name) {
            return None;
        }

        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let now = event.ts;
        let alert_key = format!("kmod:{}:{}", module_name, comm);

        // Cooldown check
        if let Some(&last) = self.alerted.get(&alert_key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(alert_key, now);

        // Determine severity: Critical if loading from suspicious paths
        let severity = if Self::has_suspicious_path(command) {
            Severity::Critical
        } else {
            Severity::High
        };

        let summary = if Self::has_suspicious_path(command) {
            format!(
                "Rootkit indicator: kernel module {module_name} loaded from suspicious path by {comm} (pid={pid}, uid={uid})"
            )
        } else {
            format!(
                "Non-standard kernel module loaded: {module_name} by {comm} (pid={pid}, uid={uid})"
            )
        };

        // Prune stale entries
        if self.alerted.len() > 500 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "kernel_module:{}:{}:{}",
                module_name,
                comm,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Kernel module load detected: {module_name}"),
            summary,
            evidence: serde_json::json!([{
                "kind": "kernel_module_load",
                "module": module_name,
                "command": command,
                "comm": comm,
                "pid": pid,
                "uid": uid,
            }]),
            recommended_checks: vec![
                format!("Investigate module {module_name} — is it a known system module?"),
                format!("Check who loaded it: ps -o user= -p {pid}"),
                "List loaded modules: lsmod | grep suspicious".to_string(),
                format!("Check module file: modinfo {module_name}"),
                "If unexpected: rmmod the module and investigate the attack vector".to_string(),
            ],
            tags: vec![
                "kernel-module".to_string(),
                "persistence".to_string(),
                "rootkit".to_string(),
            ],
            entities: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn module_event(command: &str, comm: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 0,
                "ppid": 1,
                "comm": comm,
                "command": command,
            }),
            tags: vec!["ebpf".to_string(), "exec".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_insmod_unknown_module() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let inc = det.process(&module_event("insmod /opt/rootkit.ko", "bash", 1234, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("rootkit"));
    }

    #[test]
    fn detects_modprobe_unknown_module() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let inc = det.process(&module_event("modprobe evil_module", "bash", 1234, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("evil_module"));
    }

    #[test]
    fn detects_rmmod_unknown_module() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let inc = det.process(&module_event("rmmod evil_module", "bash", 1234, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn allows_standard_modules() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        assert!(det
            .process(&module_event("modprobe ext4", "mount", 100, now))
            .is_none());
        assert!(det
            .process(&module_event("modprobe nf_conntrack", "iptables", 101, now))
            .is_none());
        assert!(det
            .process(&module_event("modprobe overlay", "docker", 102, now))
            .is_none());
        assert!(det
            .process(&module_event(
                "insmod /lib/modules/5.15/veth.ko",
                "dockerd",
                103,
                now
            ))
            .is_none());
    }

    #[test]
    fn allows_prefix_modules() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        assert!(det
            .process(&module_event("modprobe virtio_net", "systemd", 100, now))
            .is_none());
        assert!(det
            .process(&module_event("modprobe kvm_intel", "qemu", 101, now))
            .is_none());
        assert!(det
            .process(&module_event("modprobe hv_vmbus", "systemd", 102, now))
            .is_none());
    }

    #[test]
    fn critical_for_suspicious_paths() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let inc = det.process(&module_event("insmod /tmp/rootkit.ko", "bash", 1234, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("Rootkit indicator"));

        let inc2 = det.process(&module_event(
            "insmod /dev/shm/backdoor.ko",
            "sh",
            1235,
            now,
        ));
        assert!(inc2.is_some());
        assert_eq!(inc2.unwrap().severity, Severity::Critical);

        let inc3 = det.process(&module_event("insmod /home/user/evil.ko", "sh", 1236, now));
        assert!(inc3.is_some());
        assert_eq!(inc3.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        assert!(det
            .process(&module_event("modprobe evil", "bash", 1234, now))
            .is_some());
        assert!(det
            .process(&module_event(
                "modprobe evil",
                "bash",
                1234,
                now + Duration::seconds(10)
            ))
            .is_none());
    }

    #[test]
    fn cooldown_expires_and_realerts() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        assert!(det
            .process(&module_event("modprobe evil", "bash", 1234, now))
            .is_some());
        assert!(det
            .process(&module_event(
                "modprobe evil",
                "bash",
                1234,
                now + Duration::seconds(601)
            ))
            .is_some());
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "not an exec".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn ignores_normal_commands() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        assert!(det
            .process(&module_event("ls -la /tmp", "bash", 1234, now))
            .is_none());
        assert!(det
            .process(&module_event("curl http://example.com", "curl", 1235, now))
            .is_none());
        assert!(det
            .process(&module_event("cat /etc/passwd", "cat", 1236, now))
            .is_none());
    }

    #[test]
    fn handles_process_exec_kind() {
        let mut det = KernelModuleLoadDetector::new("test", 600);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: "Process executed: insmod".to_string(),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 0,
                "ppid": 1,
                "comm": "insmod",
                "command": "insmod /opt/suspicious.ko",
            }),
            tags: vec!["ebpf".to_string(), "exec".to_string()],
            entities: vec![],
        };
        let inc = det.process(&event);
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("suspicious"));
    }
}
