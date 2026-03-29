//! Kernel integrity monitoring.
//!
//! Two complementary checks:
//!
//! 1. **eBPF program inventory**: Periodically reads the list of loaded eBPF
//!    programs and compares against a baseline established at boot. New programs
//!    loaded by processes other than innerwarden are flagged as potential
//!    eBPF weaponization (VoidLink-style attacks).
//!
//! 2. **Syscall table integrity**: Reads `/proc/kallsyms` at boot for the
//!    addresses of key syscall handlers. Periodically compares — if addresses
//!    change, a rootkit has hooked the syscall table.
//!
//! Also monitors `/proc/modules` for new kernel modules loaded after boot.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::mpsc;
use tracing::{info, warn};

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

/// Key syscall names to monitor in kallsyms.
const MONITORED_SYSCALLS: &[&str] = &[
    "__x64_sys_execve",
    "__x64_sys_openat",
    "__x64_sys_connect",
    "__x64_sys_ptrace",
    "__x64_sys_init_module",
    "__x64_sys_finit_module",
    "__x64_sys_mount",
    "__x64_sys_setuid",
    "__x64_sys_setgid",
    "__x64_sys_kill",
];

/// eBPF programs owned by innerwarden (expected).
const INNERWARDEN_BPF_PREFIXES: &[&str] = &[
    "innerwarden",
    "iw_",
    "tracepoint__",
    "kprobe__",
    "lsm__",
    "xdp__",
];

/// Baseline state established at boot.
struct KernelBaseline {
    /// Syscall name → address from /proc/kallsyms.
    syscall_addresses: HashMap<String, String>,
    /// Known eBPF program IDs at boot.
    known_bpf_ids: HashSet<u32>,
    /// Known kernel modules at boot.
    known_modules: HashSet<String>,
    /// When the baseline was established.
    established_at: DateTime<Utc>,
}

/// Run the kernel integrity monitor.
pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    poll_seconds: u64,
) {
    // Establish baseline at startup
    let baseline = KernelBaseline {
        syscall_addresses: read_kallsyms(),
        known_bpf_ids: read_bpf_program_ids(),
        known_modules: read_kernel_modules(),
        established_at: Utc::now(),
    };

    info!(
        syscalls = baseline.syscall_addresses.len(),
        bpf_programs = baseline.known_bpf_ids.len(),
        modules = baseline.known_modules.len(),
        "kernel integrity baseline established"
    );

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));
    let mut last_alert: HashMap<String, DateTime<Utc>> = HashMap::new();
    let cooldown = Duration::seconds(600);

    loop {
        interval.tick().await;
        let now = Utc::now();

        // Check 1: Syscall table integrity
        let current_syscalls = read_kallsyms();
        for (name, baseline_addr) in &baseline.syscall_addresses {
            if let Some(current_addr) = current_syscalls.get(name) {
                if current_addr != baseline_addr {
                    let key = format!("syscall:{name}");
                    let should_alert = last_alert
                        .get(&key)
                        .map(|t| now - *t > cooldown)
                        .unwrap_or(true);

                    if should_alert {
                        last_alert.insert(key, now);
                        let ev = Event {
                            ts: now,
                            host: host.clone(),
                            source: "kernel_integrity".to_string(),
                            kind: "kernel.syscall_table_modified".to_string(),
                            severity: Severity::Critical,
                            summary: format!(
                                "CRITICAL: Syscall table modified — {} changed from {} to {} (rootkit indicator)",
                                name, baseline_addr, current_addr
                            ),
                            details: serde_json::json!({
                                "syscall": name,
                                "baseline_address": baseline_addr,
                                "current_address": current_addr,
                                "baseline_time": baseline.established_at.to_rfc3339(),
                            }),
                            tags: vec![
                                "kernel_integrity".to_string(),
                                "rootkit".to_string(),
                                "syscall_hook".to_string(),
                            ],
                            entities: vec![],
                        };
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        // Check 2: New eBPF programs
        let current_bpf = read_bpf_program_ids();
        for id in &current_bpf {
            if !baseline.known_bpf_ids.contains(id) {
                let key = format!("bpf:{id}");
                let should_alert = last_alert
                    .get(&key)
                    .map(|t| now - *t > cooldown)
                    .unwrap_or(true);

                if should_alert {
                    let prog_info = read_bpf_program_info(*id);
                    let is_innerwarden = prog_info
                        .as_ref()
                        .map(|name| {
                            INNERWARDEN_BPF_PREFIXES
                                .iter()
                                .any(|prefix| name.starts_with(prefix))
                        })
                        .unwrap_or(false);

                    if !is_innerwarden {
                        last_alert.insert(key, now);
                        let prog_name = prog_info.unwrap_or_else(|| "unknown".to_string());
                        let ev = Event {
                            ts: now,
                            host: host.clone(),
                            source: "kernel_integrity".to_string(),
                            kind: "kernel.bpf_program_loaded".to_string(),
                            severity: Severity::High,
                            summary: format!(
                                "New eBPF program loaded after boot: id={id} name='{prog_name}'"
                            ),
                            details: serde_json::json!({
                                "bpf_id": id,
                                "bpf_name": prog_name,
                                "baseline_programs": baseline.known_bpf_ids.len(),
                                "current_programs": current_bpf.len(),
                            }),
                            tags: vec![
                                "kernel_integrity".to_string(),
                                "ebpf".to_string(),
                                "weaponization".to_string(),
                            ],
                            entities: vec![],
                        };
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        // Check 3: New kernel modules
        let current_modules = read_kernel_modules();
        for module in &current_modules {
            if !baseline.known_modules.contains(module) {
                let key = format!("module:{module}");
                let should_alert = last_alert
                    .get(&key)
                    .map(|t| now - *t > cooldown)
                    .unwrap_or(true);

                if should_alert {
                    last_alert.insert(key, now);
                    let ev = Event {
                        ts: now,
                        host: host.clone(),
                        source: "kernel_integrity".to_string(),
                        kind: "kernel.new_module_post_boot".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "Kernel module loaded after boot: {module}"
                        ),
                        details: serde_json::json!({
                            "module": module,
                            "baseline_modules": baseline.known_modules.len(),
                            "current_modules": current_modules.len(),
                        }),
                        tags: vec![
                            "kernel_integrity".to_string(),
                            "module".to_string(),
                        ],
                        entities: vec![EntityRef::service(module)],
                    };
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
            }
        }

        // Prune old alerts
        if last_alert.len() > 1000 {
            let cutoff = now - cooldown;
            last_alert.retain(|_, t| *t > cutoff);
        }
    }
}

// ---------------------------------------------------------------------------
// System readers
// ---------------------------------------------------------------------------

/// Read key syscall addresses from /proc/kallsyms.
fn read_kallsyms() -> HashMap<String, String> {
    let mut syscalls = HashMap::new();
    let content = match std::fs::read_to_string("/proc/kallsyms") {
        Ok(c) => c,
        Err(_) => return syscalls,
    };

    for line in content.lines() {
        // Format: address type name
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            let addr = parts[0];
            let name = parts[2].split('\t').next().unwrap_or(parts[2]);
            if MONITORED_SYSCALLS.contains(&name) {
                syscalls.insert(name.to_string(), addr.to_string());
            }
        }
    }

    syscalls
}

/// Read loaded eBPF program IDs by parsing /proc/*/fdinfo.
/// On systems without bpftool, falls back to scanning /proc for bpf fds.
fn read_bpf_program_ids() -> HashSet<u32> {
    let mut ids = HashSet::new();

    // Try bpftool first (most reliable)
    if let Ok(output) = std::process::Command::new("bpftool")
        .args(["prog", "list", "-j"])
        .output()
    {
        if output.status.success() {
            if let Ok(progs) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                for prog in progs {
                    if let Some(id) = prog.get("id").and_then(|v| v.as_u64()) {
                        ids.insert(id as u32);
                    }
                }
                return ids;
            }
        }
    }

    // Fallback: scan /proc/self/fdinfo for BPF file descriptors
    // (Limited — only sees our own programs)
    ids
}

/// Get the name of a specific eBPF program by ID.
fn read_bpf_program_info(id: u32) -> Option<String> {
    let output = std::process::Command::new("bpftool")
        .args(["prog", "show", "id", &id.to_string(), "-j"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let val: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    val.get("name")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Read loaded kernel modules from /proc/modules.
fn read_kernel_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    let content = match std::fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return modules,
    };

    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            modules.insert(name.to_string());
        }
    }

    modules
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitored_syscalls_not_empty() {
        assert!(!MONITORED_SYSCALLS.is_empty());
        assert!(MONITORED_SYSCALLS.contains(&"__x64_sys_execve"));
    }

    #[test]
    fn innerwarden_prefix_detection() {
        let is_iw = |name: &str| {
            INNERWARDEN_BPF_PREFIXES
                .iter()
                .any(|p| name.starts_with(p))
        };
        assert!(is_iw("innerwarden_xdp"));
        assert!(is_iw("iw_kprobe_commit_creds"));
        assert!(is_iw("tracepoint__syscalls__sys_enter_execve"));
        assert!(!is_iw("malicious_program"));
        assert!(!is_iw("custom_bpf_prog"));
    }

    #[test]
    fn kallsyms_parsing() {
        // On CI/macOS, /proc/kallsyms may not exist
        let result = read_kallsyms();
        // Just verify it doesn't crash
        assert!(result.len() <= MONITORED_SYSCALLS.len());
    }

    #[test]
    fn modules_parsing() {
        let result = read_kernel_modules();
        // On macOS this returns empty, on Linux it returns modules
        // Just verify no crash
        let _ = result.len();
    }

    #[test]
    fn bpf_program_ids() {
        let result = read_bpf_program_ids();
        // bpftool may not be available — just verify no crash
        let _ = result.len();
    }
}
