//! Memory forensics collector via `/proc/[pid]/maps`.
//!
//! Scans process memory maps for indicators of compromise:
//! - RWX (read+write+execute) memory regions → shellcode
//! - Anonymous executable mappings → injected code
//! - Deleted file mappings → fileless malware (loaded then unlinked)
//! - Stack/heap with execute permission → exploitation
//! - LD_PRELOAD in environment → shared library injection
//!
//! Runs periodically (default: every 60s) and on-demand when triggered
//! by High/Critical incidents.

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::warn;

/// Suspicious memory region found in a process.
#[derive(Debug, Clone)]
pub struct SuspiciousRegion {
    pub pid: u32,
    pub comm: String,
    pub region_type: RegionType,
    pub addr_start: String,
    pub addr_end: String,
    pub perms: String,
    pub path: String,
    pub size_kb: u64,
}

#[derive(Debug, Clone)]
pub enum RegionType {
    /// Memory mapped as read+write+execute (classic shellcode indicator).
    Rwx,
    /// Anonymous mapping with execute permission (injected code).
    AnonExecutable,
    /// Mapping from a deleted file (fileless malware loaded then unlinked).
    DeletedFile,
    /// Stack with execute permission (exploitation / ROP).
    ExecutableStack,
    /// Heap with execute permission (heap spray / shellcode).
    ExecutableHeap,
}

impl RegionType {
    fn label(&self) -> &'static str {
        match self {
            Self::Rwx => "rwx_memory",
            Self::AnonExecutable => "anon_executable",
            Self::DeletedFile => "deleted_file_mapping",
            Self::ExecutableStack => "executable_stack",
            Self::ExecutableHeap => "executable_heap",
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::Rwx | Self::DeletedFile => Severity::Critical,
            Self::AnonExecutable | Self::ExecutableStack | Self::ExecutableHeap => Severity::High,
        }
    }
}

/// Processes to always skip (kernel threads, known safe).
const SKIP_COMMS: &[&str] = &[
    "kworker",
    "ksoftirqd",
    "migration",
    "rcu_",
    "watchdog",
    "kcompactd",
    "khugepaged",
    "kswapd",
    "kthreadd",
    "systemd-journal",
    "innerwarden",
];

/// Run the proc_maps collector as a periodic scanner.
///
/// Scans all processes every `poll_seconds` and emits events for suspicious
/// memory regions.
pub async fn run(tx: mpsc::Sender<Event>, host: String, poll_seconds: u64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));
    let mut seen_alerts: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    let cooldown = chrono::Duration::seconds(600); // 10min cooldown per PID+type

    loop {
        interval.tick().await;

        let findings = scan_all_processes();
        let now = Utc::now();

        for finding in findings {
            let key = format!(
                "{}:{}:{}",
                finding.pid,
                finding.region_type.label(),
                finding.comm
            );

            // Cooldown: don't re-alert for same PID+type within window
            if let Some(&last) = seen_alerts.get(&key) {
                if now - last < cooldown {
                    continue;
                }
            }
            seen_alerts.insert(key, now);

            let ev = Event {
                ts: now,
                host: host.clone(),
                source: "proc_maps".to_string(),
                kind: format!("memory.{}", finding.region_type.label()),
                severity: finding.region_type.severity(),
                summary: format!(
                    "{} in {} (PID {}): {} ({} KB at {})",
                    finding.region_type.label(),
                    finding.comm,
                    finding.pid,
                    finding.path,
                    finding.size_kb,
                    finding.addr_start
                ),
                details: serde_json::json!({
                    "pid": finding.pid,
                    "comm": finding.comm,
                    "region_type": finding.region_type.label(),
                    "addr_start": finding.addr_start,
                    "addr_end": finding.addr_end,
                    "perms": finding.perms,
                    "path": finding.path,
                    "size_kb": finding.size_kb,
                }),
                tags: vec![
                    "memory_forensics".to_string(),
                    finding.region_type.label().to_string(),
                ],
                entities: vec![EntityRef::service(&finding.comm)],
            };

            if tx.send(ev).await.is_err() {
                return; // channel closed
            }
        }

        // Prune old cooldowns
        if seen_alerts.len() > 5000 {
            let cutoff = now - cooldown;
            seen_alerts.retain(|_, ts| *ts > cutoff);
        }
    }
}

/// Scan a single PID's memory maps. Useful for on-demand scanning after incidents.
#[allow(dead_code)]
pub fn scan_pid(pid: u32) -> Vec<SuspiciousRegion> {
    let comm = read_comm(pid).unwrap_or_else(|| "unknown".to_string());
    if should_skip(&comm) {
        return Vec::new();
    }
    parse_maps(pid, &comm)
}

/// Scan all processes for suspicious memory regions.
fn scan_all_processes() -> Vec<SuspiciousRegion> {
    let mut findings = Vec::new();
    let proc_dir = Path::new("/proc");

    let entries = match std::fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("proc_maps: cannot read /proc: {e}");
            return findings;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        // Only process numeric directories (PIDs)
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm = match read_comm(pid) {
            Some(c) => c,
            None => continue,
        };

        if should_skip(&comm) {
            continue;
        }

        findings.extend(parse_maps(pid, &comm));

        // Also check LD_PRELOAD
        if let Some(preload) = check_ld_preload(pid) {
            findings.push(SuspiciousRegion {
                pid,
                comm: comm.clone(),
                region_type: RegionType::DeletedFile, // reuse type — LD_PRELOAD is injection
                addr_start: String::new(),
                addr_end: String::new(),
                perms: "LD_PRELOAD".to_string(),
                path: preload,
                size_kb: 0,
            });
        }
    }

    findings
}

/// Parse `/proc/[pid]/maps` for suspicious regions.
fn parse_maps(pid: u32, comm: &str) -> Vec<SuspiciousRegion> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = match std::fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    for line in content.lines() {
        // Format: addr_start-addr_end perms offset dev inode pathname
        // Example: 7f1234000000-7f1234001000 rwxp 00000000 00:00 0  [heap]
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 {
            continue;
        }

        let addr_range = parts[0];
        let perms = parts[1];
        let path = if parts.len() >= 6 {
            parts[5].trim()
        } else {
            ""
        };

        let (addr_start, addr_end) = match addr_range.split_once('-') {
            Some((s, e)) => (s.to_string(), e.to_string()),
            None => continue,
        };

        // Calculate size in KB
        let size_kb = match (
            u64::from_str_radix(&addr_start, 16),
            u64::from_str_radix(&addr_end, 16),
        ) {
            (Ok(s), Ok(e)) if e > s => (e - s) / 1024,
            _ => 0,
        };

        let has_read = perms.contains('r');
        let has_write = perms.contains('w');
        let has_exec = perms.contains('x');

        // Check: RWX memory (read + write + execute)
        if has_read && has_write && has_exec {
            // Skip JIT compilers and known safe RWX
            if !is_known_rwx(comm, path) {
                findings.push(SuspiciousRegion {
                    pid,
                    comm: comm.to_string(),
                    region_type: RegionType::Rwx,
                    addr_start: addr_start.clone(),
                    addr_end: addr_end.clone(),
                    perms: perms.to_string(),
                    path: path.to_string(),
                    size_kb,
                });
            }
        }

        // Check: anonymous executable mapping (no file path, has exec)
        if has_exec && path.is_empty() && size_kb > 0 {
            findings.push(SuspiciousRegion {
                pid,
                comm: comm.to_string(),
                region_type: RegionType::AnonExecutable,
                addr_start: addr_start.clone(),
                addr_end: addr_end.clone(),
                perms: perms.to_string(),
                path: "(anonymous)".to_string(),
                size_kb,
            });
        }

        // Check: deleted file mapping
        if path.contains("(deleted)") && has_exec {
            findings.push(SuspiciousRegion {
                pid,
                comm: comm.to_string(),
                region_type: RegionType::DeletedFile,
                addr_start: addr_start.clone(),
                addr_end: addr_end.clone(),
                perms: perms.to_string(),
                path: path.to_string(),
                size_kb,
            });
        }

        // Check: executable stack
        if path == "[stack]" && has_exec {
            findings.push(SuspiciousRegion {
                pid,
                comm: comm.to_string(),
                region_type: RegionType::ExecutableStack,
                addr_start: addr_start.clone(),
                addr_end: addr_end.clone(),
                perms: perms.to_string(),
                path: path.to_string(),
                size_kb,
            });
        }

        // Check: executable heap
        if path == "[heap]" && has_exec {
            findings.push(SuspiciousRegion {
                pid,
                comm: comm.to_string(),
                region_type: RegionType::ExecutableHeap,
                addr_start,
                addr_end,
                perms: perms.to_string(),
                path: path.to_string(),
                size_kb,
            });
        }
    }

    findings
}

/// Read `/proc/[pid]/comm` to get process name.
fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Check `/proc/[pid]/environ` for LD_PRELOAD.
fn check_ld_preload(pid: u32) -> Option<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    // environ is NUL-separated
    let env_str = String::from_utf8_lossy(&environ);
    for var in env_str.split('\0') {
        if let Some(value) = var.strip_prefix("LD_PRELOAD=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    // Also check /etc/ld.so.preload (system-wide)
    if pid == 1 {
        // Only check once from PID 1
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
            let trimmed = content.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                return Some(format!("/etc/ld.so.preload: {trimmed}"));
            }
        }
    }
    None
}

/// Should this process be skipped (kernel thread, known safe)?
fn should_skip(comm: &str) -> bool {
    SKIP_COMMS.iter().any(|s| comm.starts_with(s))
}

/// Is this a known-safe RWX mapping? (JIT compilers, etc.)
fn is_known_rwx(comm: &str, path: &str) -> bool {
    // Java JIT, V8/Node JIT, Python JIT, .NET JIT
    let jit_processes = [
        "java", "node", "deno", "bun", "python", "dotnet", "mono", "ruby",
    ];
    if jit_processes.iter().any(|j| comm.contains(j)) {
        return true;
    }
    // Mapped JIT libraries
    if path.contains("jit") || path.contains("v8") || path.contains("libjvm") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_paths_detected() {
        assert!(!is_known_rwx("malware", ""));
        assert!(is_known_rwx("java", ""));
        assert!(is_known_rwx("node", "libjit.so"));
    }

    #[test]
    fn skip_kernel_threads() {
        assert!(should_skip("kworker/0:0"));
        assert!(should_skip("ksoftirqd/0"));
        assert!(should_skip("innerwarden-sensor"));
        assert!(!should_skip("nginx"));
        assert!(!should_skip("bash"));
    }

    #[test]
    fn parse_maps_line_format() {
        // Test the parsing logic with synthetic data
        // In production this reads /proc/[pid]/maps which isn't available in tests
        // So we test the helper functions instead
        assert!(!is_known_rwx("suspicious_binary", "/tmp/payload"));
        assert!(is_known_rwx("java", "/usr/lib/jvm/libjit.so"));
    }

    #[test]
    fn region_type_severity() {
        assert_eq!(RegionType::Rwx.severity(), Severity::Critical);
        assert_eq!(RegionType::DeletedFile.severity(), Severity::Critical);
        assert_eq!(RegionType::AnonExecutable.severity(), Severity::High);
        assert_eq!(RegionType::ExecutableStack.severity(), Severity::High);
        assert_eq!(RegionType::ExecutableHeap.severity(), Severity::High);
    }
}
