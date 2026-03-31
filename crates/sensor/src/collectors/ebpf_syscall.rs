//! eBPF syscall collector - kernel-level visibility via tracepoints.
//!
//! Replaces (or complements) audit-based collection with zero-latency
//! kernel-level process execution and network connection monitoring.
//!
//! Requires: Linux kernel 5.8+, CAP_BPF + CAP_PERFMON (or root).
//! Gracefully disables itself when eBPF is not available.

#![allow(dead_code, unused_imports)]
// Functions are used only when compiled with --features ebpf

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Embedded eBPF bytecode (compiled into the sensor binary).
/// Built with: cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
/// When the feature `ebpf-embedded` is enabled, the bytecode is baked into the binary
/// via include_bytes! - no separate file needed. `innerwarden upgrade` updates everything.
#[cfg(feature = "ebpf-embedded")]
const EBPF_BYTECODE_EMBEDDED: &[u8] =
    include_bytes!("../../../sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf");

/// Fallback paths for when bytecode is NOT embedded (dev mode or separate deploy).
const EBPF_OBJ_PATH: &str = "/usr/local/lib/innerwarden/innerwarden-ebpf";
const EBPF_OBJ_PATH_DEV: &str =
    "crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf";

/// Check if eBPF is available on this system.
pub fn is_ebpf_available() -> bool {
    if cfg!(not(target_os = "linux")) {
        return false;
    }

    // Kernel version >= 5.8
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let parts: Vec<u32> = release
            .trim()
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() >= 2 && (parts[0] < 5 || (parts[0] == 5 && parts[1] < 8)) {
            return false;
        }
    } else {
        return false;
    }

    // BTF available
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return false;
    }

    // eBPF bytecode exists
    std::path::Path::new(EBPF_OBJ_PATH).exists() || std::path::Path::new(EBPF_OBJ_PATH_DEV).exists()
}

/// Find the eBPF bytecode file.
fn find_ebpf_obj() -> Option<String> {
    if std::path::Path::new(EBPF_OBJ_PATH).exists() {
        Some(EBPF_OBJ_PATH.to_string())
    } else if std::path::Path::new(EBPF_OBJ_PATH_DEV).exists() {
        Some(EBPF_OBJ_PATH_DEV.to_string())
    } else {
        None
    }
}

/// Resolve parent PID from /proc/<pid>/status. Best-effort (returns 0 on failure).
fn resolve_ppid(pid: u32) -> u32 {
    let path = format!("/proc/{pid}/status");
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Extract container ID from /proc/<pid>/cgroup. Returns None for host processes.
fn resolve_container_id(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        // Docker: 0::/docker/<container_id>
        // Podman: 0::/libpod-<container_id>.scope
        // k8s:    0::/kubepods/besteffort/pod<uuid>/<container_id>
        if let Some(rest) = line.split("docker/").nth(1) {
            let id = rest.split('/').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(id[..12].to_string());
            }
        }
        if let Some(rest) = line.split("libpod-").nth(1) {
            let id = rest.split('.').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(id[..12].to_string());
            }
        }
        if line.contains("kubepods") {
            // Last segment is the container ID
            if let Some(id) = line.rsplit('/').next() {
                if id.len() >= 12 {
                    return Some(id[..12].to_string());
                }
            }
        }
    }
    None
}

/// Convert a kernel execve event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn execve_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    host: &str,
) -> Event {
    let argv_json: Vec<serde_json::Value> = if filename.is_empty() {
        vec![serde_json::Value::String(comm.to_string())]
    } else {
        vec![serde_json::Value::String(filename.to_string())]
    };

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "command": filename,
        "argv": argv_json,
        "argc": 1,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "exec".to_string()];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary: format!("Shell command executed: {filename}"),
        details,
        tags,
        entities,
    }
}

/// Convert a kernel connect event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn connect_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    host: &str,
) -> Event {
    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "dst_ip": dst_ip.to_string(),
        "dst_port": dst_port,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "network".to_string()];
    let mut entities = vec![EntityRef::ip(dst_ip.to_string())];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "network.outbound_connect".to_string(),
        severity: if dst_port == 4444 || dst_port == 1337 || dst_port == 31337 {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!("{comm} (pid={pid}) connecting to {dst_ip}:{dst_port}"),
        details,
        tags,
        entities,
    }
}

/// Convert a kernel file open event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn file_open_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    flags: u32,
    host: &str,
) -> Event {
    let is_write = flags & 0x3 != 0; // O_WRONLY or O_RDWR

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "filename": filename,
        "flags": flags,
        "write": is_write,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "file".to_string()];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: if is_write {
            "file.write_access".to_string()
        } else {
            "file.read_access".to_string()
        },
        severity: if is_write
            && (filename.contains("shadow")
                || filename.contains("sudoers")
                || filename.contains("authorized_keys"))
        {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!(
            "{comm} (pid={pid}) {} {filename}",
            if is_write { "writing" } else { "reading" }
        ),
        details,
        tags,
        entities,
    }
}

/// Processes that legitimately escalate to root - filtered in userspace.
const LEGITIMATE_ESCALATION: &[&str] = &[
    "sudo",
    "su",
    "login",
    "sshd",
    "cron",
    "crond",
    "atd",
    "polkitd",
    "pkexec",
    "systemd",
    "dbus-daemon",
    "gdm",
    "lightdm",
    "sddm",
    "newgrp",
    // Package managers and system tools that use SUID/setuid
    "install",
    "find",
    "mandb",
    "man",
    "dpkg",
    "apt",
    "apt-get",
    "apt-check",
    "unattended-upg", // unattended-upgrades (truncated comm)
    "update-notifier",
    "snap",
    "snapd",
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "usermod",
    "useradd",
    "groupadd",
    "at",
    "fusermount",
    "mount",
    "umount",
    "ping",
    "traceroute",
    "ssh-agent",
    "gpg-agent",
    "gpg",
    "ntpd",
    "chronyd",
    "logrotate",
    "run-parts",
    "anacron",
    "innerwarden",    // our own agent/sensor using sudo for bpftool/ufw
    "innerwarden-ag", // truncated comm (16 char limit)
    "innerwarden-se",
    "innerwarden-ct", // innerwarden-ctl
    "fwupdmgr",       // firmware update manager
];

/// Convert a kernel privilege escalation event to an Inner Warden Event.
fn privesc_to_event(
    pid: u32,
    old_uid: u32,
    new_uid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    host: &str,
) -> Option<Event> {
    let comm_base = comm.split('/').next_back().unwrap_or(comm);

    // Filter legitimate escalation processes.
    // Use starts_with to handle kernel comm truncation (16 char limit).
    if LEGITIMATE_ESCALATION
        .iter()
        .any(|p| comm_base.starts_with(p))
    {
        return None;
    }

    let severity = if container_id.is_some() {
        Severity::Critical // escalation inside container is always critical
    } else {
        Severity::High
    };

    let mut details = serde_json::json!({
        "pid": pid,
        "old_uid": old_uid,
        "new_uid": new_uid,
        "comm": comm,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec![
        "ebpf".to_string(),
        "kprobe".to_string(),
        "privesc".to_string(),
    ];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    let summary = if let Some(cid) = container_id {
        format!(
            "Privilege escalation: {comm} (pid={pid}) uid {old_uid} → {new_uid} [container {cid}]"
        )
    } else {
        format!("Privilege escalation: {comm} (pid={pid}) uid {old_uid} → {new_uid}")
    };

    Some(Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "privilege.escalation".to_string(),
        severity,
        summary,
        details,
        tags,
        entities,
    })
}

/// Extract a null-terminated string from a byte slice.
fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

/// Pin path for the XDP blocklist BPF map.
/// The agent writes to this map via bpftool to add/remove blocked IPs.
const XDP_PIN_DIR: &str = "/sys/fs/bpf/innerwarden";
const XDP_BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";
const XDP_ALLOWLIST_PIN: &str = "/sys/fs/bpf/innerwarden/allowlist";

/// Detect the default network interface for XDP attachment.
fn detect_default_interface() -> Option<String> {
    // Read /proc/net/route - first non-loopback default route
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                return Some(fields[0].to_string());
            }
        }
    }
    None
}

/// Pin path for the LSM policy map.
const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";
/// Pin path for per-cgroup capability map.
const CGROUP_CAP_PIN: &str = "/sys/fs/bpf/innerwarden/cgroup_capabilities";
/// Pin path for per-comm capability map.
const COMM_CAP_PIN: &str = "/sys/fs/bpf/innerwarden/comm_capabilities";

/// Attach LSM execution policy and pin the policy map.
/// Requires `lsm=...,bpf` in kernel boot cmdline.
/// Non-critical - if LSM is not available, the sensor continues without it.
#[cfg(feature = "ebpf")]
fn attach_lsm(bpf: &mut aya::Ebpf) {
    use aya::programs::Lsm;

    match bpf.program_mut("innerwarden_lsm_exec") {
        Some(prog) => {
            let lsm: &mut Lsm = match prog.try_into() {
                Ok(l) => l,
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_exec: not available (kernel may lack lsm=bpf)");
                    return;
                }
            };

            let btf = aya::Btf::from_sys_fs().ok();
            if let Err(e) = lsm.load("bprm_check_security", &btf.as_ref().unwrap()) {
                info!(error = %e, "innerwarden_lsm_exec: BPF LSM not enabled in kernel (add lsm=bpf to boot cmdline)");
                return;
            }
            if let Err(e) = lsm.attach() {
                warn!(error = %e, "innerwarden_lsm_exec: failed to attach");
                return;
            }
            info!("eBPF: innerwarden_lsm_exec → bprm_check_security (LSM enforcement) ✅");
        }
        None => {
            info!("eBPF: innerwarden_lsm_exec program not found - LSM not available");
            return;
        }
    }

    // Attach LSM file_open hook for sensitive path write protection.
    // Non-critical — if it fails, we still have observe-only via the openat tracepoint.
    match bpf.program_mut("innerwarden_lsm_file_open") {
        Some(prog) => {
            let lsm: &mut Lsm = match prog.try_into() {
                Ok(l) => l,
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_file_open: not available");
                    // Continue — the exec LSM is the critical one
                    return pin_lsm_policy(bpf);
                }
            };
            let btf = aya::Btf::from_sys_fs().ok();
            if let Err(e) = lsm.load("file_open", &btf.as_ref().unwrap()) {
                info!(error = %e, "innerwarden_lsm_file_open: failed to load");
            } else if let Err(e) = lsm.attach() {
                warn!(error = %e, "innerwarden_lsm_file_open: failed to attach");
            } else {
                info!("eBPF: innerwarden_lsm_file_open → file_open (sensitive path protection) ✅");
            }
        }
        None => {
            info!(
                "eBPF: innerwarden_lsm_file_open not found — sensitive path blocking unavailable"
            );
        }
    }

    // Phase 2: LSM bpf hook — monitor eBPF program loading (VoidLink defense)
    match bpf.program_mut("innerwarden_lsm_bpf") {
        Some(prog) => {
            let lsm: &mut aya::programs::Lsm = match prog.try_into() {
                Ok(l) => l,
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_bpf: not available");
                    pin_lsm_policy(bpf);
                    return;
                }
            };
            let btf = aya::Btf::from_sys_fs().ok();
            if let Err(e) = lsm.load("bpf", &btf.as_ref().unwrap()) {
                info!(error = %e, "innerwarden_lsm_bpf: failed to load");
            } else if let Err(e) = lsm.attach() {
                warn!(error = %e, "innerwarden_lsm_bpf: failed to attach");
            } else {
                info!("eBPF: innerwarden_lsm_bpf → bpf (eBPF program loading) ✅");
            }
        }
        None => {
            info!("eBPF: innerwarden_lsm_bpf not found — BPF load monitoring unavailable");
        }
    }

    pin_lsm_policy(bpf);
}

#[cfg(feature = "ebpf")]
fn pin_lsm_policy(bpf: &mut aya::Ebpf) {
    // Pin the LSM_POLICY map so the agent can enable/disable enforcement.
    // Remove stale pin first — on sensor restart, the old pin points to a dead
    // map from the previous instance, causing map.pin() to fail with EEXIST.
    if let Some(map) = bpf.map_mut("LSM_POLICY") {
        let _ = std::fs::remove_file(LSM_POLICY_PIN);
        if let Err(e) = map.pin(LSM_POLICY_PIN) {
            warn!(error = %e, "LSM: failed to pin policy map");
        } else {
            info!("eBPF: LSM policy map pinned at {LSM_POLICY_PIN}");
            info!("eBPF: LSM enforcement is OFF by default - enable via: bpftool map update pinned {LSM_POLICY_PIN} key 0 0 0 0 value 1 0 0 0");
        }
    }

    // Pin capability maps so the agent can grant per-cgroup/per-comm permissions.
    for (map_name, pin_path) in [
        ("CGROUP_CAPABILITIES", CGROUP_CAP_PIN),
        ("COMM_CAPABILITIES", COMM_CAP_PIN),
    ] {
        if let Some(map) = bpf.map_mut(map_name) {
            let _ = std::fs::remove_file(pin_path);
            if let Err(e) = map.pin(pin_path) {
                warn!(error = %e, "{map_name}: failed to pin");
            } else {
                info!("eBPF: {map_name} pinned at {pin_path}");
            }
        }
    }

    // Populate INODE_SIZE map for overlayfs drift detection (Falco trick).
    // sizeof(struct inode) varies by kernel config; query BTF at runtime.
    populate_inode_size(bpf);
}

/// Query sizeof(struct inode) from kernel BTF and write it to the INODE_SIZE map.
/// This enables the eBPF overlay drift detector to find ovl_inode.__upperdentry
/// at (inode_ptr + sizeof(struct inode)) without needing BTF for the private ovl_inode.
#[cfg(feature = "ebpf")]
fn populate_inode_size(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap as BpfHashMap;

    // Try to get sizeof(struct inode) from BTF via bpftool
    let inode_size = match std::process::Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            let btf_dump = String::from_utf8_lossy(&output.stdout);
            // Parse: look for "struct inode {" and count to closing "}"
            // This is heuristic — production should use proper BTF parsing.
            // Fallback: use bpftool to query the size directly.
            None.or_else(|| {
                // Try bpftool btf dump id 1 to get struct sizes
                let size_output = std::process::Command::new("bpftool")
                    .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux"])
                    .output()
                    .ok()?;
                let text = String::from_utf8_lossy(&size_output.stdout);
                // Look for: [NNN] STRUCT 'inode' size=XXX
                for line in text.lines() {
                    if line.contains("STRUCT 'inode'") && line.contains("size=") {
                        if let Some(size_str) = line.split("size=").nth(1) {
                            let size_str = size_str.split_whitespace().next().unwrap_or("0");
                            if let Ok(size) = size_str.parse::<u64>() {
                                if size > 100 && size < 2000 {
                                    return Some(size);
                                }
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| {
                // If BTF dump doesn't contain it, try the raw text from format c
                // and look for "} __attribute__((preserve_access_index));"
                // after "struct inode {"
                drop(btf_dump);
                0
            })
        }
        _ => 0,
    };

    if inode_size == 0 {
        info!("eBPF: could not determine sizeof(struct inode) from BTF — container drift detection disabled");
        info!("eBPF: ensure bpftool is installed and /sys/kernel/btf/vmlinux exists");
        return;
    }

    if let Some(map) = bpf.map_mut("INODE_SIZE") {
        let mut hash: BpfHashMap<_, u32, u64> = match map.try_into() {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "INODE_SIZE map: wrong type");
                return;
            }
        };
        if let Err(e) = hash.insert(0u32, inode_size, 0) {
            warn!(error = %e, "INODE_SIZE map: failed to insert");
        } else {
            info!(
                inode_size,
                "eBPF: container drift detection enabled (sizeof(struct inode) = {inode_size})"
            );
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn attach_lsm(_bpf: &mut ()) {}

/// Attach XDP firewall program and pin the blocklist map.
/// Non-critical - if it fails, the sensor continues without XDP.
#[cfg(feature = "ebpf")]
fn attach_xdp(bpf: &mut aya::Ebpf) {
    use aya::programs::{Xdp, XdpFlags};

    let iface = match detect_default_interface() {
        Some(i) => i,
        None => {
            warn!("XDP: no default network interface found - skipping XDP firewall");
            return;
        }
    };

    match bpf.program_mut("innerwarden_xdp") {
        Some(prog) => {
            let xdp: &mut Xdp = match prog.try_into() {
                Ok(x) => x,
                Err(e) => {
                    warn!(error = %e, "innerwarden_xdp: not an XDP program");
                    return;
                }
            };
            if let Err(e) = xdp.load() {
                warn!(error = %e, "innerwarden_xdp: failed to load");
                return;
            }
            // Use SKB mode (generic) for maximum compatibility.
            // Native mode (XdpFlags::default()) is faster but requires driver support.
            if let Err(e) = xdp.attach(&iface, XdpFlags::SKB_MODE) {
                warn!(error = %e, iface = %iface, "innerwarden_xdp: failed to attach");
                return;
            }
            info!(iface = %iface, "eBPF: innerwarden_xdp → {iface} (XDP firewall) ✅");
        }
        None => {
            info!("eBPF: innerwarden_xdp program not found - XDP firewall not available");
            return;
        }
    }

    // Pin the BLOCKLIST map so the agent can access it via bpftool
    if let Err(e) = std::fs::create_dir_all(XDP_PIN_DIR) {
        warn!(error = %e, "XDP: failed to create pin directory {XDP_PIN_DIR}");
        return;
    }
    if let Some(map) = bpf.map_mut("BLOCKLIST") {
        let _ = std::fs::remove_file(XDP_BLOCKLIST_PIN);
        if let Err(e) = map.pin(XDP_BLOCKLIST_PIN) {
            warn!(error = %e, "XDP: failed to pin blocklist map");
        } else {
            info!("eBPF: XDP blocklist pinned at {XDP_BLOCKLIST_PIN}");
        }
    }

    // Pin the ALLOWLIST map for operator-managed never-drop IPs
    if let Some(map) = bpf.map_mut("ALLOWLIST") {
        let _ = std::fs::remove_file(XDP_ALLOWLIST_PIN);
        if let Err(e) = map.pin(XDP_ALLOWLIST_PIN) {
            warn!(error = %e, "XDP: failed to pin allowlist map");
        } else {
            info!("eBPF: XDP allowlist pinned at {XDP_ALLOWLIST_PIN}");
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn attach_xdp(_bpf: &mut ()) {}

/// Start the eBPF collector. Loads programs, attaches tracepoints, reads ring buffer.
///
/// Events flow through the same mpsc channel as all other collectors.
// ---------------------------------------------------------------------------
// Kernel filter population - Falco-derived allowlists
// ---------------------------------------------------------------------------
//
// Handler bitmask for COMM_ALLOWLIST:
//   bit 0 = execve, 1 = connect, 2 = openat, 3 = ptrace,
//   4 = setuid, 5 = bind, 6 = mount, 7 = memfd, 8 = init_module
//
// Sources: falcosecurity/rules (falco_rules.yaml), adapted for Inner Warden.

#[cfg(feature = "ebpf")]
fn populate_kernel_filters(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap;

    // --- COMM_ALLOWLIST: safe processes per handler ---
    if let Ok(mut map) =
        HashMap::<_, [u8; 16], u32>::try_from(bpf.map_mut("COMM_ALLOWLIST").unwrap())
    {
        // Helper: create 16-byte key from comm name
        let key = |name: &str| -> [u8; 16] {
            let mut k = [0u8; 16];
            let bytes = name.as_bytes();
            k[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
            k
        };

        const EXECVE: u32 = 1 << 0;
        const CONNECT: u32 = 1 << 1;
        const OPENAT: u32 = 1 << 2;
        const PTRACE: u32 = 1 << 3;
        const SETUID: u32 = 1 << 4;
        const BIND: u32 = 1 << 5;
        // bit 6 = mount (never allowlisted)
        // bit 7 = memfd
        // bit 8 = init_module (never allowlisted)

        // Package managers - noisy on execve, openat, connect
        for comm in [
            "apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "snap", "apk", "pip", "pip3", "conda",
            "npm", "gem",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT | CONNECT, 0);
        }

        // Build tools - noisy on execve, openat
        for comm in [
            "cargo", "rustc", "gcc", "g++", "cc1", "cc1plus", "clang", "ld", "ar", "make", "cmake",
            "ninja", "javac", "go",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT, 0);
        }

        // Coreutils - noisy on openat, execve (spawned constantly by scripts)
        for comm in [
            "cat", "ls", "cp", "mv", "rm", "mkdir", "chmod", "chown", "ln", "head", "tail", "wc",
            "sort", "cut", "tr", "sed", "awk", "grep", "find", "xargs", "tee", "touch", "date",
            "sleep", "true", "false", "echo", "env", "pwd", "id", "whoami", "basename", "dirname",
            "readlink", "stat", "test", "seq", "yes", "dd", "df", "du", "uname", "mktemp",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT, 0);
        }

        // System daemons - allowed on setuid, connect, openat, bind
        for comm in [
            "systemd",
            "systemd-logind",
            "systemd-resolve",
            "systemd-timesyn",
            "systemd-network",
        ] {
            let _ = map.insert(key(comm), SETUID | CONNECT | OPENAT | BIND, 0);
        }

        // SSH daemons - allowed on setuid (legitimate priv change), bind
        for comm in ["sshd", "sshd-session"] {
            let _ = map.insert(key(comm), SETUID | BIND, 0);
        }

        // Auth/login - allowed on setuid
        for comm in [
            "sudo",
            "su",
            "login",
            "cron",
            "crond",
            "polkitd",
            "dbus-daemon",
        ] {
            let _ = map.insert(key(comm), SETUID, 0);
        }

        // Web/DB servers - allowed on bind (they legitimately bind ports)
        for comm in [
            "nginx",
            "apache2",
            "httpd",
            "redis-server",
            "mysqld",
            "postgres",
            "mongod",
            "memcached",
        ] {
            let _ = map.insert(key(comm), BIND, 0);
        }

        // Container runtimes - allowed on bind, connect, openat
        for comm in [
            "dockerd",
            "containerd",
            "containerd-shim",
            "runc",
            "crio",
            "podman",
        ] {
            let _ = map.insert(key(comm), BIND | CONNECT | OPENAT, 0);
        }

        // Debuggers - allowed on ptrace (their whole purpose)
        for comm in ["gdb", "strace", "ltrace", "lldb", "perf", "valgrind"] {
            let _ = map.insert(key(comm), PTRACE, 0);
        }

        // Monitoring agents - noisy on openat, connect
        for comm in [
            "prometheus",
            "node_exporter",
            "grafana",
            "telegraf",
            "collectd",
            "fluentd",
            "filebeat",
        ] {
            let _ = map.insert(key(comm), OPENAT | CONNECT, 0);
        }

        // Log rotation / coreutils - allowed on unlink, rename
        const UNLINK: u32 = 1 << 13;
        const RENAME: u32 = 1 << 14;
        for comm in ["logrotate", "journald", "rsyslogd", "systemd-journal"] {
            let _ = map.insert(key(comm), UNLINK | RENAME | OPENAT, 0);
        }

        // JIT runtimes - allowed on mprotect (they make memory executable legitimately)
        const MPROTECT: u32 = 1 << 11;
        for comm in [
            "node", "python3", "python", "java", "ruby", "php", "dotnet", "mono", "v8", "wasmtime",
        ] {
            let _ = map.insert(key(comm), MPROTECT, 0);
        }

        // Container runtimes - also allowed on clone, dup, listen, accept
        const DUP: u32 = 1 << 9;
        const LISTEN: u32 = 1 << 10;
        const CLONE: u32 = 1 << 12;
        const ACCEPT: u32 = 1 << 17;
        for comm in [
            "dockerd",
            "containerd",
            "containerd-shim",
            "runc",
            "crio",
            "podman",
        ] {
            let _ = map.insert(
                key(comm),
                BIND | CONNECT | OPENAT | CLONE | DUP | LISTEN | ACCEPT,
                0,
            );
        }

        // Shells - allowed on dup, clone (normal shell behavior)
        for comm in ["bash", "sh", "zsh", "dash", "ash", "fish", "tcsh", "ksh"] {
            let _ = map.insert(key(comm), DUP | CLONE, 0);
        }

        // Inner Warden itself - skip everything except mount + init_module
        let all_but_critical = EXECVE
            | CONNECT
            | OPENAT
            | PTRACE
            | SETUID
            | BIND
            | DUP
            | LISTEN
            | MPROTECT
            | CLONE
            | UNLINK
            | RENAME
            | ACCEPT;
        for comm in [
            "innerwarden-sen",
            "innerwarden-age",
            "innerwarden-dna",
            "innerwarden-shi",
        ] {
            let _ = map.insert(key(comm), all_but_critical, 0);
        }

        let count = map.keys().count();
        tracing::info!(count, "eBPF: COMM_ALLOWLIST populated");
    } else {
        tracing::warn!("eBPF: COMM_ALLOWLIST map not found - kernel filters disabled");
    }
}

/// Attach a typed tracepoint program - helper to eliminate repetition.
/// Returns true if the program was found, loaded, and attached successfully.
#[cfg(feature = "ebpf")]
fn attach_tp(bpf: &mut aya::Ebpf, name: &str, category: &str, tp_name: &str) -> bool {
    use aya::programs::TracePoint;

    if let Some(prog) = bpf.program_mut(name) {
        if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog) {
            if tp.load().is_ok() {
                if let Err(e) = tp.attach(category, tp_name) {
                    warn!(error = %e, "{name}: failed to attach to {category}/{tp_name}");
                } else {
                    info!("eBPF: {name} → {tp_name} ✅");
                    return true;
                }
            }
        }
    }
    false
}

/// Attach the syscall dispatcher - single raw_tracepoint on sys_enter that
/// tail-calls per-syscall handlers via a SYSCALL_DISPATCH ProgramArray.
///
/// This is more efficient than 18 individual typed tracepoints because the
/// kernel only fires one BPF program per syscall entry instead of scanning
/// all tracepoints.
///
/// Returns true if the dispatcher was loaded and at least one handler was
/// inserted into the dispatch table.
///
/// aarch64 syscall numbers (from include/uapi/asm-generic/unistd.h):
///   execve=221, connect=203, openat=56, ptrace=117, setuid=146,
///   bind=200, mount=40, memfd_create=279, init_module=105, dup2=n/a (dup3=24),
///   listen=201, mprotect=226, clone=220, unlinkat=35, renameat2=276,
///   kill=129, prctl=167, accept4=242
#[cfg(feature = "ebpf")]
fn attach_dispatcher(bpf: &mut aya::Ebpf) -> bool {
    use aya::maps::{Array, HashMap, ProgramArray};
    use aya::programs::RawTracePoint;

    // --- 1. Load and attach the dispatcher to raw_tracepoint/sys_enter ---
    let dispatcher_ok = if let Some(prog) = bpf.program_mut("innerwarden_dispatcher") {
        match TryInto::<&mut RawTracePoint>::try_into(prog) {
            Ok(rtp) => {
                if let Err(e) = rtp.load() {
                    warn!(error = %e, "dispatcher: failed to load");
                    return false;
                }
                if let Err(e) = rtp.attach("sys_enter") {
                    warn!(error = %e, "dispatcher: failed to attach to sys_enter");
                    return false;
                }
                info!("eBPF: innerwarden_dispatcher → raw_tracepoint/sys_enter ✅");
                true
            }
            Err(e) => {
                warn!(error = %e, "dispatcher: not a RawTracePoint program");
                return false;
            }
        }
    } else {
        return false;
    };

    if !dispatcher_ok {
        return false;
    }

    // --- 2. Load each dispatch_* handler as RawTracePoint (no attach - called via tail_call) ---
    // (name_in_elf, syscall_nr on aarch64)
    let handlers: &[(&str, u32)] = &[
        ("dispatch_execve", 221),
        ("dispatch_connect", 203),
        ("dispatch_openat", 56),
        ("dispatch_ptrace", 117),
        ("dispatch_setuid", 146),
        ("dispatch_bind", 200),
        ("dispatch_mount", 40),
        ("dispatch_memfd_create", 279),
        ("dispatch_init_module", 105),
        ("dispatch_dup", 24), // dup3 on aarch64 (no dup2)
        ("dispatch_listen", 201),
        ("dispatch_mprotect", 226),
        ("dispatch_clone", 220),
        ("dispatch_unlink", 35),  // unlinkat
        ("dispatch_rename", 276), // renameat2
        ("dispatch_kill", 129),
        ("dispatch_prctl", 167),
        ("dispatch_accept", 242), // accept4
    ];

    // Load all handlers first (must happen before we borrow the map mutably)
    for &(name, _) in handlers {
        if let Some(prog) = bpf.program_mut(name) {
            if let Ok(rtp) = TryInto::<&mut RawTracePoint>::try_into(prog) {
                if let Err(e) = rtp.load() {
                    warn!(error = %e, "dispatch handler {name}: failed to load");
                }
            }
        }
    }

    // --- 3. Wire handlers into SYSCALL_DISPATCH ProgramArray ---
    // Use take_map() to transfer ownership - avoids borrow conflict with bpf.program()
    let mut dispatch_map = match bpf.take_map("SYSCALL_DISPATCH") {
        Some(map) => match ProgramArray::try_from(map) {
            Ok(arr) => arr,
            Err(e) => {
                warn!(error = %e, "dispatcher: SYSCALL_DISPATCH not a ProgramArray");
                return false;
            }
        },
        None => {
            warn!("dispatcher: SYSCALL_DISPATCH map not found");
            return false;
        }
    };

    let mut inserted = 0u32;
    for &(name, syscall_nr) in handlers {
        if let Some(prog) = bpf.program(name) {
            if let Ok(fd) = prog.fd() {
                if dispatch_map.set(syscall_nr, fd, 0).is_ok() {
                    inserted += 1;
                }
            }
        }
    }

    if inserted == 0 {
        warn!("dispatcher: no handlers wired into SYSCALL_DISPATCH");
        return false;
    }
    info!(count = inserted, "eBPF: SYSCALL_DISPATCH populated");

    // --- 4. Populate SYSCALL_ENABLED map ---
    if let Some(map) = bpf.take_map("SYSCALL_ENABLED") {
        if let Ok(mut enabled_map) = HashMap::<_, u32, u32>::try_from(map) {
            for &(_, syscall_nr) in handlers {
                let _ = enabled_map.insert(syscall_nr, 1u32, 0);
            }
            info!(
                "eBPF: SYSCALL_ENABLED populated ({} syscalls)",
                handlers.len()
            );
        }
    }

    true
}

#[cfg(feature = "ebpf")]
pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use std::os::fd::{AsRawFd, FromRawFd};

    if !is_ebpf_available() {
        warn!("eBPF not available - falling back to audit-based collection");
        return;
    }

    // Load eBPF bytecode: prefer embedded (baked into binary), fallback to file on disk.
    #[cfg(feature = "ebpf-embedded")]
    let bytes = {
        info!(
            "eBPF collector: using embedded bytecode ({} bytes)",
            EBPF_BYTECODE_EMBEDDED.len()
        );
        EBPF_BYTECODE_EMBEDDED.to_vec()
    };

    #[cfg(not(feature = "ebpf-embedded"))]
    let bytes = {
        let obj_path = match find_ebpf_obj() {
            Some(p) => p,
            None => {
                warn!("eBPF bytecode not found - skipping eBPF collector");
                return;
            }
        };
        info!(path = %obj_path, "eBPF collector: loading bytecode from file");
        match std::fs::read(&obj_path) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "failed to read eBPF bytecode");
                return;
            }
        }
    };

    // CO-RE loader: use BTF relocations when available for cross-kernel portability
    let btf = aya::Btf::from_sys_fs().ok();
    if btf.is_some() {
        info!("eBPF: BTF available - CO-RE relocations enabled");
    }
    let mut bpf = match aya::EbpfLoader::new().btf(btf.as_ref()).load(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to load eBPF programs into kernel (need root or CAP_BPF)");
            return;
        }
    };

    // --- Attach syscall handlers: dispatcher mode or individual tracepoints ---
    let using_dispatcher = if bpf.program("innerwarden_dispatcher").is_some() {
        info!("eBPF: dispatcher program found - attempting dispatcher mode");
        attach_dispatcher(&mut bpf)
    } else {
        false
    };

    if using_dispatcher {
        info!("eBPF: dispatcher mode active - single sys_enter hook with tail calls");
    } else {
        // Typed tracepoint mode - attach each handler individually
        if !using_dispatcher && bpf.program("innerwarden_dispatcher").is_some() {
            info!("eBPF: dispatcher attach failed - falling back to typed tracepoints");
        }

        // Core tracepoints (execve, connect, openat)
        attach_tp(
            &mut bpf,
            "innerwarden_execve",
            "syscalls",
            "sys_enter_execve",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_connect",
            "syscalls",
            "sys_enter_connect",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_openat",
            "syscalls",
            "sys_enter_openat",
        );

        // v2 syscall handlers (non-critical - each is independent)
        attach_tp(
            &mut bpf,
            "innerwarden_ptrace",
            "syscalls",
            "sys_enter_ptrace",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_setuid",
            "syscalls",
            "sys_enter_setuid",
        );
        attach_tp(&mut bpf, "innerwarden_bind", "syscalls", "sys_enter_bind");
        attach_tp(&mut bpf, "innerwarden_mount", "syscalls", "sys_enter_mount");
        attach_tp(
            &mut bpf,
            "innerwarden_memfd_create",
            "syscalls",
            "sys_enter_memfd_create",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_init_module",
            "syscalls",
            "sys_enter_init_module",
        );
        // dup2 doesn't exist on aarch64 — try dup2, fall back to dup3.
        // Load the program once, then try attach with fallback.
        {
            use aya::programs::TracePoint;
            if let Some(prog) = bpf.program_mut("innerwarden_dup") {
                if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog) {
                    let _ = tp.load(); // load once
                    if tp.attach("syscalls", "sys_enter_dup2").is_ok() {
                        info!("eBPF: innerwarden_dup → sys_enter_dup2 ✅");
                    } else if tp.attach("syscalls", "sys_enter_dup3").is_ok() {
                        info!("eBPF: innerwarden_dup → sys_enter_dup3 ✅ (aarch64 fallback)");
                    } else {
                        warn!("innerwarden_dup: failed to attach to dup2 or dup3");
                    }
                }
            }
        }
        attach_tp(
            &mut bpf,
            "innerwarden_listen",
            "syscalls",
            "sys_enter_listen",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_mprotect",
            "syscalls",
            "sys_enter_mprotect",
        );
        attach_tp(&mut bpf, "innerwarden_clone", "syscalls", "sys_enter_clone");
        attach_tp(
            &mut bpf,
            "innerwarden_unlink",
            "syscalls",
            "sys_enter_unlinkat",
        );
        attach_tp(
            &mut bpf,
            "innerwarden_rename",
            "syscalls",
            "sys_enter_renameat2",
        );
        attach_tp(&mut bpf, "innerwarden_kill", "syscalls", "sys_enter_kill");
        attach_tp(&mut bpf, "innerwarden_prctl", "syscalls", "sys_enter_prctl");
        attach_tp(
            &mut bpf,
            "innerwarden_accept",
            "syscalls",
            "sys_enter_accept4",
        );
    }

    // --- Always attach non-tracepoint programs individually ---

    // Attach commit_creds kprobe (privilege escalation detection - non-critical)
    if let Some(prog) = bpf.program_mut("innerwarden_privesc") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                if let Err(e) = kp.attach("commit_creds", 0) {
                    warn!(error = %e, "innerwarden_privesc: failed to attach to commit_creds");
                } else {
                    info!("eBPF: innerwarden_privesc → commit_creds (privilege escalation) ✅");
                }
            }
        }
    }

    // Attach sched_process_exit tracepoint (rootkit lifecycle tracking - non-critical)
    if let Some(prog) = bpf.program_mut("innerwarden_process_exit") {
        if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog) {
            if tp.load().is_ok() {
                if let Err(e) = tp.attach("sched", "sched_process_exit") {
                    warn!(error = %e, "innerwarden_process_exit: failed to attach");
                } else {
                    info!("eBPF: innerwarden_process_exit → sched_process_exit (rootkit lifecycle) ✅");
                }
            }
        }
    }

    // io_uring monitoring (non-critical — requires kernel 5.10+ with io_uring tracepoints)
    // Try the 6.4+ name first, fall back to the pre-6.4 name.
    if !attach_tp(
        &mut bpf,
        "innerwarden_io_uring_submit",
        "io_uring",
        "io_uring_submit_req",
    ) {
        attach_tp(
            &mut bpf,
            "innerwarden_io_uring_submit",
            "io_uring",
            "io_uring_submit_sqe",
        );
    }
    attach_tp(
        &mut bpf,
        "innerwarden_io_uring_create",
        "io_uring",
        "io_uring_create",
    );

    // Attach LSM execution policy (non-critical - requires lsm=bpf in kernel cmdline)
    attach_lsm(&mut bpf);

    // Attach XDP firewall (non-critical - continues without it)
    attach_xdp(&mut bpf);

    // Phase 2: Firmware security hooks (non-critical on ARM — some x86 only)
    // MSR write monitoring (x86 only — kprobe on native_write_msr)
    if let Some(prog) = bpf.program_mut("innerwarden_msr_write") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("native_write_msr", 0) {
                    Ok(_) => info!("eBPF: innerwarden_msr_write → native_write_msr ✅"),
                    Err(e) => info!(error = %e, "innerwarden_msr_write: not available (x86 only)"),
                }
            }
        }
    }
    // I/O port access (ioperm syscall — x86 only, harmless no-op on ARM)
    attach_tp(
        &mut bpf,
        "innerwarden_ioperm",
        "syscalls",
        "sys_enter_ioperm",
    );
    // I/O privilege level (iopl syscall — x86 only)
    attach_tp(&mut bpf, "innerwarden_iopl", "syscalls", "sys_enter_iopl");
    // ACPI method evaluation (kprobe — available on any system with ACPI)
    if let Some(prog) = bpf.program_mut("innerwarden_acpi_eval") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("acpi_evaluate_object", 0) {
                    Ok(_) => info!("eBPF: innerwarden_acpi_eval → acpi_evaluate_object ✅"),
                    Err(e) => info!(error = %e, "innerwarden_acpi_eval: ACPI not available"),
                }
            }
        }
    }
    // BPF program loading (LSM hook — requires lsm=bpf)
    // This is attached via attach_lsm() which handles LSM hooks.

    // Phase 3: Red team gap hooks — timestomp + truncate detection
    // These use #[kprobe(function = "...")] in the eBPF code, so Aya creates
    // separate sections: kprobe/vfs_utimes and kprobe/do_truncate.
    // They need to be loaded and attached by the section name.
    // With #[kprobe(function = "vfs_utimes")], Aya registers as "vfs_utimes"
    if let Some(prog) = bpf.program_mut("vfs_utimes").or_else(|| bpf.program_mut("innerwarden_utimensat")) {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("vfs_utimes", 0) {
                    Ok(_) => info!("eBPF: innerwarden_utimensat → vfs_utimes (timestomp) ✅"),
                    Err(e) => warn!(error = %e, "innerwarden_utimensat: vfs_utimes not available"),
                }
            }
        }
    } else {
        // Try alternate name: Aya may use section name "kprobe_vfs_utimes" or function name
        info!("eBPF: innerwarden_utimensat not found by name, trying auto-attach...");
    }
    if let Some(prog) = bpf.program_mut("do_truncate").or_else(|| bpf.program_mut("innerwarden_truncate")) {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("do_truncate", 0) {
                    Ok(_) => info!("eBPF: innerwarden_truncate → do_truncate (log tampering) ✅"),
                    Err(e) => warn!(error = %e, "innerwarden_truncate: do_truncate not available"),
                }
            }
        }
    } else {
        info!("eBPF: innerwarden_truncate not found by name, trying auto-attach...");
    }

    // Trace of the Times: attach kprobe/kretprobe pairs for timing measurement.
    {
        let timing_targets = [
            (
                "innerwarden_tot_iterate_dir_entry",
                "innerwarden_tot_iterate_dir_ret",
                "iterate_dir",
            ),
            (
                "innerwarden_tot_filldir64_entry",
                "innerwarden_tot_filldir64_ret",
                "filldir64",
            ),
            (
                "innerwarden_tot_tcp4_entry",
                "innerwarden_tot_tcp4_ret",
                "tcp4_seq_show",
            ),
            (
                "innerwarden_tot_procdir_entry",
                "innerwarden_tot_procdir_ret",
                "proc_pid_readdir",
            ),
        ];
        for (entry_prog, ret_prog, func_name) in &timing_targets {
            // Attach kprobe (entry).
            let entry_ok = if let Some(prog) = bpf.program_mut(entry_prog) {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
                    kp.load().is_ok() && kp.attach(func_name, 0).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            // Attach kretprobe (return).
            let ret_ok = if let Some(prog) = bpf.program_mut(ret_prog) {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
                    kp.load().is_ok() && kp.attach(func_name, 0).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            if entry_ok && ret_ok {
                info!("eBPF: ToT timing probe → {func_name} (entry+return) ✅");
            } else if entry_ok || ret_ok {
                warn!("eBPF: ToT {func_name}: partial attach (entry={entry_ok}, ret={ret_ok})");
            } else {
                info!("eBPF: ToT {func_name}: not available on this kernel");
            }
        }
    }

    // Populate kernel-level noise filters BEFORE taking ring buffer borrow
    populate_kernel_filters(&mut bpf);

    // Read from ring buffer
    let mut ring_buf = match RingBuf::try_from(bpf.map_mut("EVENTS").unwrap()) {
        Ok(rb) => rb,
        Err(e) => {
            warn!(error = %e, "eBPF: failed to open ring buffer");
            return;
        }
    };

    info!("eBPF collector active - kernel-level syscall monitoring (27 hooks + 5 firmware)");

    // Setup epoll-based wakeup via AsyncFd wrapping the ring buffer's raw fd.
    // Falls back to 100ms sleep polling if fd duplication or AsyncFd fails.
    let async_fd = {
        let ring_fd = ring_buf.as_raw_fd();
        // dup() so AsyncFd owns an independent fd and won't close the ring buffer's fd
        let duped = unsafe { libc::dup(ring_fd) };
        if duped >= 0 {
            // Safety: duped is a valid fd we just created
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(duped) };
            match tokio::io::unix::AsyncFd::new(owned) {
                Ok(afd) => {
                    info!("eBPF: ring buffer epoll wakeup enabled (fd={ring_fd})");
                    Some(afd)
                }
                Err(e) => {
                    warn!(error = %e, "eBPF: AsyncFd creation failed - falling back to poll");
                    None
                }
            }
        } else {
            warn!("eBPF: dup() failed - falling back to poll");
            None
        }
    };

    // Safe byte parsing: returns from match arm with `continue` on malformed data
    macro_rules! read_u16 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u16::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }
    macro_rules! read_u32 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u32::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }
    macro_rules! read_u64 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u64::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }

    loop {
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if data.len() < 4 {
                continue;
            }

            let kind = read_u32!(data, 0..4);

            let event = match kind {
                // ExecveEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) gid(4) ppid(4) cgroup_id(8) comm(64) filename(256)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96..352
                1 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(execve_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        &host,
                    ))
                }
                // ConnectEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) ppid(4) _pad(4) cgroup_id(8) comm(64)
                //   dst_addr(4) dst_port(2) family(2) ts_ns(8)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96  100  102
                2 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let addr = read_u32!(data, 96..100);
                    let port = read_u16!(data, 100..102);

                    let ip = Ipv4Addr::from(addr);

                    if ip.is_loopback() || ip.is_private() || ip.is_unspecified() {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(connect_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        ip,
                        port,
                        &host,
                    ))
                }
                // FileOpenEvent layout (#[repr(C)]):
                //   kind(4) pid(4) uid(4) ppid(4) cgroup_id(8) comm(64) filename(256) flags(4)
                //   Offsets: 0  4  8  12  16  24..88  88..344  344
                3 if data.len() >= 348 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    let flags = read_u32!(data, 344..348);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(file_open_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        flags,
                        &host,
                    ))
                }
                // FileWrite from LSM file_open hook (same layout as FileOpenEvent)
                // Emitted when a non-allowlisted process writes to sensitive paths.
                4 if data.len() >= 348 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    let flags = read_u32!(data, 344..348);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(file_open_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        flags,
                        &host,
                    ))
                }
                // PrivEscEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) old_uid(4) new_uid(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                //   Offsets: 0  4  8  12  16  20  24  32..96
                5 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let old_uid = read_u32!(data, 12..16);
                    let new_uid = read_u32!(data, 16..20);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let container_id = resolve_container_id(pid);

                    privesc_to_event(
                        pid,
                        old_uid,
                        new_uid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &host,
                    )
                }
                // LSM blocked execution - uses ExecveEvent layout but kind=6
                // Same offsets as ExecveEvent: kind(4) pid(4) tgid(4) uid(4) gid(4) ppid(4) cgroup_id(8) comm(64) filename(256)
                6 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    let container_id = resolve_container_id(pid);

                    let mut details = serde_json::json!({
                        "pid": pid,
                        "uid": uid,
                        "comm": comm,
                        "filename": filename,
                        "cgroup_id": cgroup_id,
                        "action": "blocked",
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    let mut tags =
                        vec!["ebpf".to_string(), "lsm".to_string(), "blocked".to_string()];
                    let mut entities = vec![];
                    if let Some(ref cid) = container_id {
                        tags.push("container".to_string());
                        entities.push(EntityRef::container(cid));
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "lsm.exec_blocked".to_string(),
                        severity: Severity::Critical,
                        summary: format!("LSM blocked execution: {comm} tried to run {filename}"),
                        details,
                        tags,
                        entities,
                    })
                }
                // ContainerDrift: ExecveEvent layout with kind=26.
                // Binary executed from overlayfs upper layer (not in original image).
                26 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    let container_id = resolve_container_id(pid);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "shell.command_exec".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "Container drift: {comm} executed {filename} (overlay upper layer)"
                        ),
                        details: serde_json::json!({
                            "pid": pid,
                            "uid": uid,
                            "comm": comm,
                            "filename": filename,
                            "cgroup_id": cgroup_id,
                            "container_id": container_id.as_deref().unwrap_or(""),
                            "overlay_upper": true,
                        }),
                        tags: vec!["ebpf".to_string(), "container_drift".to_string()],
                        entities: vec![],
                    })
                }
                // ProcessExitEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) comm(64) exit_code(4) ts_ns(8)
                //   Offsets: 0  4  8  12..76  76  80
                7 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let comm = bytes_to_string(&data[12..76]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.exit".to_string(),
                        severity: Severity::Debug,
                        summary: format!("Process exited: {comm} (PID {pid})"),
                        details: serde_json::json!({
                            "pid": pid,
                            "comm": comm,
                        }),
                        tags: vec!["ebpf".to_string()],
                        entities: vec![],
                    })
                }
                // PtraceEvent: kind(4) pid(4) uid(4) target_pid(4) request(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  32..96
                8 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_pid = read_u32!(data, 12..16);
                    let request = read_u32!(data, 16..20);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let request_name = match request {
                        4 => "PTRACE_POKETEXT",
                        5 => "PTRACE_POKEDATA",
                        16 => "PTRACE_ATTACH",
                        0x4206 => "PTRACE_SEIZE",
                        _ => "UNKNOWN",
                    };
                    let container_id = resolve_container_id(pid);

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "target_pid": target_pid,
                        "request": request, "request_name": request_name,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    let mut tags = vec![
                        "ebpf".to_string(),
                        "ptrace".to_string(),
                        "injection".to_string(),
                    ];
                    if container_id.is_some() {
                        tags.push("container".to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.ptrace_attach".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "{comm} (PID {pid}) called {request_name} on PID {target_pid}"
                        ),
                        details,
                        tags,
                        entities: vec![],
                    })
                }
                // SetUidEvent: kind(4) pid(4) uid(4) target_uid(4) syscall_nr(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  32..96
                9 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let container_id = resolve_container_id(pid);
                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "target_uid": target_uid,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "privilege.setuid".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}, uid {uid}) called setuid(0) - escalating to root"
                        ),
                        details,
                        tags: vec!["ebpf".to_string(), "privesc".to_string()],
                        entities: vec![],
                    })
                }
                // SocketBindEvent: kind(4) pid(4) uid(4) protocol(2) family(2) port(2) _pad(2) addr(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  14  16  18  20  24  32..96
                10 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let family = read_u16!(data, 12..14);
                    let port = read_u16!(data, 16..18);
                    let addr = read_u32!(data, 20..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let ip = std::net::Ipv4Addr::from(addr);
                    let container_id = resolve_container_id(pid);

                    // Low ports or INADDR_ANY are more suspicious
                    let severity = if port < 1024 || addr == 0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "port": port,
                        "addr": format!("{ip}"), "family": family,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.bind_listen".to_string(),
                        severity,
                        summary: format!("{comm} (PID {pid}) binding to {ip}:{port}"),
                        details,
                        tags: vec![
                            "ebpf".to_string(),
                            "network".to_string(),
                            "bind".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // MountEvent: kind(4) pid(4) uid(4) flags(4) cgroup_id(8) comm(64) source(256) target(256) fs_type(32) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88  88..344  344..600  600..632
                11 if data.len() >= 632 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let flags = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let source = bytes_to_string(&data[88..344]);
                    let target = bytes_to_string(&data[344..600]);
                    let fs_type = bytes_to_string(&data[600..632]);

                    let container_id = resolve_container_id(pid);
                    let in_container = cgroup_id > 1;

                    let severity = if in_container {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "flags": flags,
                        "source": source, "target": target, "fs_type": fs_type,
                        "comm": comm, "cgroup_id": cgroup_id,
                        "in_container": in_container,
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    let mut tags = vec!["ebpf".to_string(), "mount".to_string()];
                    if in_container {
                        tags.push("container_escape".to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "filesystem.mount".to_string(),
                        severity,
                        summary: format!(
                            "{comm} (PID {pid}) mounting {source} on {target} (type: {fs_type})"
                        ),
                        details,
                        tags,
                        entities: vec![],
                    })
                }
                // MemfdCreateEvent: kind(4) pid(4) uid(4) flags(4) cgroup_id(8) comm(64) name(256) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88  88..344
                12 if data.len() >= 344 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let flags = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let name = bytes_to_string(&data[88..344]);

                    let container_id = resolve_container_id(pid);

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "flags": flags,
                        "name": name, "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(ref cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.memfd_create".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) created anonymous memory file: {name}"
                        ),
                        details,
                        tags: vec![
                            "ebpf".to_string(),
                            "fileless".to_string(),
                            "memfd".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // ModuleLoadEvent: kind(4) pid(4) uid(4) syscall_nr(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88
                13 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "kernel.module_load".to_string(),
                        severity: Severity::Critical,
                        summary: format!("{comm} (PID {pid}, uid {uid}) loading kernel module"),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "kernel".to_string(),
                            "module_load".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // DupEvent: kind(4) pid(4) uid(4) oldfd(4) newfd(4) _pad(4) cgroup_id(8) comm(64)
                14 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let oldfd = read_u32!(data, 12..16);
                    let newfd = read_u32!(data, 16..20);
                    let comm = bytes_to_string(&data[24..88]);
                    let fd_name = match newfd {
                        0 => "stdin",
                        1 => "stdout",
                        2 => "stderr",
                        _ => "fd",
                    };
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.fd_redirect".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) redirected fd {oldfd} → {fd_name}({newfd})"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "oldfd": oldfd, "newfd": newfd, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "reverse_shell".to_string()],
                        entities: vec![],
                    })
                }
                // ListenEvent: kind(4) pid(4) uid(4) backlog(4) cgroup_id(8) comm(64)
                15 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let backlog = read_u32!(data, 12..16);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.listen".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) started listening (backlog={backlog})"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "backlog": backlog, "comm": comm}),
                        tags: vec![
                            "ebpf".to_string(),
                            "network".to_string(),
                            "listen".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // MprotectEvent: kind(4) pid(4) uid(4) prot(4) addr(8) len(8) cgroup_id(8) comm(64)
                16 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let prot = read_u32!(data, 12..16);
                    let addr = read_u64!(data, 16..24);
                    let len = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[40..104]);
                    let rwx = prot & 0x7 == 0x7; // PROT_READ|PROT_WRITE|PROT_EXEC
                    Some(Event {
                        ts: chrono::Utc::now(), host: host.to_string(), source: "ebpf".to_string(),
                        kind: "memory.mprotect_exec".to_string(),
                        severity: if rwx { Severity::Critical } else { Severity::High },
                        summary: format!("{comm} (PID {pid}) mprotect → executable memory at 0x{addr:x} ({len} bytes){}", if rwx { " [RWX - shellcode indicator]" } else { "" }),
                        details: serde_json::json!({"pid": pid, "uid": uid, "prot": prot, "addr": format!("0x{addr:x}"), "len": len, "rwx": rwx, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "shellcode".to_string()], entities: vec![],
                    })
                }
                // CloneEvent: kind(4) pid(4) uid(4) _pad(4) clone_flags(8) cgroup_id(8) comm(64)
                17 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let clone_flags = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[32..96]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.clone".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (PID {pid}) clone(flags=0x{clone_flags:x})"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "clone_flags": format!("0x{clone_flags:x}"), "comm": comm}),
                        tags: vec!["ebpf".to_string()],
                        entities: vec![],
                    })
                }
                // UnlinkEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) filename(256)
                18 if data.len() >= 344 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "file.delete".to_string(),
                        severity: Severity::High,
                        summary: format!("{comm} (PID {pid}) deleting {filename}"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "filename": filename, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "evidence_destruction".to_string()],
                        entities: vec![],
                    })
                }
                // RenameEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) oldname(256) newname(256)
                19 if data.len() >= 600 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    let oldname = bytes_to_string(&data[88..344]);
                    let newname = bytes_to_string(&data[344..600]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "file.rename".to_string(),
                        severity: Severity::High,
                        summary: format!("{comm} (PID {pid}) renaming {oldname} → {newname}"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "oldname": oldname, "newname": newname, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "binary_replacement".to_string()],
                        entities: vec![],
                    })
                }
                // KillEvent: kind(4) pid(4) uid(4) target_pid(4) signal(4) _pad(4) cgroup_id(8) comm(64)
                20 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_pid = read_u32!(data, 12..16);
                    let signal = read_u32!(data, 16..20);
                    let comm = bytes_to_string(&data[28..92]);
                    let sig_name = match signal {
                        9 => "SIGKILL",
                        15 => "SIGTERM",
                        19 => "SIGSTOP",
                        _ => "SIG?",
                    };
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.signal".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) sending {sig_name} to PID {target_pid}"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "target_pid": target_pid, "signal": signal, "signal_name": sig_name, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "kill_signal".to_string()],
                        entities: vec![],
                    })
                }
                // PrctlEvent: kind(4) pid(4) uid(4) option(4) arg2(8) cgroup_id(8) comm(64)
                21 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let option = read_u32!(data, 12..16);
                    let comm = bytes_to_string(&data[32..96]);
                    let op_name = match option {
                        15 => "PR_SET_NAME",
                        38 => "PR_SET_NO_NEW_PRIVS",
                        _ => "unknown",
                    };
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.prctl".to_string(),
                        severity: Severity::Medium,
                        summary: format!("{comm} (PID {pid}) prctl({op_name})"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "option": option, "op_name": op_name, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "prctl".to_string()],
                        entities: vec![],
                    })
                }
                // AcceptEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64)
                22 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.accept".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (PID {pid}) accepted incoming connection"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "network".to_string()],
                        entities: vec![],
                    })
                }
                // EXPERIMENTAL: EfiCallEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                23 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.efi_call".to_string(),
                        severity: Severity::Debug,
                        summary: format!(
                            "[EXPERIMENTAL] {comm} (PID {pid}) EFI Runtime Services call"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "comm": comm, "experimental": true}),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "experimental".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // IoUringEvent: kind(4) pid(4) uid(4) opcode(1) sqe_flags(1) _pad(2) fd(4)
                //   cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  13  14  16  20  24..88  88
                24 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let opcode = data[12];
                    let sqe_flags = data[13];
                    let fd = read_u32!(data, 16..20) as i32;
                    let cgroup_id = read_u64!(data, 20..28);
                    let comm = bytes_to_string(&data[28..92]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "io_uring.submit".to_string(),
                        severity: Severity::Info,
                        summary: format!(
                            "{comm} (pid={pid}) io_uring submit opcode={opcode} fd={fd}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "opcode": opcode, "sqe_flags": sqe_flags,
                            "fd": fd, "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "io_uring".to_string()],
                        entities: vec![],
                    })
                }
                // IoUringCreateEvent: kind(4) pid(4) uid(4) ring_fd(4) sq_entries(4)
                //   cq_entries(4) flags(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  28  32..96  96
                25 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let ring_fd = read_u32!(data, 12..16) as i32;
                    let sq_entries = read_u32!(data, 16..20);
                    let cq_entries = read_u32!(data, 20..24);
                    let flags = read_u32!(data, 24..28);
                    let cgroup_id = read_u64!(data, 32..40);
                    let comm = bytes_to_string(&data[40..104]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "io_uring.create".to_string(),
                        severity: Severity::Info,
                        summary: format!(
                            "{comm} (pid={pid}) created io_uring ring (sq={sq_entries})"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "ring_fd": ring_fd, "sq_entries": sq_entries,
                            "cq_entries": cq_entries, "flags": flags,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "io_uring".to_string()],
                        entities: vec![],
                    })
                }
                // ── Phase 2: Firmware hooks ──────────────────────

                // MsrWriteEvent: kind(4) pid(4) uid(4) pad(4) msr_addr(8) lo(4) hi(4) cgroup(8) comm(64) ts(8)
                27 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let msr_addr = read_u64!(data, 16..24);
                    let msr_lo = read_u32!(data, 24..28);
                    let msr_hi = read_u32!(data, 28..32);
                    let cgroup_id = read_u64!(data, 32..40);
                    let comm = bytes_to_string(&data[40..104]);

                    let msr_name = match msr_addr {
                        0xC0000081 => "STAR",
                        0xC0000082 => "LSTAR (syscall entry)",
                        0xC0000083 => "CSTAR",
                        0xC0000084 => "SF_MASK",
                        0x1F2 => "IA32_SMRR_PHYSBASE",
                        0x1F3 => "IA32_SMRR_PHYSMASK",
                        0x3A => "IA32_FEATURE_CONTROL",
                        _ => "UNKNOWN",
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.msr_write".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "{comm} (pid={pid}) wrote to MSR {msr_name} (0x{msr_addr:X}) = 0x{msr_hi:08X}{msr_lo:08X}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "msr_address": format!("0x{msr_addr:X}"),
                            "msr_name": msr_name,
                            "msr_value": format!("0x{msr_hi:08X}{msr_lo:08X}"),
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "firmware".to_string(), "msr".to_string()],
                        entities: vec![],
                    })
                }
                // IopermEvent: kind(4) pid(4) uid(4) pad(4) from(8) num(8) turn_on(8) cgroup(8) comm(64) ts(8)
                28 if data.len() >= 112 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let port_from = read_u64!(data, 16..24);
                    let port_num = read_u64!(data, 24..32);
                    let cgroup_id = read_u64!(data, 40..48);
                    let comm = bytes_to_string(&data[48..112]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.ioperm".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (pid={pid}) requested I/O port access: ports 0x{port_from:X}-0x{:X}",
                            port_from + port_num
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "port_from": port_from, "port_num": port_num,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "firmware".to_string(), "hardware".to_string()],
                        entities: vec![],
                    })
                }
                // IoplEvent: kind(4) pid(4) uid(4) pad(4) level(8) cgroup(8) comm(64) ts(8)
                29 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let level = read_u64!(data, 16..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.iopl".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (pid={pid}) elevated I/O privilege level to {level}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "level": level, "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "hardware".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // AcpiEvalEvent: kind(4) pid(4) uid(4) pad(4) cgroup(8) pathname(64) comm(64) ts(8)
                30 if data.len() >= 160 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let pathname = bytes_to_string(&data[24..88]);
                    let comm = bytes_to_string(&data[88..152]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.acpi_eval".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (pid={pid}) ACPI evaluate: {pathname}"),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "pathname": pathname, "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "acpi".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // TimingProbeEvent: kind(4) pid(4) target(4) pad(4) delta_ns(8) cgroup(8) comm(64) ts(8)
                32 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let target = read_u32!(data, 8..12);
                    let delta_ns = read_u64!(data, 16..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let target_name = match target {
                        1 => "iterate_dir",
                        2 => "filldir64",
                        3 => "tcp4_seq_show",
                        4 => "proc_pid_readdir",
                        _ => "unknown",
                    };

                    // Timing events are high-volume. Only emit as events
                    // when delta is unusually large (> 1ms = possible hook).
                    // Normal deltas are sub-microsecond.
                    if delta_ns > 1_000_000 {
                        Some(Event {
                            ts: chrono::Utc::now(),
                            host: host.to_string(),
                            source: "ebpf".to_string(),
                            kind: "firmware.timing_anomaly".to_string(),
                            severity: Severity::High,
                            summary: format!(
                                "{target_name} took {:.1}ms (pid={pid} {comm}) — possible kernel hook",
                                delta_ns as f64 / 1_000_000.0,
                            ),
                            details: serde_json::json!({
                                "pid": pid, "comm": comm,
                                "target": target_name,
                                "delta_ns": delta_ns,
                                "delta_ms": delta_ns as f64 / 1_000_000.0,
                                "cgroup_id": cgroup_id,
                            }),
                            tags: vec!["ebpf".to_string(), "firmware".to_string(), "timing".to_string()],
                            entities: vec![],
                        })
                    } else {
                        // Normal timing — silently collected for baseline building.
                        // TODO: accumulate in a buffer for periodic Trace of the Times analysis.
                        None
                    }
                }
                // BpfLoadEvent: kind(4) pid(4) uid(4) bpf_cmd(4) cgroup(8) comm(64) ts(8)
                31 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let bpf_cmd = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);

                    let cmd_name = match bpf_cmd {
                        0 => "BPF_MAP_CREATE",
                        5 => "BPF_PROG_LOAD",
                        18 => "BPF_BTF_LOAD",
                        28 => "BPF_LINK_CREATE",
                        _ => "UNKNOWN",
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.bpf_load".to_string(),
                        severity: Severity::Medium,
                        summary: format!(
                            "{comm} (pid={pid}) loaded eBPF: {cmd_name} (cmd={bpf_cmd})"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "bpf_cmd": bpf_cmd, "cmd_name": cmd_name,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "bpf_load".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // UtimensatEvent: timestomp detection (vfs_utimes kprobe)
                // kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) filename(256) ts_ns(8)
                33 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.clone(),
                        source: "ebpf".to_string(),
                        kind: "file.timestomp".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "File timestamp modification by {} (pid={}, uid={})",
                            comm, pid, uid
                        ),
                        details: serde_json::json!({
                            "comm": comm,
                            "pid": pid,
                            "uid": uid,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "defense_evasion".to_string(),
                            "timestomp".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // TruncateEvent: log tampering detection (do_truncate kprobe)
                // kind(4) pid(4) uid(4) _pad(4) new_size(8) cgroup_id(8) comm(64) filename(256) ts_ns(8)
                34 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let new_size = read_u64!(data, 16..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.clone(),
                        source: "ebpf".to_string(),
                        kind: "file.truncate".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "File truncated to {} bytes by {} (pid={}, uid={})",
                            new_size, comm, pid, uid
                        ),
                        details: serde_json::json!({
                            "comm": comm,
                            "pid": pid,
                            "uid": uid,
                            "new_size": new_size,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "defense_evasion".to_string(),
                            "log_tampering".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                _ => None,
            };

            if let Some(ev) = event {
                if tx.send(ev).await.is_err() {
                    warn!("eBPF collector: channel closed, stopping");
                    return;
                }
            }
        }

        // Wait for ring buffer readability via epoll, or fall back to 100ms poll
        if let Some(ref afd) = async_fd {
            // Wait until the kernel signals data is available on the ring buffer fd
            match afd.readable().await {
                Ok(mut guard) => {
                    guard.clear_ready();
                }
                Err(_) => {
                    // epoll error - fall back to short sleep this iteration
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Fallback when ebpf feature is not enabled.
#[cfg(not(feature = "ebpf"))]
pub async fn run(_tx: mpsc::Sender<Event>, _host: String) {
    if is_ebpf_available() {
        info!("eBPF is available but the sensor was compiled without --features ebpf");
        info!("Rebuild with: cargo build --features ebpf -p innerwarden-sensor");
    }
    // Silently return - other collectors handle detection
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_event_maps_to_shell_command_exec() {
        let event = execve_to_event(1234, 0, 1, 0, None, "bash", "/usr/bin/curl", "test-host");
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "shell.command_exec");
        assert!(event.summary.contains("curl"));
        assert_eq!(event.details["pid"], 1234);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn execve_event_with_container() {
        let event = execve_to_event(
            1234,
            0,
            1,
            12345,
            Some("abc123def456"),
            "bash",
            "/usr/bin/curl",
            "test-host",
        );
        assert_eq!(event.details["container_id"], "abc123def456");
        assert_eq!(event.details["cgroup_id"], 12345);
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn connect_event_high_severity_for_reverse_shell_ports() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(5678, 1000, 1, 0, None, "nc", ip, 4444, "test-host");
        assert_eq!(event.severity, Severity::High);

        let event_normal = connect_to_event(5678, 1000, 1, 0, None, "curl", ip, 443, "test-host");
        assert_eq!(event_normal.severity, Severity::Info);
    }

    #[test]
    fn connect_event_with_container() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(
            5678,
            1000,
            1,
            99999,
            Some("container123"),
            "nc",
            ip,
            4444,
            "test-host",
        );
        assert_eq!(event.details["container_id"], "container123");
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn file_open_event_write_to_shadow() {
        let event = file_open_to_event(
            100,
            0,
            1,
            0,
            None,
            "vim",
            "/etc/shadow",
            0x1, // O_WRONLY
            "test-host",
        );
        assert_eq!(event.kind, "file.write_access");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn file_open_event_read_normal() {
        let event = file_open_to_event(
            100,
            1000,
            1,
            0,
            None,
            "cat",
            "/etc/passwd",
            0x0, // O_RDONLY
            "test-host",
        );
        assert_eq!(event.kind, "file.read_access");
        assert_eq!(event.severity, Severity::Info);
    }

    #[test]
    fn bytes_to_string_handles_null_terminator() {
        let buf = b"hello\0world\0\0\0";
        assert_eq!(bytes_to_string(buf), "hello");
    }

    #[test]
    fn ebpf_availability_on_non_linux() {
        if cfg!(target_os = "macos") {
            assert!(!is_ebpf_available());
        }
    }

    #[test]
    fn resolve_ppid_nonexistent_process() {
        // PID 999999999 shouldn't exist
        assert_eq!(resolve_ppid(999_999_999), 0);
    }

    #[test]
    fn resolve_container_id_host_process() {
        // Host process shouldn't have a container ID
        // (pid 1 is always the init process on the host)
        if cfg!(target_os = "linux") {
            assert!(resolve_container_id(1).is_none());
        }
    }
}
