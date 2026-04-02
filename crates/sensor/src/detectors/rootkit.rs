use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Detects rootkit indicators via eBPF events and filesystem checks.
///
/// Detection patterns:
/// 1. **Hidden process** - eBPF sees a PID executing but /proc/{pid}/ doesn't exist.
///    Rootkits hide processes from userspace tools (ps, top) but eBPF tracepoints
///    see everything at kernel level.
///
/// 2. **Known rootkit artifacts** - files/paths that rootkits typically create:
///    /dev/.hidden, /dev/shm/.hidden, /usr/lib/libprocesshider.so, /etc/ld.so.preload
///    with suspicious entries, files in /tmp or /dev/shm with suspicious names.
///
/// 3. **LD_PRELOAD hijacking** - process loads a library via LD_PRELOAD from an
///    unusual location (not /usr/lib, /lib, /usr/local/lib).
///
/// 4. **Kernel module rootkit** - insmod/modprobe/rmmod for a non-standard module.
///
/// 5. **Syscall table reconnaissance** - process reads /boot/System.map or
///    /proc/kallsyms (used by rootkits to find syscall table addresses).
///
/// 6. **Process name spoofing** - eBPF sees the real binary path via execve but
///    the comm field doesn't match the binary name.
///
/// 7. **Kernel function timing analysis** - tracks inter-event timing per syscall kind
///    using Welford's online algorithm. Rootkits that hook kernel functions (e.g.,
///    getdents64 to hide files/processes) add measurable latency. Consecutive timing
///    anomalies beyond a configurable z-score threshold raise an incident.
///    Based on research from ait-aecid/rootkit-detection-ebpf-time-trace.
pub struct RootkitDetector {
    cooldown: Duration,
    check_interval: Duration,
    /// Tracked PIDs: pid → PidInfo
    pids: HashMap<u32, PidInfo>,
    /// Cooldown per alert key
    alerted: HashMap<String, DateTime<Utc>>,
    /// Last time we ran the periodic hidden-process check
    last_check: DateTime<Utc>,
    host: String,
    /// Pluggable function to check if a PID exists in /proc.
    /// Defaults to checking the filesystem. Overridden in tests.
    pid_exists_fn: fn(u32) -> bool,
    /// Per-syscall-kind timing statistics (Welford's online algorithm).
    /// Tracks inter-event timing to detect kernel function hooking.
    syscall_timing: HashMap<String, TimingStats>,
    /// Whether timing analysis is enabled.
    timing_enabled: bool,
    /// Minimum samples before a timing profile is considered trained.
    timing_min_samples: u64,
    /// Z-score threshold for flagging a single timing anomaly.
    timing_z_threshold: f64,
    /// Consecutive anomalous timings required to raise an incident.
    timing_consecutive_threshold: usize,
}

/// Per-syscall-kind timing statistics using Welford's online algorithm.
/// Tracks inter-event timing deltas to build a baseline and detect anomalies
/// that indicate kernel function hooking (rootkit behavior).
#[derive(Debug, Clone)]
struct TimingStats {
    /// Number of timing samples observed.
    count: u64,
    /// Running mean of inter-event delta in nanoseconds.
    mean_ns: f64,
    /// Welford's M2 aggregator for computing variance.
    m2: f64,
    /// Minimum inter-event delta observed (nanoseconds).
    min_ns: u64,
    /// Maximum inter-event delta observed (nanoseconds).
    max_ns: u64,
    /// Timestamp of the last event of this kind.
    last_ts: DateTime<Utc>,
    /// True after timing_min_samples have been collected.
    trained: bool,
    /// Count of consecutive anomalous timings.
    consecutive_anomalies: usize,
}

impl TimingStats {
    fn new(ts: DateTime<Utc>) -> Self {
        Self {
            count: 0,
            mean_ns: 0.0,
            m2: 0.0,
            min_ns: u64::MAX,
            max_ns: 0,
            last_ts: ts,
            trained: false,
            consecutive_anomalies: 0,
        }
    }

    /// Update with a new inter-event delta using Welford's online algorithm.
    fn update(&mut self, delta_ns: u64, min_samples: u64) {
        self.count += 1;
        let x = delta_ns as f64;
        let delta = x - self.mean_ns;
        self.mean_ns += delta / self.count as f64;
        let delta2 = x - self.mean_ns;
        self.m2 += delta * delta2;

        if delta_ns < self.min_ns {
            self.min_ns = delta_ns;
        }
        if delta_ns > self.max_ns {
            self.max_ns = delta_ns;
        }

        if self.count >= min_samples {
            self.trained = true;
        }
    }

    /// Compute the population standard deviation.
    fn stddev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / self.count as f64).sqrt()
    }
}

#[derive(Debug, Clone)]
struct PidInfo {
    comm: String,
    binary_path: String,
    last_seen: DateTime<Utc>,
    uid: u32,
    /// How many times we've seen this PID via eBPF
    seen_count: u32,
}

/// Known-good kernel modules that are expected on a normal Linux system.
/// Modules not in this list trigger an alert when loaded/unloaded.
const KNOWN_GOOD_MODULES: &[&str] = &[
    // Filesystem
    "ext4",
    "xfs",
    "btrfs",
    "nfs",
    "nfsd",
    "cifs",
    "vfat",
    "fat",
    "fuse",
    "overlay",
    "squashfs",
    "isofs",
    "udf",
    "ntfs",
    "ntfs3",
    // Networking
    "ip_tables",
    "iptable_filter",
    "iptable_nat",
    "ip6_tables",
    "ip6table_filter",
    "nf_conntrack",
    "nf_nat",
    "nf_tables",
    "nft_chain_nat",
    "bridge",
    "br_netfilter",
    "veth",
    "bonding",
    "tun",
    "tap",
    "wireguard",
    "openvpn",
    "vxlan",
    "geneve",
    "ipvlan",
    "macvlan",
    // Storage / Block
    "dm_mod",
    "dm_crypt",
    "dm_thin_pool",
    "raid0",
    "raid1",
    "raid10",
    "raid456",
    "md_mod",
    "loop",
    "nbd",
    "scsi_mod",
    "sd_mod",
    "sr_mod",
    "ahci",
    "nvme",
    "nvme_core",
    "virtio_blk",
    "virtio_scsi",
    // Virtualization / Container
    "kvm",
    "kvm_intel",
    "kvm_amd",
    "vhost",
    "vhost_net",
    "virtio_net",
    "virtio_pci",
    "virtio_ring",
    "virtio_console",
    "vmw_vsock_virtio_transport",
    "vmw_vsock_vmci_transport",
    "vsock",
    "vboxdrv",
    "vboxnetflt",
    "vboxnetadp",
    // Device drivers
    "i2c_core",
    "i2c_piix4",
    "usbcore",
    "usb_common",
    "xhci_hcd",
    "ehci_hcd",
    "uhci_hcd",
    "usb_storage",
    "hid",
    "hid_generic",
    "usbhid",
    "evdev",
    "input_leds",
    "psmouse",
    // Audio / Video
    "snd",
    "snd_pcm",
    "snd_hda_intel",
    "snd_hda_codec",
    "drm",
    "drm_kms_helper",
    "i915",
    "amdgpu",
    "nvidia",
    "nouveau",
    // Security / Crypto
    "selinux",
    "apparmor",
    "bpf",
    "aes_x86_64",
    "aesni_intel",
    "sha256_generic",
    "sha512_generic",
    "crc32c_intel",
    "authenc",
    "af_alg",
    "algif_hash",
    "algif_skcipher",
    // Power / ACPI
    "acpi",
    "acpi_cpufreq",
    "cpufreq_ondemand",
    "cpufreq_conservative",
    "processor",
    "thermal",
    "battery",
    "button",
    // Misc system
    "configfs",
    "efivarfs",
    "autofs4",
    "sunrpc",
    "nfs_acl",
    "lockd",
    "grace",
    "ip_vs",
    "nf_conntrack_netlink",
    "xfrm_user",
    "xfrm_algo",
    "af_packet",
    "ppp_generic",
    "ppp_async",
    "ppp_deflate",
    "pppoe",
    "tls",
    "xt_conntrack",
    "xt_MASQUERADE",
    "xt_addrtype",
    "xt_comment",
    "xt_multiport",
    "xt_nat",
    "xt_tcpudp",
    "xt_mark",
    // Container runtime / eBPF
    "cls_bpf",
    "sch_ingress",
    "act_bpf",
    // Cloud / Hypervisor guest
    "hv_vmbus",
    "hv_storvsc",
    "hv_netvsc",
    "hv_utils",
    "hv_balloon",
    "hyperv_keyboard",
    "xen_blkfront",
    "xen_netfront",
    "ena",
    "ixgbevf",
];

/// Paths that are known rootkit artifacts.
const ROOTKIT_ARTIFACT_PATHS: &[&str] = &[
    "/dev/.hidden",
    "/dev/shm/.hidden",
    "/usr/lib/libprocesshider.so",
    "/usr/lib64/libprocesshider.so",
    "/lib/libprocesshider.so",
    "/lib64/libprocesshider.so",
];

/// Suspicious filename patterns in /tmp or /dev/shm.
const SUSPICIOUS_TMPFILE_NAMES: &[&str] = &[
    ".x",
    ".cache",
    ".kdev",
    ".ICE-unix-",
    ".font-unix-",
    ".r00t",
    ".sshd",
    ".bd",
    ".knark",
    ".1proc",
    ".rk",
    ".iceseed",
    ".hax0r",
    ".log",
];

/// Syscall table reconnaissance targets.
const RECON_PATHS: &[&str] = &["/boot/System.map", "/proc/kallsyms"];

/// Legitimate system directories for shared libraries.
const LEGIT_LIB_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib",
    "/lib64",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/local/lib",
    "/usr/local/lib64",
];

/// Default check: does /proc/{pid} exist on the filesystem?
fn default_pid_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

impl RootkitDetector {
    pub fn new(host: impl Into<String>, check_interval_secs: u64, cooldown_seconds: u64) -> Self {
        Self {
            cooldown: Duration::seconds(cooldown_seconds as i64),
            check_interval: Duration::seconds(check_interval_secs as i64),
            pids: HashMap::new(),
            alerted: HashMap::new(),
            last_check: Utc::now(),
            host: host.into(),
            pid_exists_fn: default_pid_exists,
            syscall_timing: HashMap::new(),
            timing_enabled: true,
            timing_min_samples: 100,
            timing_z_threshold: 4.0,
            timing_consecutive_threshold: 5,
        }
    }

    /// Create with explicit timing configuration.
    pub fn with_timing_config(
        mut self,
        enabled: bool,
        min_samples: u64,
        z_threshold: f64,
        consecutive_threshold: usize,
    ) -> Self {
        self.timing_enabled = enabled;
        self.timing_min_samples = min_samples;
        self.timing_z_threshold = z_threshold;
        self.timing_consecutive_threshold = consecutive_threshold;
        self
    }

    #[cfg(test)]
    fn with_pid_exists_fn(mut self, f: fn(u32) -> bool) -> Self {
        self.pid_exists_fn = f;
        self
    }

    /// Process an event and return an incident if a rootkit indicator is found.
    /// Also returns hidden-process incidents when the check interval has elapsed.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let now = event.ts;

        // Track PIDs from execve events
        if event.kind == "shell.command_exec" {
            self.track_pid(event);
        }

        // Remove PIDs on exit events (proper lifecycle tracking)
        if event.kind == "process.exit" {
            if let Some(pid) = event.details["pid"].as_u64() {
                self.pids.remove(&(pid as u32));
            }
        }

        // Kernel function timing analysis - runs for every event to build profiles
        if self.timing_enabled {
            if let Some(inc) = self.check_timing_anomaly(event, now) {
                return Some(inc);
            }
        }

        // Check for rootkit artifacts (openat events)
        if event.kind == "file.read_access" || event.kind == "file.write_access" {
            if let Some(inc) = self.check_rootkit_artifact(event, now) {
                return Some(inc);
            }
            if let Some(inc) = self.check_ld_so_preload_modification(event, now) {
                return Some(inc);
            }
            if let Some(inc) = self.check_syscall_recon(event, now) {
                return Some(inc);
            }
        }

        // Check for kernel module operations and process name spoofing (execve events)
        if event.kind == "shell.command_exec" {
            if let Some(inc) = self.check_kernel_module_op(event, now) {
                return Some(inc);
            }
            if let Some(inc) = self.check_ld_preload_hijack(event, now) {
                return Some(inc);
            }
            if let Some(inc) = self.check_process_name_spoof(event, now) {
                return Some(inc);
            }
        }

        // Hidden process check - now tracks both execve AND exit events.
        // Only flags PIDs that were born (execve) but never died (no exit event)
        // AND are missing from /proc. Short-lived processes are removed by exit events.
        if now - self.last_check >= self.check_interval {
            self.last_check = now;
            if let Some(inc) = self.check_hidden_processes(now) {
                return Some(inc);
            }
        }

        // Clean up state periodically
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }

    /// Track a PID from an eBPF execve event.
    fn track_pid(&mut self, event: &Event) {
        let pid = match event.details["pid"].as_u64() {
            Some(p) => p as u32,
            None => return,
        };
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let binary_path = event.details["command"].as_str().unwrap_or("").to_string();
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;

        if let Some(info) = self.pids.get_mut(&pid) {
            info.last_seen = event.ts;
            info.seen_count += 1;
            info.comm = comm;
            info.binary_path = binary_path;
            info.uid = uid;
        } else {
            self.pids.insert(
                pid,
                PidInfo {
                    comm,
                    binary_path,
                    last_seen: event.ts,
                    uid,
                    seen_count: 1,
                },
            );
        }
    }

    /// Check if any tracked PIDs are hidden from /proc.
    fn check_hidden_processes(&mut self, now: DateTime<Utc>) -> Option<Incident> {
        let check_fn = self.pid_exists_fn;
        let _short_lived_cutoff = now - Duration::seconds(2);

        for (&pid, info) in &self.pids {
            // Skip short-lived processes (< 5s since last seen) - normal exits
            let five_sec_cutoff = now - chrono::Duration::seconds(5);
            if info.last_seen > five_sec_cutoff {
                continue;
            }
            // Only flag if seen many times (persistent process, not one-shot commands)
            if info.seen_count < 5 {
                continue;
            }
            // Check if PID exists in /proc
            if !(check_fn)(pid) {
                let alert_key = format!("hidden_pid:{pid}");
                if self.is_cooled_down(&alert_key, now) {
                    continue;
                }
                self.alerted.insert(alert_key, now);

                return Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!(
                        "rootkit:hidden_pid:{pid}:{}",
                        now.format("%Y-%m-%dT%H:%MZ")
                    ),
                    severity: Severity::Critical,
                    title: format!("Hidden process detected: PID {pid}"),
                    summary: format!(
                        "Hidden process detected: PID {pid} ({}) visible to kernel but hidden from /proc",
                        info.comm
                    ),
                    evidence: serde_json::json!([{
                        "kind": "hidden_process",
                        "pid": pid,
                        "comm": info.comm,
                        "binary_path": info.binary_path,
                        "uid": info.uid,
                        "seen_count": info.seen_count,
                        "last_seen": info.last_seen.to_rfc3339(),
                    }]),
                    recommended_checks: vec![
                        format!("CRITICAL: PID {pid} is hidden from userspace - this is a strong rootkit indicator"),
                        "Check for loaded kernel modules: lsmod | diff - <(cat /proc/modules)".to_string(),
                        "Check for LD_PRELOAD rootkits: cat /etc/ld.so.preload".to_string(),
                        "Run rkhunter or chkrootkit for full rootkit scan".to_string(),
                        "Consider booting from a known-good live USB for forensic analysis".to_string(),
                    ],
                    tags: vec![
                        "ebpf".to_string(),
                        "rootkit".to_string(),
                        "hidden_process".to_string(),
                    ],
                    entities: vec![],
                });
            }
        }
        None
    }

    /// Check if an openat event accesses a known rootkit artifact path.
    fn check_rootkit_artifact(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let filename = event.details["filename"].as_str().unwrap_or("");
        if filename.is_empty() {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        // Check exact rootkit artifact paths
        let is_artifact = ROOTKIT_ARTIFACT_PATHS.contains(&filename);

        // Check suspicious files in /tmp and /dev/shm
        let is_suspicious_tmp = (filename.starts_with("/tmp/")
            || filename.starts_with("/dev/shm/"))
            && SUSPICIOUS_TMPFILE_NAMES.iter().any(|name| {
                let basename = filename.rsplit('/').next().unwrap_or("");
                basename == *name || basename.starts_with(name)
            });

        // Check for hidden directories in /dev or /dev/shm (dot-prefixed)
        let is_hidden_dev = (filename.starts_with("/dev/.") || filename.starts_with("/dev/shm/."))
            && !filename.starts_with("/dev/shm/.hidden") // already covered by artifact list
            && !filename.starts_with("/dev/.hidden")
            && filename != "/dev/shm/"
            && filename != "/dev/";

        if !is_artifact && !is_suspicious_tmp && !is_hidden_dev {
            return None;
        }

        let alert_key = format!("artifact:{filename}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "rootkit:artifact:{}:{}",
                filename.replace('/', "_"),
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!("Rootkit artifact: {filename}"),
            summary: format!("Rootkit artifact detected: {comm} (pid={pid}) accessed {filename}"),
            evidence: serde_json::json!([{
                "kind": "rootkit_artifact",
                "filename": filename,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Investigate rootkit artifact: {filename}"),
                format!("Check process {comm} (pid={pid}) - what created this file?"),
                "Check for LD_PRELOAD: cat /etc/ld.so.preload".to_string(),
                "Run: rkhunter --check --skip-keypress".to_string(),
                "Run: chkrootkit".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "artifact".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check if /etc/ld.so.preload is being modified (write access).
    fn check_ld_so_preload_modification(
        &mut self,
        event: &Event,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        if event.kind != "file.write_access" {
            return None;
        }

        let filename = event.details["filename"].as_str().unwrap_or("");
        if filename != "/etc/ld.so.preload" {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        let alert_key = "ld_so_preload_write".to_string();
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "rootkit:ld_preload_modify:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: "LD_PRELOAD rootkit: /etc/ld.so.preload modified".to_string(),
            summary: format!(
                "LD_PRELOAD rootkit indicator: {comm} (pid={pid}) writing to /etc/ld.so.preload"
            ),
            evidence: serde_json::json!([{
                "kind": "ld_preload_modification",
                "filename": filename,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                "CRITICAL: /etc/ld.so.preload modification is a rootkit installation technique"
                    .to_string(),
                "Check contents: cat /etc/ld.so.preload".to_string(),
                format!("Investigate process {comm} (pid={pid})"),
                "Remove suspicious entries and restart affected services".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "ld_preload".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check if a process is doing syscall table reconnaissance.
    fn check_syscall_recon(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let filename = event.details["filename"].as_str().unwrap_or("");
        if !RECON_PATHS
            .iter()
            .any(|p| filename == *p || filename.starts_with(p))
        {
            return None;
        }

        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        // Allow known legitimate tools
        if matches!(
            comm,
            "modprobe"
                | "depmod"
                | "systemd"
                | "systemd-modules"
                | "kmod"
                | "dracut"
                | "mkinitramfs"
                | "update-initramf"
                | "perf"
                | "bpftool"
                | "innerwarden"
        ) {
            return None;
        }

        let alert_key = format!("recon:{comm}:{filename}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("rootkit:recon:{comm}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Potential syscall table reconnaissance: {comm} reading {filename}"),
            summary: format!(
                "Potential syscall table reconnaissance: {comm} (pid={pid}) reading {filename}"
            ),
            evidence: serde_json::json!([{
                "kind": "syscall_recon",
                "filename": filename,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Investigate why {comm} is reading {filename}"),
                "This file contains kernel symbol addresses used for syscall table hooking"
                    .to_string(),
                format!("Check process lineage: ps -ef | grep {pid}"),
                "Check for kernel module rootkits: lsmod".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "recon".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check if insmod/modprobe/rmmod is loading a suspicious kernel module.
    fn check_kernel_module_op(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let command = event.details["command"].as_str().unwrap_or("");
        let comm = event.details["comm"].as_str().unwrap_or("");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        // Check if this is a kernel module operation
        let base_comm = comm.rsplit('/').next().unwrap_or(comm);
        let base_command = command.rsplit('/').next().unwrap_or(command);

        let is_module_op = matches!(base_comm, "insmod" | "modprobe" | "rmmod")
            || matches!(base_command, "insmod" | "modprobe" | "rmmod");

        if !is_module_op {
            return None;
        }

        // Extract module name from the command or arguments
        let module_name = self.extract_module_name(event);
        if module_name.is_empty() {
            return None;
        }

        // Check if it's a known-good module
        let module_base = module_name
            .rsplit('/')
            .next()
            .unwrap_or(&module_name)
            .trim_end_matches(".ko")
            .trim_end_matches(".ko.xz")
            .trim_end_matches(".ko.zst")
            .replace('-', "_");

        if KNOWN_GOOD_MODULES.iter().any(|m| *m == module_base) {
            return None;
        }

        let op = base_comm;
        let alert_key = format!("kmod:{op}:{module_base}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "rootkit:kmod:{op}:{module_base}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!("Suspicious kernel module operation: {op} {module_base}"),
            summary: format!(
                "Suspicious kernel module operation: {comm} (pid={pid}) - {op} {module_name}"
            ),
            evidence: serde_json::json!([{
                "kind": "kernel_module_operation",
                "operation": op,
                "module": module_name,
                "module_base": module_base,
                "comm": comm,
                "pid": pid,
            }]),
            recommended_checks: vec![
                format!("Investigate kernel module: {module_name}"),
                "Check loaded modules: lsmod".to_string(),
                "Compare with known-good module list".to_string(),
                format!("Check process {comm} (pid={pid}) - who initiated this?"),
                "If unexpected: rmmod the module and investigate".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "kernel_module".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Extract module name from event details.
    fn extract_module_name(&self, event: &Event) -> String {
        // Try argv first (more reliable)
        if let Some(argv) = event.details["argv"].as_array() {
            // Skip the command name (argv[0]) and flags starting with '-'
            for arg in argv.iter().skip(1) {
                if let Some(s) = arg.as_str() {
                    if !s.starts_with('-') {
                        return s.to_string();
                    }
                }
            }
        }
        // Fall back to command field
        let command = event.details["command"].as_str().unwrap_or("");
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.len() > 1 {
            return parts.last().unwrap_or(&"").to_string();
        }
        String::new()
    }

    /// Check for LD_PRELOAD hijacking in execve events.
    fn check_ld_preload_hijack(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let command = event.details["command"].as_str().unwrap_or("");
        let comm = event.details["comm"].as_str().unwrap_or("unknown");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        // Check if LD_PRELOAD appears in the command or environment
        // eBPF can capture the command line which may include env vars
        let preload_lib = if let Some(argv) = event.details["argv"].as_array() {
            argv.iter()
                .filter_map(|a| a.as_str())
                .find_map(|a| a.strip_prefix("LD_PRELOAD=").map(|lib| lib.to_string()))
        } else if command.contains("LD_PRELOAD=") {
            command
                .split_whitespace()
                .find_map(|part| part.strip_prefix("LD_PRELOAD=").map(|s| s.to_string()))
        } else {
            None
        };

        let library = match preload_lib {
            Some(lib) if !lib.is_empty() => lib,
            _ => return None,
        };

        // Check if the library is from a legitimate location
        if LEGIT_LIB_DIRS.iter().any(|dir| library.starts_with(dir)) {
            return None;
        }

        let alert_key = format!("ld_preload:{comm}:{library}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "rootkit:ld_preload:{comm}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!("LD_PRELOAD hijack: {comm} loading {library}"),
            summary: format!("LD_PRELOAD hijack: {comm} (pid={pid}) loading {library}"),
            evidence: serde_json::json!([{
                "kind": "ld_preload_hijack",
                "library": library,
                "comm": comm,
                "pid": pid,
                "command": command,
            }]),
            recommended_checks: vec![
                format!("Investigate LD_PRELOAD library: {library}"),
                format!("Check if {library} is a known legitimate library"),
                "Libraries outside /usr/lib, /lib, /usr/local/lib are suspicious".to_string(),
                format!("Check process {comm} (pid={pid})"),
                "If from /tmp or /dev/shm: almost certainly malicious".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "ld_preload".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check for process name spoofing.
    fn check_process_name_spoof(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let comm = event.details["comm"].as_str().unwrap_or("");
        let command = event.details["command"].as_str().unwrap_or("");
        let pid = event.details["pid"].as_u64().unwrap_or(0) as u32;

        if comm.is_empty() || command.is_empty() {
            return None;
        }

        // Extract the binary name from the full path.
        // command may contain full argv (e.g., "/bin/bash -pu /home/..."), so take only argv[0].
        let argv0 = command.split_whitespace().next().unwrap_or(command);
        let binary_name = argv0.rsplit('/').next().unwrap_or(argv0);

        // comm is truncated to 15 chars in Linux, so only compare up to comm length
        // Also, some legitimate programs set comm differently (e.g., python scripts)
        if binary_name.is_empty() || comm.is_empty() {
            return None;
        }

        // Check if comm could be a prefix/truncation of the binary name
        // Linux comm field is limited to 16 bytes (15 chars + null)
        let comm_matches = binary_name.starts_with(comm)
            || comm.starts_with(binary_name)
            || binary_name == comm
            || (comm.len() >= 15 && binary_name.starts_with(&comm[..15]));

        if comm_matches {
            return None;
        }

        // Only flag suspicious mismatches: binary from unusual locations
        let suspicious_binary = command.starts_with("/tmp/")
            || command.starts_with("/dev/shm/")
            || command.starts_with("/var/tmp/")
            || command.contains("/.hidden")
            || command.contains("/...")
            || binary_name.starts_with('.');

        // Allow known legitimate mismatches ONLY if the binary is not from a suspicious location
        if !suspicious_binary && is_legitimate_comm_mismatch(comm, binary_name) {
            return None;
        }

        if !suspicious_binary {
            return None;
        }

        let alert_key = format!("spoof:{pid}:{binary_name}:{comm}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("rootkit:spoof:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!("Process name spoofing: PID {pid} binary={command} but comm={comm}"),
            summary: format!("Process name spoofing: PID {pid} binary={command} but comm={comm}"),
            evidence: serde_json::json!([{
                "kind": "process_name_spoof",
                "pid": pid,
                "comm": comm,
                "binary_path": command,
                "binary_name": binary_name,
            }]),
            recommended_checks: vec![
                format!(
                    "Process {pid} is masquerading as '{comm}' but the real binary is {command}"
                ),
                "This is a common rootkit/malware technique to evade ps/top".to_string(),
                format!("Investigate: ls -la {command}"),
                format!("Check: cat /proc/{pid}/cmdline"),
                "If binary is in /tmp or /dev/shm: almost certainly malicious".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "spoof".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check inter-event timing for anomalies that indicate kernel function hooking.
    ///
    /// For each event kind, we track the time delta between consecutive events.
    /// After collecting enough samples (timing_min_samples), we use Welford's
    /// running statistics to detect anomalies: if delta > mean + z_threshold * stddev,
    /// the event is anomalous. After timing_consecutive_threshold consecutive anomalies
    /// for the same kind, we raise an incident.
    ///
    /// Specific patterns:
    /// - file.read_access anomaly → possible getdents64 hook (hiding files/processes)
    /// - shell.command_exec anomaly → possible execve hook
    /// - network.connection anomaly → possible connect hook (hiding network connections)
    fn check_timing_anomaly(&mut self, event: &Event, now: DateTime<Utc>) -> Option<Incident> {
        let kind = &event.kind;

        // Skip event kinds with naturally high latency variance.
        // network.accept blocks until a connection arrives (seconds to hours).
        // file.truncate latency depends on filesystem flush (ms to seconds under I/O load).
        // These produce timing spikes during normal operations (deploys, builds, idle periods).
        match kind.as_str() {
            "network.accept" | "network.listen" | "file.truncate" | "file.timestomp"
            | "process.exit" | "process.clone" => {
                return None;
            }
            _ => {}
        }

        let min_samples = self.timing_min_samples;
        let z_threshold = self.timing_z_threshold;
        let consecutive_threshold = self.timing_consecutive_threshold;

        // Snapshot needed for incident generation - extracted before releasing borrow
        let anomaly_info = {
            let stats = self
                .syscall_timing
                .entry(kind.clone())
                .or_insert_with(|| TimingStats::new(now));

            // Compute delta from last event of this kind
            let delta = now - stats.last_ts;
            let delta_ns = delta.num_nanoseconds().unwrap_or(0);

            // Skip the first event (no delta yet) and negative/zero deltas
            if delta_ns <= 0 {
                stats.last_ts = now;
                return None;
            }
            let delta_ns = delta_ns as u64;

            // Check anomaly BEFORE updating stats - so the baseline is not
            // contaminated by the potentially anomalous sample.
            //
            // When stddev is near-zero (all samples nearly identical), we use
            // a minimum effective stddev of mean/10 so that a delta of
            // mean + 4*(mean/10) = 1.4*mean still won't trigger, but a delta
            // orders of magnitude larger will.
            let raw_stddev = stats.stddev();
            let effective_stddev = if raw_stddev < stats.mean_ns * 0.01 {
                stats.mean_ns * 0.1
            } else {
                raw_stddev
            };

            let is_anomalous = stats.trained && effective_stddev >= 1.0 && {
                let threshold_ns = stats.mean_ns + z_threshold * effective_stddev;
                (delta_ns as f64) > threshold_ns
            };

            // Snapshot pre-update stats for incident reporting
            let pre_mean = stats.mean_ns;
            let pre_stddev = effective_stddev;
            let pre_count = stats.count;

            // Only update baseline with non-anomalous samples.
            // Anomalous samples would corrupt the running statistics
            // and prevent detection of sustained anomalies.
            if !is_anomalous {
                stats.update(delta_ns, min_samples);
            }
            stats.last_ts = now;

            if is_anomalous {
                stats.consecutive_anomalies += 1;
            } else {
                stats.consecutive_anomalies = 0;
                return None;
            }

            if stats.consecutive_anomalies < consecutive_threshold {
                return None;
            }

            // Extract values we need for the incident before releasing the borrow
            let actual_us = delta_ns / 1_000;
            let expected_us = (pre_mean / 1_000.0) as u64;
            let stddev_us = (pre_stddev / 1_000.0) as u64;
            let z_score = if pre_stddev > 0.0 {
                ((delta_ns as f64) - pre_mean) / pre_stddev
            } else {
                0.0
            };
            let total_samples = pre_count;

            Some((actual_us, expected_us, stddev_us, z_score, total_samples))
        };

        let (actual_us, expected_us, stddev_us, z_score, total_samples) = anomaly_info?;

        // Now we can access self freely - the mutable borrow on syscall_timing is released
        let alert_key = format!("timing:{kind}");
        if self.is_cooled_down(&alert_key, now) {
            return None;
        }
        self.alerted.insert(alert_key, now);

        // Reset consecutive count after alerting (cooldown reset)
        if let Some(s) = self.syscall_timing.get_mut(kind) {
            s.consecutive_anomalies = 0;
        }

        // Map event kind to suspected kernel hook
        let hook_hint = match kind.as_str() {
            "file.read_access" => " (possible getdents64 hook - hiding files/processes)",
            "shell.command_exec" => " (possible execve hook)",
            "network.connection" | "network.outbound_connect" => {
                " (possible connect hook - hiding network connections)"
            }
            _ => "",
        };

        let title = format!(
            "Syscall timing anomaly: {kind} latency {actual_us}\u{00B5}s vs {expected_us}\u{00B5}s baseline{hook_hint}"
        );

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "rootkit:timing:{kind}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: title.clone(),
            summary: format!(
                "Kernel function timing anomaly detected: {kind} shows {consecutive_threshold}+ consecutive \
                 latency spikes ({actual_us}\u{00B5}s vs {expected_us}\u{00B5}s baseline, z>{z_threshold}). \
                 This may indicate a rootkit hooking the underlying syscall{hook_hint}."
            ),
            evidence: serde_json::json!([{
                "kind": "timing_anomaly",
                "event_kind": kind,
                "actual_delta_us": actual_us,
                "baseline_mean_us": expected_us,
                "baseline_stddev_us": stddev_us,
                "z_score": z_score,
                "consecutive_anomalies": consecutive_threshold,
                "total_samples": total_samples,
            }]),
            recommended_checks: vec![
                format!(
                    "Kernel function timing anomaly on {kind}: {actual_us}\u{00B5}s vs {expected_us}\u{00B5}s baseline"
                ),
                "This pattern is consistent with a rootkit hooking kernel functions (e.g., getdents64, execve, connect)".to_string(),
                "Check for loaded kernel modules: lsmod | diff - <(cat /proc/modules)".to_string(),
                "Run rkhunter or chkrootkit for full rootkit scan".to_string(),
                "Compare syscall table: cat /proc/kallsyms | grep sys_call_table".to_string(),
                "If confirmed: boot from live USB for forensic analysis".to_string(),
            ],
            tags: vec![
                "ebpf".to_string(),
                "rootkit".to_string(),
                "timing_anomaly".to_string(),
            ],
            entities: vec![],
        })
    }

    /// Check cooldown - returns true if the alert is still in cooldown.
    fn is_cooled_down(&self, key: &str, now: DateTime<Utc>) -> bool {
        if let Some(&last) = self.alerted.get(key) {
            now - last < self.cooldown
        } else {
            false
        }
    }
}

/// Known legitimate cases where comm != binary name.
fn is_legitimate_comm_mismatch(comm: &str, binary_name: &str) -> bool {
    // Script interpreters: binary is python3/bash/etc, comm is the script name
    let interpreters = [
        "python", "python3", "python2", "perl", "ruby", "node", "java", "php", "bash", "sh", "zsh",
        "dash", "fish", "env", "nice", "nohup", "timeout", "strace",
    ];
    if interpreters.contains(&binary_name) || interpreters.contains(&comm) {
        return true;
    }
    // systemd services often have different comm
    if comm.starts_with("systemd") || binary_name.starts_with("systemd") {
        return true;
    }
    // busybox: single binary, many names
    if binary_name == "busybox" || comm == "busybox" {
        return true;
    }
    // Package managers and tools that fork with different names
    let package_tools = [
        "brew",
        "cargo",
        "rustc",
        "go",
        "npm",
        "yarn",
        "pnpm",
        "pip",
        "pip3",
        "gem",
        "conda",
        "uv",
        "composer",
        "maven",
        "gradle",
        "make",
        "cmake",
        "ninja",
        "cc1",
        "cc1plus",
        "as",
        "ld",
        "collect2",
        "lto-wrapper",
        "dpkg",
        "apt",
        "snapd",
        "dnf",
        "yum",
    ];
    if package_tools.contains(&comm) || package_tools.contains(&binary_name) {
        return true;
    }
    // Monitoring and infrastructure
    let infra = [
        "gomon",
        "updater",
        "oracle-cloud",
        "cloud-init",
        "landscape",
        "unattended-upgr",
        "snapd",
        "containerd-shim",
    ];
    if infra
        .iter()
        .any(|i| comm.starts_with(i) || binary_name.starts_with(i))
    {
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

    fn exec_event(comm: &str, command: &str, pid: u32, ts: DateTime<Utc>) -> Event {
        exec_event_with_argv(comm, command, pid, ts, None)
    }

    fn exec_event_with_argv(
        comm: &str,
        command: &str,
        pid: u32,
        ts: DateTime<Utc>,
        argv: Option<Vec<&str>>,
    ) -> Event {
        let argv_json: Vec<serde_json::Value> = argv
            .unwrap_or_else(|| vec![command])
            .iter()
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();

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
                "argv": argv_json,
                "argc": argv_json.len(),
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn file_event(comm: &str, filename: &str, pid: u32, write: bool, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: if write {
                "file.write_access".to_string()
            } else {
                "file.read_access".to_string()
            },
            severity: Severity::Info,
            summary: format!(
                "{comm} (pid={pid}) {} {filename}",
                if write { "writing" } else { "reading" }
            ),
            details: serde_json::json!({
                "pid": pid,
                "uid": 0,
                "ppid": 1,
                "comm": comm,
                "filename": filename,
                "flags": if write { 1 } else { 0 },
                "write": write,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    // --- Test 1: Known rootkit artifact path triggers (Critical) ---
    #[test]
    fn rootkit_artifact_path_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("cat", "/dev/.hidden", 100, false, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/dev/.hidden"));
        assert!(inc.tags.contains(&"rootkit".to_string()));
    }

    // --- Test 2: Normal file path doesn't trigger ---
    #[test]
    fn normal_file_path_does_not_trigger() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        assert!(det
            .process(&file_event("cat", "/etc/passwd", 100, false, now))
            .is_none());
        assert!(det
            .process(&file_event("vim", "/home/user/file.txt", 101, true, now))
            .is_none());
    }

    // --- Test 3: LD_PRELOAD from /tmp triggers ---
    #[test]
    fn ld_preload_from_tmp_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "malware",
            "/usr/bin/ls",
            200,
            now,
            Some(vec!["/usr/bin/ls", "LD_PRELOAD=/tmp/evil.so"]),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("LD_PRELOAD"));
        assert!(inc.title.contains("/tmp/evil.so"));
    }

    // --- Test 4: LD_PRELOAD from /usr/lib doesn't trigger ---
    #[test]
    fn ld_preload_from_usr_lib_does_not_trigger() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "app",
            "/usr/bin/app",
            200,
            now,
            Some(vec!["/usr/bin/app", "LD_PRELOAD=/usr/lib/libjemalloc.so"]),
        );
        assert!(det.process(&ev).is_none());
    }

    // --- Test 5: insmod suspicious module triggers (Critical) ---
    #[test]
    fn insmod_suspicious_module_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "insmod",
            "/sbin/insmod",
            300,
            now,
            Some(vec!["/sbin/insmod", "/tmp/rootkit.ko"]),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("insmod"));
        assert!(inc.title.contains("rootkit"));
    }

    // --- Test 6: insmod known-good module doesn't trigger ---
    #[test]
    fn insmod_known_good_module_does_not_trigger() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "insmod",
            "/sbin/insmod",
            300,
            now,
            Some(vec!["/sbin/insmod", "ext4"]),
        );
        assert!(det.process(&ev).is_none());
    }

    // --- Test 7: modprobe suspicious module triggers ---
    #[test]
    fn modprobe_suspicious_module_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "modprobe",
            "/sbin/modprobe",
            301,
            now,
            Some(vec!["/sbin/modprobe", "diamorphine"]),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("modprobe"));
    }

    // --- Test 8: rmmod suspicious module triggers ---
    #[test]
    fn rmmod_suspicious_module_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = exec_event_with_argv(
            "rmmod",
            "/sbin/rmmod",
            302,
            now,
            Some(vec!["/sbin/rmmod", "hidden_module"]),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("rmmod"));
    }

    // --- Test 9: System.map access triggers ---
    #[test]
    fn system_map_access_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("exploit", "/boot/System.map", 400, false, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("System.map"));
        assert!(inc.title.contains("exploit"));
    }

    // --- Test 10: /proc/kallsyms access triggers ---
    #[test]
    fn proc_kallsyms_access_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("suspicious", "/proc/kallsyms", 401, false, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("kallsyms"));
    }

    // --- Test 11: Normal /proc access doesn't trigger ---
    #[test]
    fn normal_proc_access_does_not_trigger() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        assert!(det
            .process(&file_event("cat", "/proc/cpuinfo", 500, false, now))
            .is_none());
        assert!(det
            .process(&file_event("cat", "/proc/meminfo", 501, false, now))
            .is_none());
        assert!(det
            .process(&file_event("ps", "/proc/1/status", 502, false, now))
            .is_none());
    }

    // --- Test 12: Process name spoofing triggers ---
    #[test]
    fn process_name_spoofing_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        // Binary is in /tmp with hidden name, but comm shows "bash"
        let ev = exec_event("bash", "/tmp/.hidden_miner", 600, now);
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("spoof"));
        assert!(inc.title.contains("bash"));
        assert!(inc.title.contains(".hidden_miner"));
    }

    // --- Test 13: Matching comm and binary doesn't trigger ---
    #[test]
    fn matching_comm_binary_does_not_trigger() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        assert!(det
            .process(&exec_event("curl", "/usr/bin/curl", 700, now))
            .is_none());
        assert!(det
            .process(&exec_event("bash", "/usr/bin/bash", 701, now))
            .is_none());
        assert!(det
            .process(&exec_event("ls", "/bin/ls", 702, now))
            .is_none());
    }

    // --- Test 14: Cooldown suppresses re-alert ---
    #[test]
    fn cooldown_suppresses_realert() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        // First alert
        let inc = det.process(&file_event("cat", "/dev/.hidden", 100, false, now));
        assert!(inc.is_some());

        // Second alert within cooldown - suppressed
        let inc2 = det.process(&file_event(
            "cat",
            "/dev/.hidden",
            100,
            false,
            now + Duration::seconds(5),
        ));
        assert!(inc2.is_none());

        // After cooldown - should alert again
        let inc3 = det.process(&file_event(
            "cat",
            "/dev/.hidden",
            100,
            false,
            now + Duration::seconds(601),
        ));
        assert!(inc3.is_some());
    }

    // --- Test 15: Different PIDs tracked independently ---
    #[test]
    fn different_pids_tracked_independently() {
        // Test that the PID tracking stores separate entries
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        det.process(&exec_event("bash", "/usr/bin/bash", 1000, now));
        det.process(&exec_event("curl", "/usr/bin/curl", 2000, now));

        assert!(det.pids.contains_key(&1000));
        assert!(det.pids.contains_key(&2000));
        assert_eq!(det.pids[&1000].comm, "bash");
        assert_eq!(det.pids[&2000].comm, "curl");
    }

    // --- Test 16: Short-lived process excluded from hidden check ---
    #[test]
    fn short_lived_process_excluded_from_hidden_check() {
        // Use a pid_exists function that always returns false (simulating hidden)
        fn never_exists(_pid: u32) -> bool {
            false
        }

        let mut det = RootkitDetector::new("test", 10, 600).with_pid_exists_fn(never_exists);
        let now = Utc::now();

        // Add a PID that was just seen (< 2s ago) - should be excluded
        det.pids.insert(
            1234,
            PidInfo {
                comm: "malware".to_string(),
                binary_path: "/tmp/malware".to_string(),
                last_seen: now - Duration::seconds(1), // 1s ago - still short-lived
                uid: 0,
                seen_count: 5,
            },
        );

        det.last_check = now - Duration::seconds(11); // Force check
        let inc = det.check_hidden_processes(now);
        assert!(inc.is_none(), "Short-lived process should be excluded");

        // Now make the PID old enough (> 2s)
        det.pids.get_mut(&1234).unwrap().last_seen = now - Duration::seconds(5);
        let inc2 = det.check_hidden_processes(now);
        assert!(inc2.is_some(), "Old enough PID should be flagged");
        assert_eq!(inc2.unwrap().severity, Severity::Critical);
    }

    // --- Test 17: /etc/ld.so.preload modification triggers ---
    #[test]
    fn ld_so_preload_modification_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("exploit", "/etc/ld.so.preload", 800, true, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ld.so.preload"));
    }

    // --- Test 18: Hidden directory in /dev/shm triggers ---
    #[test]
    fn hidden_directory_in_dev_shm_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("cat", "/dev/shm/.hidden", 900, false, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("Rootkit artifact"));
    }

    // --- Additional tests ---

    #[test]
    fn libprocesshider_artifact_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event(
            "ld.so",
            "/usr/lib/libprocesshider.so",
            950,
            false,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("libprocesshider"));
    }

    #[test]
    fn suspicious_tmp_file_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("cat", "/tmp/.x", 960, false, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn suspicious_devshm_file_triggers() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let inc = det.process(&file_event("cat", "/dev/shm/.kdev", 970, false, now));
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn legitimate_tools_reading_kallsyms_excluded() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        // perf and bpftool legitimately read /proc/kallsyms
        assert!(det
            .process(&file_event("perf", "/proc/kallsyms", 980, false, now))
            .is_none());
        assert!(det
            .process(&file_event("bpftool", "/proc/kallsyms", 981, false, now))
            .is_none());
        assert!(det
            .process(&file_event("modprobe", "/boot/System.map", 982, false, now))
            .is_none());
    }

    #[test]
    fn hidden_process_needs_multiple_sightings() {
        fn never_exists(_pid: u32) -> bool {
            false
        }

        let mut det = RootkitDetector::new("test", 10, 600).with_pid_exists_fn(never_exists);
        let now = Utc::now();

        // PID seen only once - should NOT be flagged
        det.pids.insert(
            5555,
            PidInfo {
                comm: "suspicious".to_string(),
                binary_path: "/tmp/bad".to_string(),
                last_seen: now - Duration::seconds(5),
                uid: 0,
                seen_count: 1, // only once
            },
        );

        det.last_check = now - Duration::seconds(11);
        assert!(
            det.check_hidden_processes(now).is_none(),
            "PID seen only once should not be flagged"
        );

        // Now bump seen_count to 5 (persistent process threshold)
        det.pids.get_mut(&5555).unwrap().seen_count = 5;
        det.pids.get_mut(&5555).unwrap().last_seen = now - Duration::seconds(10);
        assert!(
            det.check_hidden_processes(now).is_some(),
            "PID seen 5+ times should be flagged"
        );
    }

    #[test]
    fn kernel_module_with_ko_extension_stripped() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        // ext4.ko should be recognized as known-good
        let ev = exec_event_with_argv(
            "insmod",
            "/sbin/insmod",
            330,
            now,
            Some(vec![
                "/sbin/insmod",
                "/lib/modules/5.15.0/kernel/fs/ext4/ext4.ko",
            ]),
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_relevant_event_kinds() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        let ev = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "connect".to_string(),
            details: serde_json::json!({"pid": 100, "comm": "curl"}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ld_so_preload_read_does_not_trigger_modification() {
        let mut det = RootkitDetector::new("test", 10, 600);
        let now = Utc::now();

        // Reading /etc/ld.so.preload is normal - only writing should trigger
        let inc = det.process(&file_event("cat", "/etc/ld.so.preload", 810, false, now));
        // This should not trigger the modification check (but may trigger artifact check
        // only if the path is in the artifact list - it's not, so should be None)
        assert!(inc.is_none());
    }

    // -----------------------------------------------------------------------
    // Kernel function timing analysis tests
    // -----------------------------------------------------------------------

    /// Helper: create a generic event with a specific kind and timestamp.
    /// Uses a benign filename so it doesn't trigger artifact/recon checks.
    fn timing_event(kind: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: kind.to_string(),
            severity: Severity::Info,
            summary: format!("timing test event: {kind}"),
            details: serde_json::json!({
                "pid": 9999,
                "uid": 1000,
                "ppid": 1,
                "comm": "app",
                "filename": "/home/user/data.txt",
                "command": "/usr/bin/app",
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    /// Helper: create a detector with low thresholds for timing tests.
    fn timing_detector(min_samples: u64, z_threshold: f64, consecutive: usize) -> RootkitDetector {
        RootkitDetector::new("test", 10, 600).with_timing_config(
            true,
            min_samples,
            z_threshold,
            consecutive,
        )
    }

    // --- Timing Test 1: Welford mean/stddev correct ---
    #[test]
    fn timing_stats_welford_mean_stddev_correct() {
        let mut stats = TimingStats::new(Utc::now());
        let values: Vec<u64> = vec![10, 20, 30, 40, 50];

        for v in &values {
            stats.update(*v, 3);
        }

        // Mean should be 30.0
        assert!(
            (stats.mean_ns - 30.0).abs() < 0.001,
            "mean={}",
            stats.mean_ns
        );

        // Population stddev of [10,20,30,40,50] = sqrt(200) ≈ 14.142
        let stddev = stats.stddev();
        assert!((stddev - 14.1421).abs() < 0.01, "stddev={stddev}");

        assert_eq!(stats.count, 5);
        assert_eq!(stats.min_ns, 10);
        assert_eq!(stats.max_ns, 50);
        assert!(stats.trained); // 5 >= min_samples(3)
    }

    // --- Timing Test 2: Normal timing doesn't trigger ---
    #[test]
    fn timing_normal_does_not_trigger() {
        // min_samples=10, z=4.0, consecutive=5
        let mut det = timing_detector(10, 4.0, 5);
        let base = Utc::now();

        // Feed 20 events at regular 100ms intervals - all normal, no anomaly
        for i in 0..20 {
            let ts = base + Duration::milliseconds(i * 100);
            let ev = timing_event("file.read_access", ts);
            let inc = det.process(&ev);
            assert!(inc.is_none(), "Normal timing should not trigger at i={i}");
        }
    }

    // --- Timing Test 3: Single anomalous timing doesn't trigger ---
    #[test]
    fn timing_single_anomaly_does_not_trigger() {
        // min_samples=10, z=4.0, consecutive=5
        let mut det = timing_detector(10, 4.0, 5);
        let base = Utc::now();

        // Train with 15 events at 100ms intervals
        for i in 0..15 {
            let ts = base + Duration::milliseconds(i * 100);
            det.process(&timing_event("file.read_access", ts));
        }

        // One big spike (10 seconds) - should NOT trigger (need 5 consecutive)
        let spike_ts = base + Duration::milliseconds(15 * 100) + Duration::seconds(10);
        let inc = det.process(&timing_event("file.read_access", spike_ts));
        assert!(
            inc.is_none(),
            "Single anomalous timing should not trigger an incident"
        );

        // Back to normal
        let normal_ts = spike_ts + Duration::milliseconds(100);
        let inc = det.process(&timing_event("file.read_access", normal_ts));
        assert!(inc.is_none());
    }

    // --- Timing Test 4: 5 consecutive anomalous timings trigger ---
    #[test]
    fn timing_consecutive_anomalies_trigger() {
        // min_samples=10, z=4.0, consecutive=5
        let mut det = timing_detector(10, 4.0, 5);
        let base = Utc::now();

        // Train with 15 events at 1ms intervals (mean ~1ms, very tight stddev)
        for i in 0..15 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        // Verify trained
        assert!(det.syscall_timing["file.read_access"].trained);

        // Now send 5+ events with 10-second gaps (massive anomaly vs 1ms baseline)
        let mut last_ts = base + Duration::milliseconds(15);
        let mut triggered = false;
        for _i in 0..10 {
            last_ts += Duration::seconds(10);
            if let Some(inc) = det.process(&timing_event("file.read_access", last_ts)) {
                assert_eq!(inc.severity, Severity::High);
                assert!(inc.title.contains("timing anomaly"), "title={}", inc.title);
                assert!(
                    inc.title.contains("file.read_access"),
                    "title={}",
                    inc.title
                );
                assert!(inc.tags.contains(&"timing_anomaly".to_string()));
                triggered = true;
                break;
            }
        }
        assert!(
            triggered,
            "Should trigger after 5 consecutive anomalous timings"
        );
    }

    // --- Timing Test 5: Different syscall kinds tracked independently ---
    #[test]
    fn timing_different_kinds_tracked_independently() {
        let mut det = timing_detector(5, 4.0, 3);
        let base = Utc::now();

        // Feed 8 file.read_access events at 1ms intervals
        for i in 0..8 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        // Feed 8 shell.command_exec events at 50ms intervals
        for i in 0..8 {
            let ts = base + Duration::milliseconds(i * 50);
            det.process(&timing_event("shell.command_exec", ts));
        }

        // Both should be tracked independently
        assert!(det.syscall_timing.contains_key("file.read_access"));
        assert!(det.syscall_timing.contains_key("shell.command_exec"));

        let file_stats = &det.syscall_timing["file.read_access"];
        let exec_stats = &det.syscall_timing["shell.command_exec"];

        // file.read_access mean should be ~1ms
        assert!(file_stats.trained);
        assert!(
            file_stats.mean_ns < 5_000_000.0,
            "file mean={}",
            file_stats.mean_ns
        );

        // shell.command_exec mean should be ~50ms
        assert!(exec_stats.trained);
        assert!(
            exec_stats.mean_ns > 10_000_000.0,
            "exec mean={}",
            exec_stats.mean_ns
        );
    }

    // --- Timing Test 6: Untrained profile doesn't trigger ---
    #[test]
    fn timing_untrained_does_not_trigger() {
        // Require 100 samples (default), but only provide 5
        let mut det = timing_detector(100, 4.0, 5);
        let base = Utc::now();

        // Feed only 5 events at 1ms intervals, then one massive spike
        for i in 0..5 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        // Profile is NOT trained (5 < 100)
        assert!(
            !det.syscall_timing["file.read_access"].trained,
            "Should not be trained with only 5 samples"
        );

        // Even a massive spike should not trigger
        for _ in 0..10 {
            let spike_ts = base + Duration::seconds(100);
            let inc = det.process(&timing_event("file.read_access", spike_ts));
            assert!(
                inc.is_none(),
                "Untrained profile should never trigger an incident"
            );
        }
    }

    // --- Timing Test 7: file.read_access anomaly mentions getdents64 ---
    #[test]
    fn timing_file_read_anomaly_mentions_getdents64() {
        // min_samples=10, z=4.0, consecutive=3 (lower threshold for test)
        let mut det = timing_detector(10, 4.0, 3);
        let base = Utc::now();

        // Train with 15 events at 1ms intervals
        for i in 0..15 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        // Now send 3 events with massive gaps
        let mut last_ts = base + Duration::milliseconds(15);
        let mut incident = None;
        for _ in 0..3 {
            last_ts += Duration::seconds(10);
            if let Some(inc) = det.process(&timing_event("file.read_access", last_ts)) {
                incident = Some(inc);
                break;
            }
        }

        let inc = incident.expect("Should trigger timing anomaly for file.read_access");
        assert!(
            inc.title.contains("getdents64"),
            "file.read_access anomaly should mention getdents64 hook, title={}",
            inc.title
        );
    }

    // --- Timing Test 8: Consecutive counter resets after alert (cooldown) ---
    #[test]
    fn timing_resets_consecutive_after_alert() {
        // min_samples=10, z=4.0, consecutive=3
        let mut det = timing_detector(10, 4.0, 3);
        let base = Utc::now();

        // Train with 15 events at 1ms intervals
        for i in 0..15 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        // Trigger with 3 anomalous events
        let mut last_ts = base + Duration::milliseconds(15);
        let mut triggered = false;
        for _ in 0..3 {
            last_ts += Duration::seconds(10);
            if det
                .process(&timing_event("file.read_access", last_ts))
                .is_some()
            {
                triggered = true;
                break;
            }
        }
        assert!(triggered, "Should have triggered first alert");

        // After alert, consecutive_anomalies should be reset to 0
        assert_eq!(
            det.syscall_timing["file.read_access"].consecutive_anomalies, 0,
            "consecutive_anomalies should be reset after alert"
        );

        // A single new anomaly should NOT trigger (need 3 more consecutive)
        last_ts += Duration::seconds(10);
        let inc = det.process(&timing_event("file.read_access", last_ts));
        assert!(
            inc.is_none(),
            "Should not trigger immediately after reset - needs consecutive threshold again"
        );
    }

    // --- Timing Test 9 (bonus): timing disabled means no analysis ---
    #[test]
    fn timing_disabled_no_analysis() {
        let mut det = RootkitDetector::new("test", 10, 600).with_timing_config(false, 10, 4.0, 3);
        let base = Utc::now();

        // Feed enough events and anomalies to normally trigger
        for i in 0..15 {
            let ts = base + Duration::milliseconds(i);
            det.process(&timing_event("file.read_access", ts));
        }

        let mut last_ts = base + Duration::milliseconds(15);
        for _ in 0..5 {
            last_ts += Duration::seconds(10);
            let inc = det.process(&timing_event("file.read_access", last_ts));
            assert!(
                inc.is_none(),
                "Timing disabled should never produce incidents"
            );
        }

        // No timing stats should have been collected
        assert!(
            det.syscall_timing.is_empty(),
            "No timing stats should be tracked when disabled"
        );
    }
}
