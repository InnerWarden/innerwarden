//! System hardening advisor — scans configuration and suggests improvements.
//!
//! `innerwarden harden` reads system files, evaluates security posture,
//! and prints actionable recommendations. Never applies changes automatically.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::Result;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn icon(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m\u{2139}\x1b[0m ", // ℹ cyan
            Severity::Low => "\x1b[34m\u{25cf}\x1b[0m ",  // ● blue
            Severity::Medium => "\x1b[33m\u{26a0}\x1b[0m ", // ⚠ yellow
            Severity::High => "\x1b[91m\u{26a0}\x1b[0m ", // ⚠ red
            Severity::Critical => "\x1b[31m\u{2718}\x1b[0m ", // ✘ red
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    fn score_penalty(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 10,
            Severity::Critical => 20,
        }
    }
}

#[allow(dead_code)]
struct Finding {
    category: &'static str,
    severity: Severity,
    title: String,
    fix: String,
}

struct CheckResult {
    category: &'static str,
    passed: Vec<String>,
    findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

fn check_ssh() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "SSH";

    let sshd_config = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    // Also read config fragments in sshd_config.d/
    let mut full_config = sshd_config.clone();
    if let Ok(entries) = fs::read_dir("/etc/ssh/sshd_config.d") {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                full_config.push('\n');
                full_config.push_str(&content);
            }
        }
    }

    let get = |key: &str| -> Option<String> {
        for line in full_config.lines().rev() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() == 2 && parts[0].eq_ignore_ascii_case(key) {
                return Some(parts[1].trim().to_string());
            }
        }
        None
    };

    // Password authentication
    match get("PasswordAuthentication").as_deref() {
        Some("no") => passed.push("Password authentication disabled".into()),
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "Password authentication is enabled".into(),
            fix: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Root login
    match get("PermitRootLogin").as_deref() {
        Some("no") | Some("prohibit-password") => {
            passed.push("Root login restricted".into());
        }
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "Root login via SSH is permitted".into(),
            fix: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Default port
    match get("Port").as_deref() {
        Some("22") | None => findings.push(Finding {
            category: cat,
            severity: Severity::Low,
            title: "SSH running on default port 22".into(),
            fix: "Consider changing to a non-standard port in /etc/ssh/sshd_config".into(),
        }),
        _ => passed.push("SSH on non-standard port".into()),
    }

    // MaxAuthTries
    match get("MaxAuthTries") {
        Some(v) if v.parse::<u32>().unwrap_or(6) <= 3 => {
            passed.push(format!("MaxAuthTries set to {v}"));
        }
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "MaxAuthTries not restricted (default: 6)".into(),
            fix: "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Empty passwords
    match get("PermitEmptyPasswords").as_deref() {
        Some("yes") => findings.push(Finding {
            category: cat,
            severity: Severity::Critical,
            title: "Empty passwords are permitted".into(),
            fix: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config".into(),
        }),
        _ => passed.push("Empty passwords not permitted".into()),
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_firewall() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Firewall";

    // Check UFW
    let ufw = Command::new("ufw").arg("status").output();
    match ufw {
        Ok(out) => {
            let status = String::from_utf8_lossy(&out.stdout);
            if status.contains("Status: active") {
                passed.push("UFW firewall is active".into());

                // Check default policy
                if status.contains("Default: deny (incoming)") {
                    passed.push("Default incoming policy: deny".into());
                } else {
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::High,
                        title: "Default incoming policy is not 'deny'".into(),
                        fix: "Run: sudo ufw default deny incoming".into(),
                    });
                }
            } else {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Critical,
                    title: "Firewall (UFW) is not active".into(),
                    fix: "Run: sudo ufw enable".into(),
                });
            }
        }
        Err(_) => {
            // Check iptables as fallback
            let ipt = Command::new("iptables").args(["-L", "-n"]).output();
            match ipt {
                Ok(out) => {
                    let rules = String::from_utf8_lossy(&out.stdout);
                    if rules.lines().count() > 5 {
                        passed.push("iptables rules configured".into());
                    } else {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: "No firewall rules detected".into(),
                            fix:
                                "Install and configure UFW: sudo apt install ufw && sudo ufw enable"
                                    .into(),
                        });
                    }
                }
                Err(_) => findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: "No firewall detected".into(),
                    fix: "Install UFW: sudo apt install ufw && sudo ufw enable".into(),
                }),
            }
        }
    }

    // Check open ports
    if let Ok(out) = Command::new("ss").args(["-tlnp"]).output() {
        let lines = String::from_utf8_lossy(&out.stdout);
        let risky_ports: Vec<(&str, &str)> = vec![
            (":3306 ", "MySQL"),
            (":5432 ", "PostgreSQL"),
            (":6379 ", "Redis"),
            (":27017", "MongoDB"),
            (":11211", "Memcached"),
        ];
        for (pattern, name) in &risky_ports {
            if lines.contains(pattern) && lines.contains("0.0.0.0:") {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: format!("{name} is listening on all interfaces"),
                    fix: format!(
                        "Bind {name} to 127.0.0.1 only, or restrict access with firewall rules"
                    ),
                });
            }
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_kernel() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Kernel";

    let read_sysctl = |path: &str| -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    };

    // ASLR
    match read_sysctl("/proc/sys/kernel/randomize_va_space").as_deref() {
        Some("2") => passed.push("ASLR fully enabled".into()),
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "ASLR not fully enabled".into(),
            fix: "Run: sudo sysctl -w kernel.randomize_va_space=2".into(),
        }),
    }

    // SYN cookies
    match read_sysctl("/proc/sys/net/ipv4/tcp_syncookies").as_deref() {
        Some("1") => passed.push("SYN cookies enabled".into()),
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "SYN cookies not enabled (SYN flood risk)".into(),
            fix: "Run: sudo sysctl -w net.ipv4.tcp_syncookies=1".into(),
        }),
    }

    // IP forwarding (should be off unless needed)
    match read_sysctl("/proc/sys/net/ipv4/ip_forward").as_deref() {
        Some("0") => passed.push("IP forwarding disabled".into()),
        Some("1") => findings.push(Finding {
            category: cat,
            severity: Severity::Low,
            title: "IP forwarding is enabled".into(),
            fix: "If not needed: sudo sysctl -w net.ipv4.ip_forward=0".into(),
        }),
        _ => {}
    }

    // ICMP redirects
    match read_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects").as_deref() {
        Some("0") => passed.push("ICMP redirects rejected".into()),
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "ICMP redirects accepted (MITM risk)".into(),
            fix: "Run: sudo sysctl -w net.ipv4.conf.all.accept_redirects=0".into(),
        }),
    }

    // Source routing
    match read_sysctl("/proc/sys/net/ipv4/conf/all/accept_source_route").as_deref() {
        Some("0") => passed.push("Source routing disabled".into()),
        _ => findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Source routing accepted".into(),
            fix: "Run: sudo sysctl -w net.ipv4.conf.all.accept_source_route=0".into(),
        }),
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_permissions() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Permissions";

    // World-writable files in sensitive dirs
    if let Ok(out) = Command::new("find")
        .args(["/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"])
        .output()
    {
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let files: Vec<&str> = raw.trim().lines().collect();
        if files.is_empty() || (files.len() == 1 && files[0].is_empty()) {
            passed.push("No world-writable files in /etc".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("{} world-writable file(s) in /etc", files.len()),
                fix: format!(
                    "Review and fix: {}",
                    files.into_iter().take(3).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // SUID binaries outside standard set
    let standard_suid = [
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/snapd/snap-confine",
        "/usr/bin/pkexec",
        "/usr/bin/at",
        "/usr/bin/crontab",
    ];
    if let Ok(out) = Command::new("find")
        .args(["/usr", "-perm", "-4000", "-type", "f"])
        .output()
    {
        let suids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .trim()
            .lines()
            .filter(|l| !l.is_empty())
            .filter(|l| !standard_suid.contains(l))
            .map(String::from)
            .collect();
        if suids.is_empty() {
            passed.push("No unusual SUID binaries".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} non-standard SUID binary(ies)", suids.len()),
                fix: format!(
                    "Review if needed: {}",
                    suids.into_iter().take(5).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // /etc/shadow permissions
    if let Ok(meta) = fs::metadata("/etc/shadow") {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode <= 0o640 {
            passed.push(format!("/etc/shadow permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Critical,
                title: format!("/etc/shadow too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 640 /etc/shadow".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_updates() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Updates";

    // Check for apt-based distros
    if Path::new("/usr/bin/apt").exists() {
        if let Ok(out) = Command::new("apt")
            .args(["list", "--upgradable"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
        {
            let raw = String::from_utf8_lossy(&out.stdout).to_string();
            let lines: Vec<&str> = raw
                .trim()
                .lines()
                .filter(|l| !l.starts_with("Listing"))
                .collect();
            let security_updates = lines.iter().filter(|l| l.contains("security")).count();

            if lines.is_empty() {
                passed.push("System is up to date".into());
            } else if security_updates > 0 {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: format!(
                        "{} security update(s) pending ({} total)",
                        security_updates,
                        lines.len()
                    ),
                    fix: "Run: sudo apt update && sudo apt upgrade -y".into(),
                });
            } else {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Low,
                    title: format!("{} package update(s) available", lines.len()),
                    fix: "Run: sudo apt update && sudo apt upgrade -y".into(),
                });
            }
        }

        // Check unattended-upgrades
        if Path::new("/etc/apt/apt.conf.d/20auto-upgrades").exists() {
            passed.push("Automatic security updates configured".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "Automatic security updates not configured".into(),
                fix: "Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_docker() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Docker";

    // Check if Docker is installed
    if Command::new("docker").arg("--version").output().is_err() {
        passed.push("Docker not installed (no container risks)".into());
        return CheckResult {
            category: cat,
            passed,
            findings,
        };
    }

    // Check for privileged containers
    if let Ok(out) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}} {{.Status}}"])
        .output()
    {
        let containers = String::from_utf8_lossy(&out.stdout);
        let count = containers.trim().lines().filter(|l| !l.is_empty()).count();
        if count > 0 {
            passed.push(format!("{count} container(s) running"));
        }
    }

    if let Ok(out) = Command::new("docker").args(["ps", "-q"]).output() {
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let ids: Vec<&str> = raw.trim().lines().filter(|l| !l.is_empty()).collect();
        for id in &ids {
            if let Ok(inspect) = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.Name}} {{.HostConfig.Privileged}}",
                    id,
                ])
                .output()
            {
                let info = String::from_utf8_lossy(&inspect.stdout);
                if info.contains("true") {
                    let name = info.split_whitespace().next().unwrap_or(id);
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::Critical,
                        title: format!("Container {name} running in privileged mode"),
                        fix: format!("Remove --privileged flag from container {name}"),
                    });
                }
            }
        }
        if findings.is_empty() && !ids.is_empty() {
            passed.push("No privileged containers".into());
        }
    }

    // Docker socket permissions
    if let Ok(meta) = fs::metadata("/var/run/docker.sock") {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode > 0o660 {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("Docker socket too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 660 /var/run/docker.sock".into(),
            });
        } else {
            passed.push("Docker socket permissions OK".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_services() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Services";

    // Check for commonly exploited services exposed on all interfaces
    if let Ok(out) = Command::new("ss").args(["-tlnp"]).output() {
        let lines = String::from_utf8_lossy(&out.stdout);

        // Check if any service binds to 0.0.0.0 on unusual ports
        let listening_all: Vec<String> = lines
            .lines()
            .filter(|l| l.contains("0.0.0.0:") || l.contains(":::"))
            .filter(|l| {
                // Exclude standard ports
                !l.contains(":22 ") && !l.contains(":80 ") && !l.contains(":443 ")
            })
            .map(|l| l.to_string())
            .collect();

        if listening_all.len() > 5 {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} services exposed on all interfaces", listening_all.len()),
                fix: "Review services binding to 0.0.0.0 — bind to 127.0.0.1 where possible".into(),
            });
        } else {
            passed.push("Service exposure looks reasonable".into());
        }
    }

    // Check fail2ban or equivalent
    let has_iw = Command::new("systemctl")
        .args(["is-active", "innerwarden-agent"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    if has_iw {
        passed.push("Inner Warden agent is active".into());
    } else {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Inner Warden agent is not running".into(),
            fix: "Run: sudo systemctl start innerwarden-agent".into(),
        });
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_crontabs() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Crontabs";

    // Patterns that indicate suspicious crontab entries.
    let suspicious = |line: &str| -> Option<&'static str> {
        let lower = line.to_lowercase();
        // Skip comments and empty lines.
        let trimmed = lower.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }
        // Download + execute: curl/wget piped to sh/bash
        if (lower.contains("curl") || lower.contains("wget"))
            && (lower.contains("| sh")
                || lower.contains("|sh")
                || lower.contains("| bash")
                || lower.contains("|bash"))
        {
            return Some("download and execute (curl/wget piped to sh/bash)");
        }
        // Reverse shell indicators
        if lower.contains("/dev/tcp") || lower.contains("nc -e") || lower.contains("ncat -e") {
            return Some("possible reverse shell (nc / /dev/tcp)");
        }
        // Base64 decode
        if lower.contains("base64 -d") || lower.contains("base64 --decode") {
            return Some("base64 decode (potential obfuscation)");
        }
        // Write to /tmp
        if lower.contains("> /tmp/") || lower.contains(">/tmp/") {
            return Some("writes to /tmp (common staging directory)");
        }
        None
    };

    let mut scanned: usize = 0;

    // Helper: scan all files in a directory.
    let mut scan_dir = |dir: &str| {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(contents) = fs::read_to_string(&path) {
                    scanned += 1;
                    for (lineno, line) in contents.lines().enumerate() {
                        if let Some(reason) = suspicious(line) {
                            findings.push(Finding {
                                category: cat,
                                severity: Severity::Medium,
                                title: format!("{}:{} — {}", path.display(), lineno + 1, reason),
                                fix: format!(
                                    "Review the entry in {} and remove it if unexpected",
                                    path.display()
                                ),
                            });
                        }
                    }
                }
            }
        }
    };

    // User crontabs
    scan_dir("/var/spool/cron/crontabs");
    // System cron fragments
    scan_dir("/etc/cron.d");

    // /etc/crontab (single file)
    if let Ok(contents) = fs::read_to_string("/etc/crontab") {
        scanned += 1;
        for (lineno, line) in contents.lines().enumerate() {
            if let Some(reason) = suspicious(line) {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Medium,
                    title: format!("/etc/crontab:{} — {}", lineno + 1, reason),
                    fix: "Review the entry in /etc/crontab and remove it if unexpected".into(),
                });
            }
        }
    }

    if findings.is_empty() {
        if scanned > 0 {
            passed.push(format!(
                "Scanned {scanned} crontab file(s) — no suspicious entries"
            ));
        } else {
            passed.push("No crontab files found to scan".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

fn check_kernel_modules() -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Kernel Modules";

    // Known rootkit modules — always flag as Critical.
    let rootkit_modules: &[&str] = &[
        "diamorphine",
        "reptile",
        "jynx",
        "adore",
        "knark",
        "suterusu",
    ];

    // Known-good modules (common, legitimate kernel modules).
    let known_good: &[&str] = &[
        // Filesystems
        "ext4",
        "xfs",
        "btrfs",
        "vfat",
        "fat",
        "nfs",
        "nfsd",
        "cifs",
        "fuse",
        "overlay",
        "isofs",
        "squashfs",
        "udf",
        "ntfs",
        "ntfs3",
        // Networking
        "ip_tables",
        "ip6_tables",
        "iptable_filter",
        "iptable_nat",
        "iptable_mangle",
        "nf_conntrack",
        "nf_nat",
        "nf_tables",
        "nft_chain_nat",
        "nft_compat",
        "nf_conntrack_ftp",
        "nf_nat_ftp",
        "nf_conntrack_netlink",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_reject_ipv4",
        "nf_reject_ipv6",
        "nft_reject",
        "br_netfilter",
        "bridge",
        "stp",
        "llc",
        "veth",
        "tun",
        "tap",
        "bonding",
        "8021q",
        "vxlan",
        "geneve",
        "wireguard",
        "openvswitch",
        "tcp_bbr",
        "tcp_cubic",
        // Block / storage
        "dm_mod",
        "dm_crypt",
        "dm_mirror",
        "dm_snapshot",
        "dm_thin_pool",
        "dm_zero",
        "dm_log",
        "dm_region_hash",
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
        "sg",
        "ahci",
        "libahci",
        "libata",
        "virtio_blk",
        "virtio_scsi",
        "nvme",
        "nvme_core",
        // Virtio / KVM / hypervisor
        "virtio",
        "virtio_pci",
        "virtio_net",
        "virtio_ring",
        "virtio_balloon",
        "virtio_console",
        "virtio_gpu",
        "virtio_mmio",
        "virtio_rng",
        "kvm",
        "kvm_intel",
        "kvm_amd",
        "vhost",
        "vhost_net",
        "vhost_vsock",
        "vmw_balloon",
        "vmw_vmci",
        "vmw_vsock_vmci_transport",
        "vmxnet3",
        "hv_vmbus",
        "hv_storvsc",
        "hv_netvsc",
        "hv_utils",
        "hv_balloon",
        "xen_blkfront",
        "xen_netfront",
        "xen_pcifront",
        // Input / HID
        "hid",
        "hid_generic",
        "usbhid",
        "evdev",
        "input_leds",
        "psmouse",
        "i2c_hid",
        "i2c_core",
        // USB
        "usbcore",
        "usb_common",
        "ehci_hcd",
        "ehci_pci",
        "ohci_hcd",
        "ohci_pci",
        "uhci_hcd",
        "xhci_hcd",
        "xhci_pci",
        // Graphics / DRM
        "drm",
        "drm_kms_helper",
        "fb_sys_fops",
        "syscopyarea",
        "sysfillrect",
        "sysimgblt",
        "i915",
        "amdgpu",
        "nouveau",
        "bochs",
        "cirrus",
        "qxl",
        // Sound
        "snd",
        "snd_pcm",
        "snd_timer",
        "snd_hda_intel",
        "snd_hda_core",
        "snd_hda_codec",
        "snd_hda_codec_generic",
        "snd_hda_codec_hdmi",
        "snd_hda_codec_realtek",
        "snd_hwdep",
        "soundcore",
        // Crypto
        "aes_x86_64",
        "aesni_intel",
        "aes_generic",
        "sha256_generic",
        "sha256_ssse3",
        "sha512_generic",
        "sha512_ssse3",
        "sha1_generic",
        "sha1_ssse3",
        "crc32c_intel",
        "crc32_pclmul",
        "crct10dif_pclmul",
        "ghash_clmulni_intel",
        "poly1305_x86_64",
        "chacha20_x86_64",
        "cryptd",
        "crypto_simd",
        "authenc",
        "echainiv",
        // ACPI / power / platform
        "acpi_cpufreq",
        "battery",
        "button",
        "thermal",
        "processor",
        "intel_rapl_msr",
        "intel_rapl_common",
        "intel_pstate",
        // Misc common
        "joydev",
        "serio_raw",
        "pcspkr",
        "lp",
        "ppdev",
        "parport",
        "parport_pc",
        "nls_utf8",
        "nls_iso8859_1",
        "nls_cp437",
        "configfs",
        "efivarfs",
        "autofs4",
        "sunrpc",
        "rpcsec_gss_krb5",
        "cuse",
        "vboxguest",
        "vboxsf",
        "vboxvideo",
        "ip_vs",
        "ip_vs_rr",
        "ip_vs_wrr",
        "ip_vs_sh",
        "xt_conntrack",
        "xt_MASQUERADE",
        "xt_addrtype",
        "xt_comment",
        "xt_mark",
        "xt_nat",
        "xt_tcpudp",
        "xt_multiport",
        "xt_state",
        "xt_LOG",
        "xt_limit",
        "xt_recent",
        "xt_set",
        "ip_set",
        "ip_set_hash_ip",
        "ip_set_hash_net",
        "cls_cgroup",
        "sch_fq_codel",
        "sch_htb",
        "rng_core",
        "tpm",
        "tpm_crb",
        "tpm_tis",
        "tpm_tis_core",
        "lz4",
        "lz4_compress",
        "lzo",
        "lzo_compress",
        "lzo_decompress",
        "zstd_compress",
        "zstd_decompress",
        "deflate",
        "zlib_deflate",
        "zlib_inflate",
        "af_packet",
        "unix",
        "ipv6",
        "mousedev",
        "mac_hid",
        "msr",
        "cpuid",
        "iscsi_tcp",
        "libiscsi",
        "libiscsi_tcp",
        "scsi_transport_iscsi",
        "ceph",
        "libceph",
        "rbd",
        // Docker / containerd common
        "xt_connmark",
        "xt_REDIRECT",
        "nf_log_syslog",
        "nf_log_ipv4",
    ];

    match Command::new("lsmod").output() {
        Ok(out) => {
            let output = String::from_utf8_lossy(&out.stdout);
            let mut unknown_modules: Vec<String> = Vec::new();

            for line in output.lines().skip(1) {
                // lsmod format: module_name  size  used_by
                let module = match line.split_whitespace().next() {
                    Some(m) => m,
                    None => continue,
                };

                // Check rootkit modules first (Critical).
                if rootkit_modules
                    .iter()
                    .any(|r| module.eq_ignore_ascii_case(r))
                {
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::Critical,
                        title: format!("Known rootkit module loaded: {module}"),
                        fix: format!(
                            "Investigate immediately — remove with: sudo rmmod {module} && audit the system"
                        ),
                    });
                    continue;
                }

                // Flag unknown modules as Low.
                if !known_good.contains(&module) {
                    unknown_modules.push(module.to_string());
                }
            }

            if !unknown_modules.is_empty() {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Low,
                    title: format!("{} unusual kernel module(s) loaded", unknown_modules.len()),
                    fix: format!(
                        "Review if expected: {}",
                        unknown_modules
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }

            if findings.is_empty() {
                passed.push("All loaded kernel modules are known-good".into());
            }
        }
        Err(_) => {
            passed.push("lsmod not available (skipped)".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Main command
// ---------------------------------------------------------------------------

pub fn cmd_harden(verbose: bool) -> Result<()> {
    println!();
    println!("  \x1b[1m\x1b[36mInner Warden — Security Hardening Advisor\x1b[0m");
    println!("  \x1b[90mScanning system configuration...\x1b[0m");
    println!();

    let checks = vec![
        check_ssh(),
        check_firewall(),
        check_kernel(),
        check_permissions(),
        check_updates(),
        check_docker(),
        check_services(),
        check_crontabs(),
        check_kernel_modules(),
    ];

    let mut total_findings = 0;
    let mut total_passed = 0;
    let mut score: u32 = 100;

    for result in &checks {
        let n_findings = result.findings.len();
        let n_passed = result.passed.len();
        total_findings += n_findings;
        total_passed += n_passed;

        // Category header
        let status = if n_findings == 0 {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[33m!\x1b[0m"
        };
        println!("  {} \x1b[1m{}\x1b[0m", status, result.category);

        // Passed items (verbose only)
        if verbose {
            for p in &result.passed {
                println!("    \x1b[32m✓\x1b[0m {}", p);
            }
        }

        // Findings
        for f in &result.findings {
            score = score.saturating_sub(f.severity.score_penalty());
            println!(
                "    {}  {} \x1b[90m[{}]\x1b[0m",
                f.severity.icon(),
                f.title,
                f.severity.label()
            );
            println!("       \x1b[90m→\x1b[0m \x1b[36m{}\x1b[0m", f.fix);
        }

        if n_findings == 0 && !verbose {
            println!("    \x1b[32m{} check(s) passed\x1b[0m", n_passed);
        }

        println!();
    }

    // Score bar
    let bar_width = 30;
    let filled = (score as usize * bar_width) / 100;
    let bar_color = if score >= 80 {
        "\x1b[32m"
    } else if score >= 50 {
        "\x1b[33m"
    } else {
        "\x1b[31m"
    };
    let bar = format!(
        "{}{}{}",
        bar_color,
        "█".repeat(filled),
        "\x1b[90m░\x1b[0m".repeat(bar_width - filled)
    );

    let grade = match score {
        90..=100 => "\x1b[32mExcellent\x1b[0m",
        75..=89 => "\x1b[32mGood\x1b[0m",
        50..=74 => "\x1b[33mFair\x1b[0m",
        25..=49 => "\x1b[91mPoor\x1b[0m",
        _ => "\x1b[31mCritical\x1b[0m",
    };

    println!(
        "  \x1b[1mScore:\x1b[0m {}{}\x1b[0m/100 — {}",
        bar_color, score, grade
    );
    println!("  {}", bar);
    println!();
    println!(
        "  \x1b[90m{} passed · {} finding(s)\x1b[0m",
        total_passed, total_findings
    );

    if total_findings == 0 {
        println!("\n  \x1b[32m\x1b[1mYour system is well hardened. Nice work!\x1b[0m\n");
    } else {
        println!("\n  \x1b[90mRun with --verbose to see all passed checks.\x1b[0m");
        println!(
            "  \x1b[90mInner Warden only advises — no changes are applied automatically.\x1b[0m\n"
        );
    }

    Ok(())
}
