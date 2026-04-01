//! Centralized allowlists for false positive suppression.
//!
//! Inspired by Falco's production-hardened rules (falcosecurity/rules).
//! Instead of each detector maintaining its own ad-hoc list, all detectors
//! reference these shared lists.
//!
//! Categories:
//!   - INNERWARDEN_SELF: our own processes (uid 998, tokio-rt-worker, etc.)
//!   - SYSTEM_DAEMONS: root-level system services
//!   - PACKAGE_MANAGERS: apt, dpkg, snap, etc.
//!   - LOGIN_BINARIES: sshd, login, su, sudo, etc.
//!   - DISCOVERY_ALLOWED: processes that legitimately run recon commands
//!   - SENSITIVE_FILE_READERS: processes allowed to read /etc/shadow, etc.
//!   - TRUNCATE_ALLOWED: processes that legitimately truncate files

/// InnerWarden's own service user ID.
pub const INNERWARDEN_UID: u64 = 998;

/// Returns true if the event is from InnerWarden's own processes.
/// Checks uid, comm prefix, and tokio runtime threads.
pub fn is_innerwarden_process(uid: u64, comm: &str) -> bool {
    // Strip kernel task parentheses: (innerwarden) -> innerwarden
    let comm = comm.trim_matches(|c: char| c == '(' || c == ')');
    uid == INNERWARDEN_UID
        || comm.starts_with("innerwarden")
        || comm == "tokio-rt-worker"
        || comm.contains("warden")
}

// ---------------------------------------------------------------------------
// System daemons (uid=0, legitimate system operations)
// ---------------------------------------------------------------------------

/// Root daemons that legitimately perform file operations, network connections,
/// and process management. Filtering these prevents the most common FPs.
pub const SYSTEM_DAEMONS: &[&str] = &[
    // Init and service management
    "systemd",
    "systemd-logind",
    "systemd-journal",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-network",
    "systemd-udevd",
    "systemd-tmpfile",
    "systemd-machine",
    "systemd-sysuser",
    // SSH
    "sshd",
    "sshd-session",
    "ssh-agent",
    "ssh-keygen",
    // Cron
    "cron",
    "crond",
    "atd",
    "anacron",
    // Auth and policy
    "polkitd",
    "pkexec",
    "dbus-daemon",
    "dbus-daemon-lau",
    // Log management
    "logrotate",
    "rsyslogd",
    "syslog-ng",
    "journalctl",
    // Network
    "irqbalance",
    "ufw",
    "iptables",
    "nftables",
    "fail2ban-serve",
    "fail2ban-client",
    "dhclient",
    "networkd-dispat",
    "NetworkManager",
    // System maintenance
    "unattended-upgr",
    "update-notifier",
    "apt-check",
    "landscape-sysi",
    "50-landscape-sy",
    "update-motd",
    "fwupdmgr",
    "snapd",
    "chronyd",
    "ntpd",
    "multipathd",
    "accounts-daemon",
    "udisksd",
    "thermald",
];

// ---------------------------------------------------------------------------
// Package managers (may read sensitive files, run discovery commands)
// ---------------------------------------------------------------------------

/// Package management binaries — these legitimately read config files,
/// run post-install scripts, and execute system commands.
pub const PACKAGE_MANAGERS: &[&str] = &[
    // Debian/Ubuntu
    "dpkg",
    "dpkg-preconfigu",
    "dpkg-reconfigur",
    "dpkg-divert",
    "apt",
    "apt-get",
    "apt-cache",
    "apt-key",
    "apt-listchanges",
    "apt-auto-remova",
    "apt-add-reposit",
    "apt.systemd.dai",
    "aptitude",
    "unattended-upgr",
    "needrestart",
    // RPM
    "rpm",
    "yum",
    "dnf",
    "dnf-automatic",
    // Snap
    "snap",
    "snapd",
    // Python/Node/Ruby
    "pip",
    "pip3",
    "npm",
    "gem",
    "conda",
    "uv",
    // Rust/Go
    "cargo",
    "rustup",
    "go",
];

// ---------------------------------------------------------------------------
// Login and auth binaries (legitimately change uid, read shadow)
// ---------------------------------------------------------------------------

/// Processes that legitimately perform privilege escalation or read auth files.
pub const LOGIN_BINARIES: &[&str] = &[
    "login",
    "su",
    "sudo",
    "suexec",
    "sshd",
    "sshd-session",
    "cron",
    "crond",
    "atd",
    "polkitd",
    "pkexec",
    "newgrp",
    "sg",
    "dbus-daemon",
    "gdm",
    "lightdm",
    "sddm",
    "systemd",
    "systemd-logind",
    "run-parts",
    "runuser",
];

/// Password/shadow management binaries.
pub const PASSWD_BINARIES: &[&str] = &[
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "usermod",
    "useradd",
    "userdel",
    "groupadd",
    "groupdel",
    "groupmod",
    "adduser",
    "addgroup",
    "deluser",
    "delgroup",
    "shadowconfig",
    "grpck",
    "pwck",
    "vipw",
    "vigr",
    "newusers",
    "chpasswd",
    "unix_chkpwd",
];

// ---------------------------------------------------------------------------
// Discovery commands — processes that legitimately run recon-like commands
// ---------------------------------------------------------------------------

/// Processes that legitimately execute discovery commands (ps, id, uname, etc.)
/// and should not trigger discovery burst alerts.
pub const DISCOVERY_ALLOWED: &[&str] = &[
    // Security / monitoring tools
    "innerwarden",
    "osqueryd",
    "ossec-syscheckd",
    "telegraf",
    "prometheus",
    "node_exporter",
    "zabbix",
    "nagios",
    "collectd",
    "datadog",
    "newrelic",
    "aide",
    "rkhunter",
    "logcheck",
    // Config management
    "ansible",
    "puppet",
    "chef",
    "chef-client",
    "salt",
    "salt-call",
    "salt-minion",
    // CI/CD and dev tools
    "cargo",
    "rustc",
    "git",
    "make",
    "cmake",
    "gcc",
    "go",
    "node",
    // System tools that run discovery commands
    "journalctl",
    "systemctl",
    "bpftool",
    "bpf_inspect",
    "landscape-sysi",
    "update-motd",
    // Cloud-init (Oracle Cloud, AWS, GCP, Azure — runs discovery on boot/reboot)
    "cloud-init",
    "cloud-init-gene",
    "ds-identify",
    // Ubuntu MOTD scripts (run uname, id, etc. on every SSH login)
    "00-header",
    "10-help-text",
    "50-motd-news",
    "60-unminimize",
    "91-release-upgr",
    "release-upgrade",
    "run-parts",
    // Package managers (post-install scripts run discovery)
    "apt-check",
    "unattended-upgr",
    "dpkg",
    "dpkg-preconfigu",
    "needrestart",
    "snap",
    "snapd",
];

// ---------------------------------------------------------------------------
// Sensitive file readers — processes allowed to read /etc/shadow, etc.
// ---------------------------------------------------------------------------

/// Processes that legitimately read sensitive files (/etc/shadow, /etc/sudoers,
/// /etc/pam.conf, SSH keys, etc.) and should not trigger Sigma rules or alerts.
pub const SENSITIVE_FILE_READERS: &[&str] = &[
    // Auth
    "sshd",
    "sshd-session",
    "login",
    "su",
    "sudo",
    "polkitd",
    "systemd",
    "systemd-logind",
    "cron",
    "crond",
    "atd",
    // Password management
    "passwd",
    "chage",
    "chsh",
    "chfn",
    "adduser",
    "useradd",
    "usermod",
    "newusers",
    "chpasswd",
    "unix_chkpwd",
    // Security tools
    "innerwarden",
    "osqueryd",
    "ossec-syscheckd",
    "rkhunter",
    "aide",
    "logcheck",
    // System tools
    "iptables",
    "lsb_release",
    "check-new-relea",
    "dumpe2fs",
    "accounts-daemon",
    "pam-auth-update",
    "pam-config",
    "cockpit-session",
    // Package managers
    "dpkg",
    "apt",
    "apt-get",
    "snap",
    "needrestart",
];

// ---------------------------------------------------------------------------
// Truncate/timestomp allowlist — processes that legitimately truncate files
// ---------------------------------------------------------------------------

/// System processes (uid=0) that legitimately call do_truncate or vfs_utimes.
/// These are filtered from eBPF truncate/timestomp events.
pub const TRUNCATE_ALLOWED: &[&str] = &[
    "systemd-journal",
    "logrotate",
    "rsyslogd",
    "syslog-ng",
    "systemd",
    "systemd-tmpfile",
    "sshd",
    "sshd-session",
    "irqbalance",
    "ufw",
    "fail2ban-serve",
    "fail2ban-client",
    "50-landscape-sy",
    "landscape-sysi",
];

// ---------------------------------------------------------------------------
// Privilege escalation allowlist
// ---------------------------------------------------------------------------

/// Processes that legitimately trigger commit_creds (uid changes).
/// Combined from Falco's login_binaries + passwd_binaries + our additions.
pub const PRIVESC_ALLOWED: &[&str] = &[
    // Standard login/auth
    "sudo",
    "su",
    "login",
    "sshd",
    "sshd-session",
    "cron",
    "crond",
    "atd",
    "polkitd",
    "pkexec",
    "systemd",
    "systemd-logind",
    "dbus-daemon",
    "dbus-daemon-lau",
    "gdm",
    "lightdm",
    "sddm",
    "newgrp",
    // Password management
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "usermod",
    "useradd",
    "groupadd",
    // Package managers
    "install",
    "dpkg",
    "apt",
    "apt-get",
    "apt-check",
    "snap",
    "snapd",
    "unattended-upg",
    "update-notifier",
    // System tools with SUID
    "at",
    "find",
    "mandb",
    "man",
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
    "fwupdmgr",
    // InnerWarden
    "innerwarden",
    "innerwarden-ag",
    "innerwarden-se",
    "innerwarden-ct",
];

// ---------------------------------------------------------------------------
// C2 callback allowlist — processes with legitimate outbound connections
// ---------------------------------------------------------------------------

/// Processes that make regular outbound HTTP/HTTPS connections and should
/// not be flagged as C2 beaconing.
pub const C2_OUTBOUND_ALLOWED: &[&str] = &[
    // InnerWarden (GeoIP, AbuseIPDB, CrowdSec, Cloudflare lookups)
    "innerwarden",
    "tokio-rt-worker",
    // System updates
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "unattended-upgr",
    "dpkg",
    // Cloud agents
    "oracle-cloud-ag",
    "google_guest_ag",
    "waagent",
    "amazon-ssm-agen",
    // Monitoring
    "telegraf",
    "prometheus",
    "datadog-agent",
    "newrelic-infra",
    "zabbix_agentd",
    "node_exporter",
    "gomon",
    "updater",
    // Security tools
    "osqueryd",
    "crowdsec",
    "fail2ban-serve",
    // Web servers (make outbound requests for plugins, APIs)
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "php",
    "ruby",
    "puma",
    "unicorn",
    "gunicorn",
    "uwsgi",
    // Databases (replication, cluster comms)
    "mysqld",
    "postgres",
    "mongod",
    "redis-server",
    // Node.js / runtime workers
    "libuv-worker",
    "node",
    // Container runtime
    "dockerd",
    "containerd",
    "containerd-shim",
    "runc",
];

// ---------------------------------------------------------------------------
// Helper: check if a process is in a given allowlist
// ---------------------------------------------------------------------------

/// Check if comm matches any entry in the allowlist using starts_with.
/// Handles kernel comm truncation (16 char limit).
pub fn comm_in_allowlist(comm: &str, allowlist: &[&str]) -> bool {
    let comm_base = comm.split('/').next_back().unwrap_or(comm);
    // Strip kernel task parentheses: (install) -> install
    let comm_base = comm_base.trim_matches(|c: char| c == '(' || c == ')');
    allowlist.iter().any(|p| comm_base.starts_with(p))
}

// ---------------------------------------------------------------------------
// Dynamic allowlist — loaded from /etc/innerwarden/allowlist.toml at runtime.
// No rebuild needed. Sensor re-reads on reload_if_changed().
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Runtime-configurable allowlist loaded from TOML file.
/// Supplements the static const lists above — if a process/IP is in either
/// the static OR dynamic list, it's considered allowed.
pub struct DynamicAllowlist {
    /// Processes to skip (starts_with matching, same as static lists)
    pub processes: HashSet<String>,
    /// IPs or CIDRs to treat as trusted
    pub ips: HashSet<String>,
    /// Destination ports to ignore in outbound anomaly
    pub ignored_ports: HashSet<u16>,
    /// Per-detector process suppressions: detector_name → set of comms
    pub per_detector: std::collections::HashMap<String, HashSet<String>>,
    /// IPs that are technically private but should be treated as external
    /// for testing purposes (e.g., Mac on local network running attacks).
    pub test_external_ips: HashSet<String>,
    /// Path to the TOML file
    path: PathBuf,
    /// Last modification time (for reload detection)
    last_modified: Option<SystemTime>,
}

impl DynamicAllowlist {
    /// Load from file. Returns empty allowlist if file doesn't exist (not an error).
    pub fn load(path: &Path) -> Self {
        let mut al = Self {
            processes: HashSet::new(),
            ips: HashSet::new(),
            ignored_ports: HashSet::new(),
            per_detector: std::collections::HashMap::new(),
            test_external_ips: HashSet::new(),
            path: path.to_path_buf(),
            last_modified: None,
        };
        al.reload();
        al
    }

    /// Reload from disk if the file has changed.
    /// Returns true if the file was reloaded.
    pub fn reload_if_changed(&mut self) -> bool {
        let current_mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());

        if current_mtime != self.last_modified {
            self.reload();
            true
        } else {
            false
        }
    }

    fn reload(&mut self) {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return, // File doesn't exist yet — that's fine
        };

        // Parse TOML manually (sensor doesn't depend on toml crate for this)
        // Simple key = "value" format per section
        self.processes.clear();
        self.ips.clear();
        self.ignored_ports.clear();
        self.per_detector.clear();
        self.test_external_ips.clear();

        let mut section = String::new();
        let mut detector_section: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Section header
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
                detector_section = if section.starts_with("detectors.") {
                    Some(section.strip_prefix("detectors.").unwrap().to_string())
                } else {
                    None
                };
                continue;
            }

            // Key = "value" or key = value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().trim_matches('"');
                let value = value.trim().trim_matches('"');

                match section.as_str() {
                    "processes" => {
                        self.processes.insert(key.to_string());
                    }
                    "ips" => {
                        self.ips.insert(key.to_string());
                    }
                    "test_external_ips" => {
                        self.test_external_ips.insert(key.to_string());
                    }
                    "ports" => {
                        // Parse comma-separated port list: ignored = 0, 9, 67
                        for part in value.split(',') {
                            if let Ok(port) = part.trim().parse::<u16>() {
                                self.ignored_ports.insert(port);
                            }
                        }
                    }
                    _ => {
                        if let Some(ref det) = detector_section {
                            let entries = self.per_detector.entry(det.clone()).or_default();
                            entries.insert(key.to_string());
                        }
                    }
                }
            }
        }

        self.last_modified = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());

        tracing::info!(
            processes = self.processes.len(),
            ips = self.ips.len(),
            ports = self.ignored_ports.len(),
            test_external = self.test_external_ips.len(),
            detectors = self.per_detector.len(),
            path = %self.path.display(),
            "Dynamic allowlist loaded"
        );
    }

    /// Check if a process comm is dynamically allowlisted (global or per-detector).
    pub fn is_process_allowed(&self, comm: &str, detector: Option<&str>) -> bool {
        let comm_base = comm.split('/').next_back().unwrap_or(comm);
        let comm_base = comm_base.trim_matches(|c: char| c == '(' || c == ')');

        // Global process allowlist
        if self
            .processes
            .iter()
            .any(|p| comm_base.starts_with(p.as_str()))
        {
            return true;
        }

        // Per-detector allowlist
        if let Some(det) = detector {
            if let Some(entries) = self.per_detector.get(det) {
                if entries.iter().any(|p| comm_base.starts_with(p.as_str())) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if an IP is dynamically allowlisted.
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.ips.contains(ip) {
            return true;
        }
        // CIDR check
        self.ips.iter().any(|entry| {
            if entry.contains('/') {
                crate::detectors::allowlists::cidr_matches(ip, entry)
            } else {
                false
            }
        })
    }

    /// Check if a destination port should be ignored.
    pub fn is_port_ignored(&self, port: u16) -> bool {
        self.ignored_ports.contains(&port)
    }

    /// Check if an IP should be treated as external even though it's technically
    /// private. Used for testing from local networks (e.g., Mac attacking VM).
    pub fn is_test_external(&self, ip: &str) -> bool {
        self.test_external_ips.contains(ip)
    }
}

/// CIDR match helper (reusable).
pub fn cidr_matches(ip_str: &str, cidr: &str) -> bool {
    let Some((base_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(base) = base_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, base) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(base4)) if prefix_len <= 32 => {
            let shift = 32u32.saturating_sub(prefix_len);
            let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
            (u32::from(ip4) & mask) == (u32::from(base4) & mask)
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(base6)) if prefix_len <= 128 => {
            let shift = 128u32.saturating_sub(prefix_len);
            let mask = if shift >= 128 { 0u128 } else { !0u128 << shift };
            (u128::from(ip6) & mask) == (u128::from(base6) & mask)
        }
        _ => false,
    }
}

/// Check if an IP is internal, respecting test_external_ips overrides.
/// Returns false (= treat as external) if the IP is in the test_external list,
/// even if it's technically a private IP.
pub fn is_internal_ip_with_overrides(ip: &str, dynamic: &DynamicAllowlist) -> bool {
    if dynamic.is_test_external(ip) {
        return false; // Treat as external for testing
    }
    super::is_internal_ip(ip)
}

/// Combined check: static const list OR dynamic allowlist.
pub fn comm_in_any_allowlist(
    comm: &str,
    static_list: &[&str],
    dynamic: &DynamicAllowlist,
    detector: Option<&str>,
) -> bool {
    comm_in_allowlist(comm, static_list) || dynamic.is_process_allowed(comm, detector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn innerwarden_detection() {
        assert!(is_innerwarden_process(998, "anything")); // uid match
        assert!(is_innerwarden_process(0, "innerwarden-sensor")); // comm prefix
        assert!(is_innerwarden_process(0, "tokio-rt-worker")); // tokio runtime
        assert!(is_innerwarden_process(998, "en-agent")); // uid 998 = innerwarden
        assert!(!is_innerwarden_process(0, "en-agent")); // not uid 998, no warden in comm
        assert!(!is_innerwarden_process(1000, "bash"));
    }

    #[test]
    fn comm_matching() {
        assert!(comm_in_allowlist("systemd-journal", SYSTEM_DAEMONS));
        assert!(comm_in_allowlist("dpkg-preconfigu", PACKAGE_MANAGERS));
        assert!(comm_in_allowlist("00-header", DISCOVERY_ALLOWED));
        assert!(!comm_in_allowlist("evil-script", SYSTEM_DAEMONS));
    }

    #[test]
    fn parenthesized_comm_matching() {
        // Kernel task format: (install) instead of install
        assert!(comm_in_allowlist("(install)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(find)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(mandb)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(fwupdmgr)", PRIVESC_ALLOWED));
        assert!(!comm_in_allowlist("(evil-exploit)", PRIVESC_ALLOWED));
        // is_innerwarden_process with parentheses
        assert!(is_innerwarden_process(0, "(innerwarden-sensor)"));
        assert!(is_innerwarden_process(0, "(tokio-rt-worker)"));
        assert!(!is_innerwarden_process(0, "(bash)"));
    }

    #[test]
    fn no_duplicates() {
        fn check(name: &str, list: &[&str]) {
            let mut seen = std::collections::HashSet::new();
            for entry in list {
                assert!(seen.insert(entry), "Duplicate in {}: {}", name, entry);
            }
        }
        check("SYSTEM_DAEMONS", SYSTEM_DAEMONS);
        check("PACKAGE_MANAGERS", PACKAGE_MANAGERS);
        check("LOGIN_BINARIES", LOGIN_BINARIES);
        check("DISCOVERY_ALLOWED", DISCOVERY_ALLOWED);
        check("PRIVESC_ALLOWED", PRIVESC_ALLOWED);
        check("C2_OUTBOUND_ALLOWED", C2_OUTBOUND_ALLOWED);
    }

    #[test]
    fn dynamic_allowlist_empty_file() {
        let al = DynamicAllowlist::load(Path::new("/nonexistent/allowlist.toml"));
        assert!(al.processes.is_empty());
        assert!(al.ips.is_empty());
        assert!(!al.is_process_allowed("evil", None));
    }

    #[test]
    fn dynamic_allowlist_parse() {
        let dir = std::env::temp_dir().join("iw_test_allowlist");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
# Dynamic allowlist for testing
[processes]
"gomon" = "Go monitor"
"updater" = "System updater"

[ips]
"172.18.0.0/16" = "Docker network"
"10.0.0.5" = "Build server"

[ports]
ignored = 0, 9, 67

[detectors.outbound_anomaly]
"my_custom_app" = "Internal tool"
"#,
        )
        .unwrap();

        let al = DynamicAllowlist::load(&path);
        assert!(al.is_process_allowed("gomon", None));
        assert!(al.is_process_allowed("updater", None));
        assert!(!al.is_process_allowed("evil", None));
        assert!(al.is_process_allowed("my_custom_app", Some("outbound_anomaly")));
        assert!(!al.is_process_allowed("my_custom_app", Some("ssh_bruteforce")));
        assert!(al.is_ip_allowed("172.18.0.6"));
        assert!(al.is_ip_allowed("10.0.0.5"));
        assert!(!al.is_ip_allowed("1.2.3.4"));
        assert!(al.is_port_ignored(9));
        assert!(!al.is_port_ignored(80));

        // Cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn cidr_matches_works() {
        assert!(cidr_matches("172.18.0.6", "172.18.0.0/16"));
        assert!(!cidr_matches("172.19.0.6", "172.18.0.0/16"));
        assert!(cidr_matches("10.0.0.1", "10.0.0.0/24"));
        assert!(!cidr_matches("10.0.1.1", "10.0.0.0/24"));
    }

    #[test]
    fn comm_in_any_works() {
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        // Static only
        assert!(comm_in_any_allowlist(
            "systemd-journal",
            SYSTEM_DAEMONS,
            &al,
            None
        ));
        // Neither
        assert!(!comm_in_any_allowlist(
            "evil-script",
            SYSTEM_DAEMONS,
            &al,
            None
        ));
    }
}
