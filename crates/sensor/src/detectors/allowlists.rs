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
}
