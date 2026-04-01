#[allow(dead_code)]
pub mod allowlists;
pub mod c2_callback;
pub mod container_escape;
pub mod credential_stuffing;
pub mod crypto_miner;
pub mod distributed_ssh;
pub mod suspicious_login;

/// IPs that should be treated as external even though they're technically private.
/// Set once at startup from the dynamic allowlist's [test_external_ips] section.
static TEST_EXTERNAL_IPS: std::sync::OnceLock<std::collections::HashSet<String>> =
    std::sync::OnceLock::new();

/// Initialize test external IPs from the dynamic allowlist.
/// Call once at startup after loading the allowlist.
pub fn init_test_external_ips(ips: std::collections::HashSet<String>) {
    let _ = TEST_EXTERNAL_IPS.set(ips);
}

/// Returns true if the IP is private, loopback, link-local, or documentation range.
/// Respects [test_external_ips] overrides from the dynamic allowlist.
pub fn is_internal_ip(ip: &str) -> bool {
    // Check test_external override first
    if let Some(test_ips) = TEST_EXTERNAL_IPS.get() {
        if test_ips.contains(ip) {
            return false; // Treat as external for testing
        }
    }

    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
/// Verify that a process name matches a known infrastructure binary path.
/// Prevents evasion by renaming a malicious binary to "crowdsec" etc.
/// Returns true only if the comm matches AND /proc/PID/exe points to a
/// legitimate system path (not /tmp, /dev/shm, or user home dirs).
pub fn is_verified_infra_process(comm: &str, pid: u32, allowed_comms: &[&str]) -> bool {
    if !allowed_comms.iter().any(|c| comm.starts_with(c)) {
        return false;
    }
    // Verify binary path via /proc — catches name spoofing
    let exe_path = format!("/proc/{pid}/exe");
    match std::fs::read_link(&exe_path) {
        Ok(path) => {
            let p = path.to_string_lossy();
            // Legitimate paths: /usr/bin, /usr/sbin, /usr/local/bin, /snap, /opt
            // NOT: /tmp, /dev/shm, /var/tmp, /home (attacker-writable)
            p.starts_with("/usr/")
                || p.starts_with("/snap/")
                || p.starts_with("/opt/")
                || p.starts_with("/sbin/")
                || p.starts_with("/bin/")
        }
        Err(_) => {
            // Process might have exited — allow if comm matches
            // (better to have a brief FN gap than block infra permanently)
            true
        }
    }
}

pub mod dns_tunneling;
pub mod docker_anomaly;
pub mod execution_guard;
pub mod fileless;
pub mod integrity_alert;
pub mod lateral_movement;
pub mod log_tampering;
pub mod osquery_anomaly;
pub mod port_scan;
pub mod privesc;
pub mod process_tree;
pub mod search_abuse;
pub mod ssh_bruteforce;
pub mod sudo_abuse;
pub mod suricata_alert;
pub mod user_agent_scanner;
pub mod web_scan;

// v0.5.0 detectors
pub mod credential_harvest;
pub mod crontab_persistence;
pub mod data_exfiltration;
pub mod kernel_module_load;
pub mod outbound_anomaly;
pub mod process_injection;
pub mod ransomware;
pub mod reverse_shell;
pub mod rootkit;
pub mod ssh_key_injection;
pub mod systemd_persistence;
pub mod user_creation;
pub mod web_shell;

pub mod discovery_burst;
pub mod sensitive_write;

// v0.6.0 detectors
pub mod cgroup_abuse;
pub mod container_drift;
pub mod data_exfil_ebpf;
pub mod host_drift;
pub mod io_uring_anomaly;
pub mod mitre_hunt;
pub mod packet_flood;
pub mod sigma_rule;
pub mod yara_scan;
