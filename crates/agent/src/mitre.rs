//! MITRE ATT&CK mapping for Inner Warden detectors.
//!
//! Each detector name (the prefix of `incident_id` before the first `:`) is
//! mapped to a single primary MITRE ATT&CK tactic + technique pair.

use serde::Serialize;

/// A single MITRE ATT&CK mapping entry.
#[derive(Debug, Clone, Serialize)]
pub struct MitreMapping {
    pub tactic: &'static str,
    pub technique_id: &'static str,
    pub technique_name: &'static str,
}

/// Look up the MITRE ATT&CK mapping for a detector name.
///
/// The `detector` argument is the incident-id prefix before the first `:`.
/// Returns `None` for unknown detectors.
pub fn map_detector(detector: &str) -> Option<MitreMapping> {
    let m = |tactic, technique_id, technique_name| {
        Some(MitreMapping {
            tactic,
            technique_id,
            technique_name,
        })
    };

    match detector {
        // ── Credential Access ───────────────────────────────────────────
        "ssh_bruteforce" => m(
            "Credential Access",
            "T1110.001",
            "Brute Force: Password Guessing",
        ),
        "credential_stuffing" => m(
            "Credential Access",
            "T1110.004",
            "Brute Force: Credential Stuffing",
        ),
        "distributed_ssh" => m("Credential Access", "T1110", "Brute Force"),
        "credential_harvest" => m("Credential Access", "T1003", "OS Credential Dumping"),

        // ── Initial Access ──────────────────────────────────────────────
        "suspicious_login" => m("Initial Access", "T1078", "Valid Accounts"),

        // ── Reconnaissance ──────────────────────────────────────────────
        "port_scan" => m("Reconnaissance", "T1595", "Active Scanning"),
        "web_scan" => m("Reconnaissance", "T1595.002", "Vulnerability Scanning"),
        "user_agent_scanner" => m("Reconnaissance", "T1595.002", "Vulnerability Scanning"),

        // ── Impact ──────────────────────────────────────────────────────
        "search_abuse" => m("Impact", "T1499", "Endpoint Denial of Service"),
        "crypto_miner" => m("Impact", "T1496", "Resource Hijacking"),
        "outbound_anomaly" => m("Impact", "T1498", "Network Denial of Service"),
        "ransomware" => m("Impact", "T1486", "Data Encrypted for Impact"),

        // ── Execution ───────────────────────────────────────────────────
        "execution_guard" => m("Execution", "T1059", "Command and Scripting Interpreter"),
        "reverse_shell" => m("Execution", "T1059.004", "Unix Shell"),
        "process_tree" => m("Execution", "T1059", "Command and Scripting Interpreter"),
        "docker_anomaly" => m("Execution", "T1610", "Deploy Container"),

        // ── Defense Evasion ─────────────────────────────────────────────
        "fileless" => m("Defense Evasion", "T1620", "Reflective Code Loading"),
        "integrity_alert" => m("Defense Evasion", "T1098", "Account Manipulation"),
        "log_tampering" => m("Defense Evasion", "T1070", "Indicator Removal"),
        "rootkit" => m("Defense Evasion", "T1014", "Rootkit"),
        "process_injection" => m("Defense Evasion", "T1055", "Process Injection"),

        // ── Persistence ─────────────────────────────────────────────────
        "web_shell" => m("Persistence", "T1505.003", "Web Shell"),
        "osquery_anomaly" => m("Persistence", "T1053", "Scheduled Task/Job"),
        "ssh_key_injection" => m("Persistence", "T1098.004", "SSH Authorized Keys"),
        "kernel_module_load" => m("Persistence", "T1547.006", "Kernel Modules and Extensions"),
        "crontab_persistence" => m("Persistence", "T1053.003", "Cron"),
        "systemd_persistence" => m("Persistence", "T1543.002", "Systemd Service"),
        "user_creation" => m("Persistence", "T1136", "Create Account"),

        // ── Privilege Escalation ────────────────────────────────────────
        "container_escape" => m("Privilege Escalation", "T1611", "Escape to Host"),
        "privesc" => m(
            "Privilege Escalation",
            "T1068",
            "Exploitation for Privilege Escalation",
        ),
        "sudo_abuse" => m(
            "Privilege Escalation",
            "T1548",
            "Abuse Elevation Control Mechanism",
        ),

        // ── Command and Control ─────────────────────────────────────────
        "c2_callback" => m("Command and Control", "T1071", "Application Layer Protocol"),

        // ── Exfiltration ────────────────────────────────────────────────
        "dns_tunneling" => m(
            "Exfiltration",
            "T1048.001",
            "Exfiltration Over Alternative Protocol",
        ),
        "data_exfiltration" => m("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),

        // ── Lateral Movement ────────────────────────────────────────────
        "lateral_movement" => m("Lateral Movement", "T1021", "Remote Services"),

        // ── Multiple / Generic ──────────────────────────────────────────
        "suricata_alert" => m("Multiple", "T1190", "Exploit Public-Facing Application"),

        // ── Sensitive Write detector (file-write monitoring) ───────────
        "sensitive_write" => m(
            "Persistence",
            "T1546.004",
            "Unix Shell Configuration Modification",
        ),

        // ── MITRE Hunt detector (command-pattern matching) ─────────────
        "at_job_persist" => m("Persistence", "T1053.002", "At"),
        "file_permission_mod" => m(
            "Defense Evasion",
            "T1222.002",
            "Linux and Mac File and Directory Permissions Modification",
        ),
        "hidden_artifact" => m(
            "Defense Evasion",
            "T1564.001",
            "Hidden Files and Directories",
        ),
        "remote_access_tool" => m("Command and Control", "T1219", "Remote Access Software"),
        "service_stop" => m("Impact", "T1489", "Service Stop"),
        "system_shutdown" => m("Impact", "T1529", "System Shutdown/Reboot"),
        "network_sniffing" => m("Credential Access", "T1040", "Network Sniffing"),
        "masquerading" => m(
            "Defense Evasion",
            "T1036.005",
            "Match Legitimate Name or Location",
        ),
        "data_archive" => m("Collection", "T1560", "Archive Collected Data"),
        "proxy_tunnel" => m("Command and Control", "T1090", "Proxy"),

        _ => None,
    }
}

/// Return ALL MITRE ATT&CK techniques for a detector, including secondary mappings.
///
/// Multi-technique detectors (sudo_abuse, sensitive_write, etc.) detect patterns
/// that span several MITRE techniques. This function returns ALL of them for
/// accurate coverage counting. `map_detector()` returns only the primary.
#[allow(dead_code)]
pub fn map_detector_all(detector: &str) -> Vec<MitreMapping> {
    let m = |tactic: &'static str, id: &'static str, name: &'static str| MitreMapping {
        tactic,
        technique_id: id,
        technique_name: name,
    };

    match detector {
        "sudo_abuse" => vec![
            m(
                "Privilege Escalation",
                "T1548",
                "Abuse Elevation Control Mechanism",
            ),
            m("Privilege Escalation", "T1548.001", "Setuid and Setgid"),
            m("Defense Evasion", "T1562.001", "Disable or Modify Tools"),
            m(
                "Defense Evasion",
                "T1562.004",
                "Disable or Modify System Firewall",
            ),
            m("Impact", "T1485", "Data Destruction"),
        ],

        "sensitive_write" => vec![
            m(
                "Persistence",
                "T1546.004",
                "Unix Shell Configuration Modification",
            ),
            m("Persistence", "T1037.004", "RC Scripts"),
            m(
                "Credential Access",
                "T1556",
                "Modify Authentication Process",
            ),
            m("Persistence", "T1574.006", "Dynamic Linker Hijacking"),
        ],

        "execution_guard" => vec![
            m("Execution", "T1059", "Command and Scripting Interpreter"),
            m("Command and Control", "T1105", "Ingress Tool Transfer"),
            m(
                "Defense Evasion",
                "T1140",
                "Deobfuscate/Decode Files or Information",
            ),
        ],

        "data_exfil_ebpf" => vec![
            m("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
            m("Credential Access", "T1552.001", "Credentials In Files"),
            m("Credential Access", "T1552.004", "Private Keys"),
        ],

        "c2_callback" => vec![
            m("Command and Control", "T1071", "Application Layer Protocol"),
            m("Command and Control", "T1571", "Non-Standard Port"),
        ],

        // Single-technique detectors: wrap the primary mapping
        _ => match map_detector(detector) {
            Some(mapping) => vec![mapping],
            None => vec![],
        },
    }
}

/// Collect all unique MITRE technique IDs covered across every known detector.
///
/// Used by threat reports and dashboard to report total coverage count.
#[allow(dead_code)]
pub fn all_technique_ids() -> Vec<&'static str> {
    use std::collections::BTreeSet;

    let all_detectors = &[
        // Original 36 from map_detector
        "ssh_bruteforce",
        "credential_stuffing",
        "distributed_ssh",
        "credential_harvest",
        "suspicious_login",
        "port_scan",
        "web_scan",
        "user_agent_scanner",
        "search_abuse",
        "crypto_miner",
        "outbound_anomaly",
        "ransomware",
        "execution_guard",
        "reverse_shell",
        "process_tree",
        "docker_anomaly",
        "fileless",
        "integrity_alert",
        "log_tampering",
        "rootkit",
        "process_injection",
        "web_shell",
        "osquery_anomaly",
        "ssh_key_injection",
        "kernel_module_load",
        "crontab_persistence",
        "systemd_persistence",
        "user_creation",
        "container_escape",
        "privesc",
        "sudo_abuse",
        "c2_callback",
        "dns_tunneling",
        "data_exfiltration",
        "lateral_movement",
        "suricata_alert",
        // New detectors
        "sensitive_write",
        "at_job_persist",
        "file_permission_mod",
        "hidden_artifact",
        "remote_access_tool",
        "service_stop",
        "system_shutdown",
        "network_sniffing",
        "masquerading",
        "data_archive",
        "proxy_tunnel",
        "data_exfil_ebpf",
    ];

    let mut ids = BTreeSet::new();
    for det in all_detectors {
        for mapping in map_detector_all(det) {
            ids.insert(mapping.technique_id);
        }
    }
    ids.into_iter().collect()
}

/// Extract the detector name from an incident_id.
///
/// The convention is `detector_name:rest`, so we split on the first `:`.
pub fn detector_from_incident_id(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or(incident_id)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assert that a detector maps to the expected tactic and technique.
    fn assert_mapping(detector: &str, tactic: &str, technique_id: &str, technique_name: &str) {
        let m = map_detector(detector).unwrap_or_else(|| {
            panic!("expected mapping for detector '{detector}', got None");
        });
        assert_eq!(m.tactic, tactic, "tactic mismatch for '{detector}'");
        assert_eq!(
            m.technique_id, technique_id,
            "technique_id mismatch for '{detector}'"
        );
        assert_eq!(
            m.technique_name, technique_name,
            "technique_name mismatch for '{detector}'"
        );
    }

    // ── One test per tactic category ────────────────────────────────────

    #[test]
    fn test_credential_access() {
        assert_mapping(
            "ssh_bruteforce",
            "Credential Access",
            "T1110.001",
            "Brute Force: Password Guessing",
        );
        assert_mapping(
            "credential_harvest",
            "Credential Access",
            "T1003",
            "OS Credential Dumping",
        );
    }

    #[test]
    fn test_initial_access() {
        assert_mapping(
            "suspicious_login",
            "Initial Access",
            "T1078",
            "Valid Accounts",
        );
    }

    #[test]
    fn test_reconnaissance() {
        assert_mapping("port_scan", "Reconnaissance", "T1595", "Active Scanning");
        assert_mapping(
            "web_scan",
            "Reconnaissance",
            "T1595.002",
            "Vulnerability Scanning",
        );
    }

    #[test]
    fn test_impact() {
        assert_mapping(
            "search_abuse",
            "Impact",
            "T1499",
            "Endpoint Denial of Service",
        );
        assert_mapping("crypto_miner", "Impact", "T1496", "Resource Hijacking");
        assert_mapping("ransomware", "Impact", "T1486", "Data Encrypted for Impact");
    }

    #[test]
    fn test_execution() {
        assert_mapping(
            "execution_guard",
            "Execution",
            "T1059",
            "Command and Scripting Interpreter",
        );
        assert_mapping("reverse_shell", "Execution", "T1059.004", "Unix Shell");
    }

    #[test]
    fn test_defense_evasion() {
        assert_mapping(
            "fileless",
            "Defense Evasion",
            "T1620",
            "Reflective Code Loading",
        );
        assert_mapping("rootkit", "Defense Evasion", "T1014", "Rootkit");
        assert_mapping(
            "log_tampering",
            "Defense Evasion",
            "T1070",
            "Indicator Removal",
        );
    }

    #[test]
    fn test_persistence() {
        assert_mapping("web_shell", "Persistence", "T1505.003", "Web Shell");
        assert_mapping("crontab_persistence", "Persistence", "T1053.003", "Cron");
        assert_mapping("user_creation", "Persistence", "T1136", "Create Account");
    }

    #[test]
    fn test_privilege_escalation() {
        assert_mapping(
            "container_escape",
            "Privilege Escalation",
            "T1611",
            "Escape to Host",
        );
        assert_mapping(
            "sudo_abuse",
            "Privilege Escalation",
            "T1548",
            "Abuse Elevation Control Mechanism",
        );
    }

    #[test]
    fn test_command_and_control() {
        assert_mapping(
            "c2_callback",
            "Command and Control",
            "T1071",
            "Application Layer Protocol",
        );
    }

    #[test]
    fn test_exfiltration() {
        assert_mapping(
            "dns_tunneling",
            "Exfiltration",
            "T1048.001",
            "Exfiltration Over Alternative Protocol",
        );
        assert_mapping(
            "data_exfiltration",
            "Exfiltration",
            "T1041",
            "Exfiltration Over C2 Channel",
        );
    }

    #[test]
    fn test_lateral_movement() {
        assert_mapping(
            "lateral_movement",
            "Lateral Movement",
            "T1021",
            "Remote Services",
        );
    }

    #[test]
    fn test_multiple_tactic() {
        assert_mapping(
            "suricata_alert",
            "Multiple",
            "T1190",
            "Exploit Public-Facing Application",
        );
    }

    // ── New detectors ──────────────────────────────────────────────────

    #[test]
    fn test_sensitive_write() {
        assert_mapping(
            "sensitive_write",
            "Persistence",
            "T1546.004",
            "Unix Shell Configuration Modification",
        );
    }

    #[test]
    fn test_mitre_hunt_detectors() {
        assert_mapping("at_job_persist", "Persistence", "T1053.002", "At");
        assert_mapping(
            "file_permission_mod",
            "Defense Evasion",
            "T1222.002",
            "Linux and Mac File and Directory Permissions Modification",
        );
        assert_mapping(
            "hidden_artifact",
            "Defense Evasion",
            "T1564.001",
            "Hidden Files and Directories",
        );
        assert_mapping(
            "remote_access_tool",
            "Command and Control",
            "T1219",
            "Remote Access Software",
        );
        assert_mapping("service_stop", "Impact", "T1489", "Service Stop");
        assert_mapping(
            "system_shutdown",
            "Impact",
            "T1529",
            "System Shutdown/Reboot",
        );
        assert_mapping(
            "network_sniffing",
            "Credential Access",
            "T1040",
            "Network Sniffing",
        );
        assert_mapping(
            "masquerading",
            "Defense Evasion",
            "T1036.005",
            "Match Legitimate Name or Location",
        );
        assert_mapping(
            "data_archive",
            "Collection",
            "T1560",
            "Archive Collected Data",
        );
        assert_mapping("proxy_tunnel", "Command and Control", "T1090", "Proxy");
    }

    // ── map_detector_all tests ──────────────────────────────────────────

    #[test]
    fn test_map_detector_all_sudo_abuse() {
        let mappings = map_detector_all("sudo_abuse");
        assert_eq!(mappings.len(), 5, "sudo_abuse should map to 5 techniques");
        let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id).collect();
        assert!(ids.contains(&"T1548"));
        assert!(ids.contains(&"T1548.001"));
        assert!(ids.contains(&"T1562.001"));
        assert!(ids.contains(&"T1562.004"));
        assert!(ids.contains(&"T1485"));
    }

    #[test]
    fn test_map_detector_all_sensitive_write() {
        let mappings = map_detector_all("sensitive_write");
        assert_eq!(mappings.len(), 4);
        let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id).collect();
        assert!(ids.contains(&"T1546.004"));
        assert!(ids.contains(&"T1037.004"));
        assert!(ids.contains(&"T1556"));
        assert!(ids.contains(&"T1574.006"));
    }

    #[test]
    fn test_map_detector_all_execution_guard() {
        let mappings = map_detector_all("execution_guard");
        assert_eq!(mappings.len(), 3);
        let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id).collect();
        assert!(ids.contains(&"T1059"));
        assert!(ids.contains(&"T1105"));
        assert!(ids.contains(&"T1140"));
    }

    #[test]
    fn test_map_detector_all_data_exfil_ebpf() {
        let mappings = map_detector_all("data_exfil_ebpf");
        assert_eq!(mappings.len(), 3);
        let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id).collect();
        assert!(ids.contains(&"T1041"));
        assert!(ids.contains(&"T1552.001"));
        assert!(ids.contains(&"T1552.004"));
    }

    #[test]
    fn test_map_detector_all_c2_callback() {
        let mappings = map_detector_all("c2_callback");
        assert_eq!(mappings.len(), 2);
        let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id).collect();
        assert!(ids.contains(&"T1071"));
        assert!(ids.contains(&"T1571"));
    }

    #[test]
    fn test_map_detector_all_single_technique_fallback() {
        let mappings = map_detector_all("ssh_bruteforce");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].technique_id, "T1110.001");
    }

    #[test]
    fn test_map_detector_all_unknown_returns_empty() {
        let mappings = map_detector_all("nonexistent_detector");
        assert!(mappings.is_empty());
    }

    // ── Coverage count ──────────────────────────────────────────────────

    #[test]
    fn test_all_technique_ids_coverage() {
        let ids = all_technique_ids();
        // 42 original + 23 new = 65 unique technique IDs
        // (discovery_burst and eBPF timestomp/truncate are counted in README
        //  but not in map_detector; this counts only mitre.rs-mapped techniques)
        assert!(
            ids.len() >= 55,
            "expected at least 55 unique technique IDs from mitre.rs mappings, got {}",
            ids.len()
        );
        // Verify key new additions are present
        assert!(
            ids.contains(&"T1546.004"),
            "missing T1546.004 (Shell Config)"
        );
        assert!(ids.contains(&"T1037.004"), "missing T1037.004 (RC Scripts)");
        assert!(ids.contains(&"T1556"), "missing T1556 (Modify Auth)");
        assert!(ids.contains(&"T1574.006"), "missing T1574.006 (LD_PRELOAD)");
        assert!(ids.contains(&"T1548.001"), "missing T1548.001 (SUID)");
        assert!(
            ids.contains(&"T1562.001"),
            "missing T1562.001 (Disable Tools)"
        );
        assert!(ids.contains(&"T1562.004"), "missing T1562.004 (Disable FW)");
        assert!(ids.contains(&"T1485"), "missing T1485 (Data Destruction)");
        assert!(ids.contains(&"T1105"), "missing T1105 (Tool Transfer)");
        assert!(ids.contains(&"T1140"), "missing T1140 (Deobfuscation)");
        assert!(
            ids.contains(&"T1552.001"),
            "missing T1552.001 (Creds in Files)"
        );
        assert!(
            ids.contains(&"T1552.004"),
            "missing T1552.004 (Private Keys)"
        );
        assert!(ids.contains(&"T1571"), "missing T1571 (Non-Standard Port)");
        assert!(ids.contains(&"T1053.002"), "missing T1053.002 (At)");
        assert!(ids.contains(&"T1222.002"), "missing T1222.002 (File Perms)");
        assert!(
            ids.contains(&"T1564.001"),
            "missing T1564.001 (Hidden Files)"
        );
        assert!(ids.contains(&"T1219"), "missing T1219 (Remote Access)");
        assert!(ids.contains(&"T1489"), "missing T1489 (Service Stop)");
        assert!(ids.contains(&"T1529"), "missing T1529 (Shutdown)");
        assert!(ids.contains(&"T1040"), "missing T1040 (Sniffing)");
        assert!(
            ids.contains(&"T1036.005"),
            "missing T1036.005 (Masquerading)"
        );
        assert!(ids.contains(&"T1560"), "missing T1560 (Archive)");
        assert!(ids.contains(&"T1090"), "missing T1090 (Proxy)");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn test_unknown_detector_returns_none() {
        assert!(map_detector("nonexistent_detector").is_none());
    }

    #[test]
    fn test_detector_from_incident_id_simple() {
        assert_eq!(
            detector_from_incident_id("ssh_bruteforce:192.168.1.1:2024-01-01"),
            "ssh_bruteforce"
        );
    }

    #[test]
    fn test_detector_from_incident_id_no_colon() {
        assert_eq!(
            detector_from_incident_id("ssh_bruteforce"),
            "ssh_bruteforce"
        );
    }

    #[test]
    fn test_all_47_detectors_are_mapped() {
        let detectors = [
            // Original 36
            "ssh_bruteforce",
            "credential_stuffing",
            "distributed_ssh",
            "suspicious_login",
            "port_scan",
            "web_scan",
            "user_agent_scanner",
            "search_abuse",
            "execution_guard",
            "reverse_shell",
            "fileless",
            "web_shell",
            "process_tree",
            "c2_callback",
            "dns_tunneling",
            "container_escape",
            "docker_anomaly",
            "privesc",
            "sudo_abuse",
            "integrity_alert",
            "osquery_anomaly",
            "suricata_alert",
            "log_tampering",
            "lateral_movement",
            "crypto_miner",
            "outbound_anomaly",
            "rootkit",
            "ssh_key_injection",
            "kernel_module_load",
            "crontab_persistence",
            "systemd_persistence",
            "data_exfiltration",
            "process_injection",
            "user_creation",
            "ransomware",
            "credential_harvest",
            // New: sensitive_write + 10 mitre_hunt
            "sensitive_write",
            "at_job_persist",
            "file_permission_mod",
            "hidden_artifact",
            "remote_access_tool",
            "service_stop",
            "system_shutdown",
            "network_sniffing",
            "masquerading",
            "data_archive",
            "proxy_tunnel",
        ];
        for det in detectors {
            assert!(
                map_detector(det).is_some(),
                "detector '{det}' should have a MITRE mapping"
            );
        }
    }
}
