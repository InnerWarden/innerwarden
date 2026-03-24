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

        _ => None,
    }
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
    fn test_all_36_detectors_are_mapped() {
        let detectors = [
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
        ];
        for det in detectors {
            assert!(
                map_detector(det).is_some(),
                "detector '{det}' should have a MITRE mapping"
            );
        }
    }
}
