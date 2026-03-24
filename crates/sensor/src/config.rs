use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub collectors: CollectorsConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
}

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub host_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    pub data_dir: String,
    #[serde(default = "default_true")]
    pub write_events: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub auth_log: AuthLogConfig,
    #[serde(default)]
    pub integrity: IntegrityConfig,
    #[serde(default)]
    pub journald: JournaldConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub exec_audit: ExecAuditConfig,
    #[serde(default)]
    pub nginx_access: NginxAccessConfig,
    #[serde(default)]
    pub nginx_error: NginxErrorConfig,
    #[serde(default)]
    pub suricata_eve: SuricataEveConfig,
    #[serde(default)]
    pub osquery_log: OsqueryLogConfig,
    #[serde(default)]
    pub macos_log: MacosLogConfig,
    #[serde(default)]
    pub wazuh_alerts: WazuhAlertsConfig,
    #[serde(default)]
    pub syslog_firewall: SyslogFirewallConfig,
    #[serde(default)]
    pub cloudtrail: CloudTrailConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MacosLogConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WazuhAlertsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wazuh_alerts_path")]
    pub path: String,
}

impl Default for WazuhAlertsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_wazuh_alerts_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OsqueryLogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_osquery_log_path")]
    pub path: String,
}

impl Default for OsqueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_osquery_log_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SuricataEveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_suricata_eve_path")]
    pub path: String,
    /// Event types to ingest. Defaults: alert, dns, http, tls, anomaly.
    /// Add "flow" or "stats" if needed (high volume).
    #[serde(default = "default_suricata_event_types")]
    pub event_types: Vec<String>,
}

impl Default for SuricataEveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_suricata_eve_path(),
            event_types: default_suricata_event_types(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecAuditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_exec_audit_path")]
    pub path: String,
    #[serde(default)]
    pub include_tty: bool,
}

impl Default for ExecAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_exec_audit_path(),
            include_tty: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JournaldConfig {
    #[serde(default)]
    pub enabled: bool,
    /// systemd unit names to filter on (e.g. "sshd", "sudo"). Empty = all units.
    #[serde(default = "default_journald_units")]
    pub units: Vec<String>,
}

impl Default for JournaldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            units: default_journald_units(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DockerConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct IntegrityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec![],
            poll_seconds: default_poll_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auth_log_path")]
    pub path: String,
}

impl Default for AuthLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_auth_log_path(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub ssh_bruteforce: SshBruteforceConfig,
    #[serde(default)]
    pub credential_stuffing: CredentialStuffingConfig,
    #[serde(default)]
    pub port_scan: PortScanConfig,
    #[serde(default)]
    pub sudo_abuse: SudoAbuseConfig,
    #[serde(default)]
    pub search_abuse: SearchAbuseConfig,
    #[serde(default)]
    pub web_scan: WebScanConfig,
    #[serde(default)]
    pub user_agent_scanner: UserAgentScannerConfig,
    #[serde(default)]
    pub execution_guard: ExecutionGuardConfig,
    #[serde(default)]
    pub suricata_alert: SuricataAlertConfig,
    #[serde(default)]
    pub docker_anomaly: DockerAnomalyConfig,
    #[serde(default)]
    pub integrity_alert: IntegrityAlertConfig,
    #[serde(default)]
    pub log_tampering: LogTamperingConfig,
    #[serde(default)]
    pub osquery_anomaly: OsqueryAnomalyConfig,
    #[serde(default)]
    pub dns_tunneling: DnsTunnelingConfig,
    #[serde(default)]
    pub lateral_movement: LateralMovementConfig,
    #[serde(default)]
    pub crypto_miner: CryptoMinerConfig,
    #[serde(default)]
    pub outbound_anomaly: OutboundAnomalyConfig,
    #[serde(default)]
    pub rootkit: RootkitConfig,
    #[serde(default)]
    pub reverse_shell: ReverseShellConfig,
    #[serde(default)]
    pub ssh_key_injection: SshKeyInjectionConfig,
    #[serde(default)]
    pub web_shell: WebShellConfig,
    #[serde(default)]
    pub kernel_module_load: KernelModuleLoadConfig,
    #[serde(default)]
    pub crontab_persistence: CrontabPersistenceConfig,
    #[serde(default)]
    pub data_exfiltration: DataExfiltrationConfig,
    #[serde(default)]
    pub process_injection: ProcessInjectionConfig,
    #[serde(default)]
    pub user_creation: UserCreationConfig,
    #[serde(default)]
    pub systemd_persistence: SystemdPersistenceConfig,
    #[serde(default)]
    pub ransomware: RansomwareConfig,
    #[serde(default)]
    pub credential_harvest: CredentialHarvestConfig,
}

#[derive(Debug, Deserialize)]
pub struct SshBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: usize,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SshBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_threshold(),
            window_seconds: default_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CredentialStuffingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_credential_stuffing_threshold")]
    pub threshold: usize,
    #[serde(default = "default_credential_stuffing_window_seconds")]
    pub window_seconds: u64,
}

impl Default for CredentialStuffingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_credential_stuffing_threshold(),
            window_seconds: default_credential_stuffing_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortScanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_port_scan_threshold")]
    pub threshold: usize,
    #[serde(default = "default_port_scan_window_seconds")]
    pub window_seconds: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_port_scan_threshold(),
            window_seconds: default_port_scan_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SudoAbuseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_sudo_abuse_threshold")]
    pub threshold: usize,
    #[serde(default = "default_sudo_abuse_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SudoAbuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_sudo_abuse_threshold(),
            window_seconds: default_sudo_abuse_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NginxAccessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nginx_access_path")]
    pub path: String,
}

impl Default for NginxAccessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_nginx_access_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchAbuseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_search_abuse_threshold")]
    pub threshold: usize,
    #[serde(default = "default_search_abuse_window_seconds")]
    pub window_seconds: u64,
    /// Path prefix to monitor. Empty string means all paths.
    #[serde(default = "default_search_abuse_path_prefix")]
    pub path_prefix: String,
}

impl Default for SearchAbuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_search_abuse_threshold(),
            window_seconds: default_search_abuse_window_seconds(),
            path_prefix: default_search_abuse_path_prefix(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecutionGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Execution mode. Only "observe" is implemented in this version.
    /// Future: "contain" (suspend-user-sudo + isolate session) and
    ///         "strict" (pre-execution interception via eBPF/LSM).
    #[serde(default = "default_execution_guard_mode")]
    pub mode: String,
    /// Correlation window for timeline sequence detection (default: 300s)
    #[serde(default = "default_execution_guard_window_seconds")]
    pub window_seconds: u64,
}

impl Default for ExecutionGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_execution_guard_mode(),
            window_seconds: default_execution_guard_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SuricataAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_suricata_alert_threshold")]
    pub threshold: usize,
    #[serde(default = "default_suricata_alert_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SuricataAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_suricata_alert_threshold(),
            window_seconds: default_suricata_alert_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DockerAnomalyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_docker_anomaly_threshold")]
    pub threshold: usize,
    #[serde(default = "default_docker_anomaly_window_seconds")]
    pub window_seconds: u64,
}

impl Default for DockerAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_docker_anomaly_threshold(),
            window_seconds: default_docker_anomaly_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IntegrityAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_integrity_alert_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for IntegrityAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cooldown_seconds: default_integrity_alert_cooldown_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogTamperingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_tampering_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for LogTamperingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_log_tampering_cooldown_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OsqueryAnomalyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_osquery_anomaly_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for OsqueryAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cooldown_seconds: default_osquery_anomaly_cooldown_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DnsTunnelingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_tunneling_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_dns_tunneling_volume_threshold")]
    pub volume_threshold: usize,
    #[serde(default = "default_dns_tunneling_length_threshold")]
    pub length_threshold: usize,
    #[serde(default = "default_dns_tunneling_window_seconds")]
    pub window_seconds: u64,
}

impl Default for DnsTunnelingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: default_dns_tunneling_entropy_threshold(),
            volume_threshold: default_dns_tunneling_volume_threshold(),
            length_threshold: default_dns_tunneling_length_threshold(),
            window_seconds: default_dns_tunneling_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LateralMovementConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_lateral_movement_ssh_threshold")]
    pub ssh_threshold: usize,
    #[serde(default = "default_lateral_movement_scan_threshold")]
    pub scan_threshold: usize,
    #[serde(default = "default_lateral_movement_window_seconds")]
    pub window_seconds: u64,
}

impl Default for LateralMovementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ssh_threshold: default_lateral_movement_ssh_threshold(),
            scan_threshold: default_lateral_movement_scan_threshold(),
            window_seconds: default_lateral_movement_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CryptoMinerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_crypto_miner_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CryptoMinerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_crypto_miner_cooldown_seconds(),
        }
    }
}

fn default_crypto_miner_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct OutboundAnomalyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_outbound_anomaly_connection_flood_threshold")]
    pub connection_flood_threshold: usize,
    #[serde(default = "default_outbound_anomaly_port_spray_threshold")]
    pub port_spray_threshold: usize,
    #[serde(default = "default_outbound_anomaly_udp_flood_threshold")]
    pub udp_flood_threshold: usize,
    #[serde(default = "default_outbound_anomaly_fanout_threshold")]
    pub fanout_threshold: usize,
    #[serde(default = "default_outbound_anomaly_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_outbound_anomaly_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for OutboundAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_flood_threshold: default_outbound_anomaly_connection_flood_threshold(),
            port_spray_threshold: default_outbound_anomaly_port_spray_threshold(),
            udp_flood_threshold: default_outbound_anomaly_udp_flood_threshold(),
            fanout_threshold: default_outbound_anomaly_fanout_threshold(),
            window_seconds: default_outbound_anomaly_window_seconds(),
            cooldown_seconds: default_outbound_anomaly_cooldown_seconds(),
        }
    }
}

fn default_outbound_anomaly_connection_flood_threshold() -> usize {
    50
}

fn default_outbound_anomaly_port_spray_threshold() -> usize {
    20
}

fn default_outbound_anomaly_udp_flood_threshold() -> usize {
    100
}

fn default_outbound_anomaly_fanout_threshold() -> usize {
    10
}

fn default_outbound_anomaly_window_seconds() -> u64 {
    60
}

fn default_outbound_anomaly_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct RootkitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rootkit_check_interval_seconds")]
    pub check_interval_seconds: u64,
    #[serde(default = "default_rootkit_cooldown_seconds")]
    pub cooldown_seconds: u64,
    /// Enable eBPF program integrity monitoring.
    /// Detects rogue BPF programs pinned in /sys/fs/bpf/ and BPF manipulation commands.
    #[serde(default = "default_true")]
    pub bpf_integrity_enabled: bool,
}

impl Default for RootkitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: default_rootkit_check_interval_seconds(),
            cooldown_seconds: default_rootkit_cooldown_seconds(),
            bpf_integrity_enabled: true,
        }
    }
}

fn default_rootkit_check_interval_seconds() -> u64 {
    60
}

fn default_rootkit_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct ReverseShellConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_reverse_shell_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for ReverseShellConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_reverse_shell_cooldown_seconds(),
        }
    }
}

fn default_reverse_shell_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct SshKeyInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ssh_key_injection_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for SshKeyInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_ssh_key_injection_cooldown_seconds(),
        }
    }
}

fn default_ssh_key_injection_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct WebShellConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_web_shell_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for WebShellConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_web_shell_cooldown_seconds(),
        }
    }
}

fn default_web_shell_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct KernelModuleLoadConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_kernel_module_load_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for KernelModuleLoadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_kernel_module_load_cooldown_seconds(),
        }
    }
}

fn default_kernel_module_load_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct CrontabPersistenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_crontab_persistence_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CrontabPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_crontab_persistence_cooldown_seconds(),
        }
    }
}

fn default_crontab_persistence_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct DataExfiltrationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_data_exfiltration_correlation_window_seconds")]
    pub correlation_window_seconds: u64,
    #[serde(default = "default_data_exfiltration_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for DataExfiltrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            correlation_window_seconds: default_data_exfiltration_correlation_window_seconds(),
            cooldown_seconds: default_data_exfiltration_cooldown_seconds(),
        }
    }
}

fn default_data_exfiltration_correlation_window_seconds() -> u64 {
    60
}

fn default_data_exfiltration_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct ProcessInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_process_injection_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for ProcessInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_process_injection_cooldown_seconds(),
        }
    }
}

fn default_process_injection_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct UserCreationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_user_creation_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for UserCreationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_user_creation_cooldown_seconds(),
        }
    }
}

fn default_user_creation_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct SystemdPersistenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_systemd_persistence_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for SystemdPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_systemd_persistence_cooldown_seconds(),
        }
    }
}

fn default_systemd_persistence_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct RansomwareConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ransomware_file_threshold")]
    pub file_threshold: usize,
    #[serde(default = "default_ransomware_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_ransomware_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file_threshold: default_ransomware_file_threshold(),
            window_seconds: default_ransomware_window_seconds(),
            cooldown_seconds: default_ransomware_cooldown_seconds(),
        }
    }
}

fn default_ransomware_file_threshold() -> usize {
    50
}

fn default_ransomware_window_seconds() -> u64 {
    30
}

fn default_ransomware_cooldown_seconds() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
pub struct CredentialHarvestConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_credential_harvest_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CredentialHarvestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_credential_harvest_cooldown_seconds(),
        }
    }
}

fn default_credential_harvest_cooldown_seconds() -> u64 {
    600
}

fn default_lateral_movement_ssh_threshold() -> usize {
    3
}

fn default_lateral_movement_scan_threshold() -> usize {
    5
}

fn default_lateral_movement_window_seconds() -> u64 {
    300
}

fn default_dns_tunneling_entropy_threshold() -> f64 {
    4.0
}

fn default_dns_tunneling_volume_threshold() -> usize {
    15
}

fn default_dns_tunneling_length_threshold() -> usize {
    100
}

fn default_dns_tunneling_window_seconds() -> u64 {
    60
}

fn default_osquery_anomaly_cooldown_seconds() -> u64 {
    3600
}

fn default_true() -> bool {
    true
}

fn default_threshold() -> usize {
    8
}

fn default_port_scan_threshold() -> usize {
    12
}

fn default_credential_stuffing_threshold() -> usize {
    6
}

fn default_sudo_abuse_threshold() -> usize {
    3
}

fn default_window_seconds() -> u64 {
    300
}

fn default_port_scan_window_seconds() -> u64 {
    60
}

fn default_credential_stuffing_window_seconds() -> u64 {
    300
}

fn default_sudo_abuse_window_seconds() -> u64 {
    300
}

fn default_poll_seconds() -> u64 {
    60
}

fn default_auth_log_path() -> String {
    "/var/log/auth.log".to_string()
}

fn default_exec_audit_path() -> String {
    "/var/log/audit/audit.log".to_string()
}

fn default_journald_units() -> Vec<String> {
    vec!["sshd".to_string(), "sudo".to_string()]
}

fn default_nginx_access_path() -> String {
    "/var/log/nginx/access.log".to_string()
}

fn default_search_abuse_threshold() -> usize {
    30
}

fn default_search_abuse_window_seconds() -> u64 {
    60
}

fn default_search_abuse_path_prefix() -> String {
    "/api/search".to_string()
}

fn default_osquery_log_path() -> String {
    "/var/log/osquery/osqueryd.results.log".to_string()
}

fn default_suricata_eve_path() -> String {
    "/var/log/suricata/eve.json".to_string()
}

fn default_suricata_event_types() -> Vec<String> {
    ["alert", "dns", "http", "tls", "anomaly"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_wazuh_alerts_path() -> String {
    "/var/ossec/logs/alerts/alerts.json".to_string()
}

fn default_execution_guard_mode() -> String {
    "observe".to_string()
}

fn default_execution_guard_window_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct NginxErrorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nginx_error_path")]
    pub path: String,
}

impl Default for NginxErrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_nginx_error_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WebScanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_web_scan_threshold")]
    pub threshold: usize,
    #[serde(default = "default_web_scan_window_seconds")]
    pub window_seconds: u64,
}

impl Default for WebScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_web_scan_threshold(),
            window_seconds: default_web_scan_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct UserAgentScannerConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_nginx_error_path() -> String {
    "/var/log/nginx/error.log".to_string()
}

fn default_web_scan_threshold() -> usize {
    15
}

fn default_web_scan_window_seconds() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
pub struct SyslogFirewallConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to syslog or kern.log. Defaults to /var/log/syslog on Debian/Ubuntu,
    /// /var/log/kern.log is a common alternative.
    #[serde(default = "default_syslog_firewall_path")]
    pub path: String,
}

impl Default for SyslogFirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_syslog_firewall_path(),
        }
    }
}

fn default_syslog_firewall_path() -> String {
    "/var/log/syslog".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CloudTrailConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Directory containing pre-extracted CloudTrail JSON files.
    #[serde(default = "default_cloudtrail_dir")]
    pub dir: String,
}

impl Default for CloudTrailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_cloudtrail_dir(),
        }
    }
}

fn default_cloudtrail_dir() -> String {
    "/var/log/cloudtrail".to_string()
}

fn default_suricata_alert_threshold() -> usize {
    3
}

fn default_suricata_alert_window_seconds() -> u64 {
    300
}

fn default_docker_anomaly_threshold() -> usize {
    3
}

fn default_docker_anomaly_window_seconds() -> u64 {
    300
}

fn default_integrity_alert_cooldown_seconds() -> u64 {
    3600
}

fn default_log_tampering_cooldown_seconds() -> u64 {
    600
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("failed to read config: {path}"))?;
    toml::from_str(&content).with_context(|| "failed to parse config")
}
