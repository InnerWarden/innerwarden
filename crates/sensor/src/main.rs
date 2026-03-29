mod collectors;
mod config;
mod detectors;
mod sinks;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use collectors::{
    auth_log::AuthLogCollector, cloudtrail::CloudTrailCollector, docker::DockerCollector,
    exec_audit::ExecAuditCollector, integrity::IntegrityCollector, journald::JournaldCollector,
    macos_log::MacosLogCollector, nginx_access::NginxAccessCollector,
    nginx_error::NginxErrorCollector, osquery_log::OsqueryLogCollector,
    suricata_eve::SuricataEveCollector, syslog_firewall::SyslogFirewallCollector,
    wazuh_alerts::WazuhAlertsCollector,
};
use detectors::c2_callback::C2CallbackDetector;
use detectors::container_escape::ContainerEscapeDetector;
use detectors::credential_harvest::CredentialHarvestDetector;
use detectors::credential_stuffing::CredentialStuffingDetector;
use detectors::crontab_persistence::CrontabPersistenceDetector;
use detectors::crypto_miner::CryptoMinerDetector;
use detectors::data_exfiltration::DataExfiltrationDetector;
use detectors::distributed_ssh::DistributedSshDetector;
use detectors::dns_tunneling::DnsTunnelingDetector;
use detectors::docker_anomaly::DockerAnomalyDetector;
use detectors::execution_guard::{ExecutionGuardDetector, ExecutionMode};
use detectors::fileless::FilelessDetector;
use detectors::integrity_alert::IntegrityAlertDetector;
use detectors::kernel_module_load::KernelModuleLoadDetector;
use detectors::lateral_movement::LateralMovementDetector;
use detectors::log_tampering::LogTamperingDetector;
use detectors::osquery_anomaly::OsqueryAnomalyDetector;
use detectors::outbound_anomaly::OutboundAnomalyDetector;
use detectors::packet_flood::PacketFloodDetector;
use detectors::port_scan::PortScanDetector;
use detectors::privesc::PrivescDetector;
use detectors::process_injection::ProcessInjectionDetector;
use detectors::process_tree::ProcessTreeDetector;
use detectors::ransomware::RansomwareDetector;
use detectors::reverse_shell::ReverseShellDetector;
use detectors::rootkit::RootkitDetector;
use detectors::search_abuse::SearchAbuseDetector;
use detectors::ssh_bruteforce::SshBruteforceDetector;
use detectors::ssh_key_injection::SshKeyInjectionDetector;
use detectors::sudo_abuse::SudoAbuseDetector;
use detectors::suricata_alert::SuricataAlertDetector;
use detectors::suspicious_login::SuspiciousLoginDetector;
use detectors::systemd_persistence::SystemdPersistenceDetector;
use detectors::user_agent_scanner::UserAgentScannerDetector;
use detectors::user_creation::UserCreationDetector;
use detectors::web_scan::WebScanDetector;
use detectors::web_shell::WebShellDetector;
#[cfg(feature = "redis-sink")]
use sinks::redis_stream::{RedisStreamConfig, RedisStreamWriter};
use sinks::{jsonl::JsonlWriter, state::State};
use tokio::sync::mpsc;
use tokio::time;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "innerwarden-sensor",
    version,
    about = "Lightweight host observability sensor"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

struct DetectorSet {
    ssh: Option<SshBruteforceDetector>,
    credential_stuffing: Option<CredentialStuffingDetector>,
    port_scan: Option<PortScanDetector>,
    sudo_abuse: Option<SudoAbuseDetector>,
    search_abuse: Option<SearchAbuseDetector>,
    web_scan: Option<WebScanDetector>,
    user_agent_scanner: Option<UserAgentScannerDetector>,
    execution_guard: Option<ExecutionGuardDetector>,
    suricata_alert: Option<SuricataAlertDetector>,
    docker_anomaly: Option<DockerAnomalyDetector>,
    integrity_alert: Option<IntegrityAlertDetector>,
    log_tampering: Option<LogTamperingDetector>,
    osquery_anomaly: Option<OsqueryAnomalyDetector>,
    distributed_ssh: Option<DistributedSshDetector>,
    suspicious_login: Option<SuspiciousLoginDetector>,
    c2_callback: Option<C2CallbackDetector>,
    process_tree: Option<ProcessTreeDetector>,
    container_escape: Option<ContainerEscapeDetector>,
    privesc: Option<PrivescDetector>,
    fileless: Option<FilelessDetector>,
    dns_tunneling: Option<DnsTunnelingDetector>,
    lateral_movement: Option<LateralMovementDetector>,
    crypto_miner: Option<CryptoMinerDetector>,
    outbound_anomaly: Option<OutboundAnomalyDetector>,
    rootkit: Option<RootkitDetector>,
    reverse_shell: Option<ReverseShellDetector>,
    ssh_key_injection: Option<SshKeyInjectionDetector>,
    web_shell: Option<WebShellDetector>,
    kernel_module_load: Option<KernelModuleLoadDetector>,
    crontab_persistence: Option<CrontabPersistenceDetector>,
    data_exfiltration: Option<DataExfiltrationDetector>,
    process_injection: Option<ProcessInjectionDetector>,
    user_creation: Option<UserCreationDetector>,
    systemd_persistence: Option<SystemdPersistenceDetector>,
    ransomware: Option<RansomwareDetector>,
    credential_harvest: Option<CredentialHarvestDetector>,
    packet_flood: Option<PacketFloodDetector>,
    sensitive_write: Option<detectors::sensitive_write::SensitiveWriteDetector>,
    io_uring_anomaly: Option<detectors::io_uring_anomaly::IoUringAnomalyDetector>,
    container_drift: Option<detectors::container_drift::ContainerDriftDetector>,
    host_drift: Option<detectors::host_drift::HostDriftDetector>,
    data_exfil_ebpf: Option<detectors::data_exfil_ebpf::DataExfilEbpfDetector>,
    yara_scan: Option<detectors::yara_scan::YaraScanDetector>,
    sigma_rule: Option<detectors::sigma_rule::SigmaRuleDetector>,
}

#[derive(Default)]
struct WriteStats {
    events_written: u64,
    incidents_written: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_sensor=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = data_dir.join("state.json");

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    // When Redis is configured, events go to Redis Streams. JSONL still writes
    // incidents (they're small and need persistence). Events JSONL is disabled
    // when Redis is active to avoid disk bloat.
    #[cfg(feature = "redis-sink")]
    let mut redis_writer: Option<RedisStreamWriter> = if let Some(ref url) = cfg.output.redis_url {
        let redis_cfg = RedisStreamConfig::new(
            url,
            cfg.output.redis_stream.as_deref(),
            cfg.output.redis_maxlen,
        );
        match RedisStreamWriter::connect(redis_cfg).await {
            Ok(w) => Some(w),
            Err(e) => {
                warn!("Redis connection failed ({e:#}), falling back to JSONL only");
                None
            }
        }
    } else {
        None
    };

    // If Redis is active, disable JSONL event writes (incidents still written).
    #[cfg(feature = "redis-sink")]
    let write_events_jsonl = cfg.output.write_events && redis_writer.is_none();
    #[cfg(not(feature = "redis-sink"))]
    let write_events_jsonl = cfg.output.write_events;

    let mut writer = JsonlWriter::new(data_dir, write_events_jsonl)?;
    // Optional syslog CEF output (configured via env or future config section)
    let mut syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter> = {
        let syslog_host = std::env::var("INNERWARDEN_SYSLOG_HOST").unwrap_or_default();
        if syslog_host.is_empty() {
            None
        } else {
            let port: u16 = std::env::var("INNERWARDEN_SYSLOG_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(514);
            let protocol = if std::env::var("INNERWARDEN_SYSLOG_TCP").is_ok() {
                sinks::syslog_cef::SyslogProtocol::Tcp
            } else {
                sinks::syslog_cef::SyslogProtocol::Udp
            };
            info!(host = %syslog_host, port, "Syslog CEF output enabled");
            Some(sinks::syslog_cef::SyslogCefWriter::new(
                sinks::syslog_cef::SyslogCefConfig {
                    host: syslog_host,
                    port,
                    protocol,
                },
                env!("CARGO_PKG_VERSION"),
            ))
        }
    };
    let (tx, mut rx) = mpsc::channel(1024);

    // Shared state - updated by collectors, read on shutdown for persistence.
    let shared_auth_offset = Arc::new(AtomicU64::new(0));
    let shared_integrity_hashes: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared_journald_cursor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_docker_since: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_exec_audit_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_error_offset = Arc::new(AtomicU64::new(0));
    let shared_suricata_offset = Arc::new(AtomicU64::new(0));
    let shared_osquery_offset = Arc::new(AtomicU64::new(0));
    let shared_wazuh_offset = Arc::new(AtomicU64::new(0));
    let shared_syslog_firewall_offset = Arc::new(AtomicU64::new(0));

    // SSH brute force detector (stateful, lives in main loop)
    let ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "ssh_bruteforce detector enabled"
        );
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let credential_stuffing_detector = cfg.detectors.credential_stuffing.enabled.then(|| {
        let d = &cfg.detectors.credential_stuffing;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "credential_stuffing detector enabled"
        );
        CredentialStuffingDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let port_scan_detector = cfg.detectors.port_scan.enabled.then(|| {
        let d = &cfg.detectors.port_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "port_scan detector enabled"
        );
        PortScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let sudo_abuse_detector = cfg.detectors.sudo_abuse.enabled.then(|| {
        let d = &cfg.detectors.sudo_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "sudo_abuse detector enabled"
        );
        SudoAbuseDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let search_abuse_detector = cfg.detectors.search_abuse.enabled.then(|| {
        let d = &cfg.detectors.search_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            path_prefix = %d.path_prefix,
            "search_abuse detector enabled"
        );
        SearchAbuseDetector::new(
            &cfg.agent.host_id,
            d.threshold,
            d.window_seconds,
            &d.path_prefix,
        )
    });
    let web_scan_detector = cfg.detectors.web_scan.enabled.then(|| {
        let d = &cfg.detectors.web_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "web_scan detector enabled"
        );
        WebScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let user_agent_scanner_detector = cfg.detectors.user_agent_scanner.enabled.then(|| {
        info!("user_agent_scanner detector enabled");
        UserAgentScannerDetector::new(&cfg.agent.host_id)
    });
    let execution_guard_detector = cfg.detectors.execution_guard.enabled.then(|| {
        let d = &cfg.detectors.execution_guard;
        info!(
            mode = %d.mode,
            window_seconds = d.window_seconds,
            "execution_guard detector enabled"
        );
        ExecutionGuardDetector::new(
            &cfg.agent.host_id,
            d.window_seconds,
            ExecutionMode::from_str(&d.mode),
        )
    });
    let suricata_alert_detector = cfg.detectors.suricata_alert.enabled.then(|| {
        let d = &cfg.detectors.suricata_alert;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "suricata_alert detector enabled"
        );
        SuricataAlertDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let docker_anomaly_detector = cfg.detectors.docker_anomaly.enabled.then(|| {
        let d = &cfg.detectors.docker_anomaly;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "docker_anomaly detector enabled"
        );
        DockerAnomalyDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let integrity_alert_detector = cfg.detectors.integrity_alert.enabled.then(|| {
        let d = &cfg.detectors.integrity_alert;
        info!(
            cooldown_seconds = d.cooldown_seconds,
            "integrity_alert detector enabled"
        );
        IntegrityAlertDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
    });
    let log_tampering_detector = cfg.detectors.log_tampering.enabled.then(|| {
        let d = &cfg.detectors.log_tampering;
        info!(
            cooldown_seconds = d.cooldown_seconds,
            "log_tampering detector enabled (eBPF openat log file monitoring)"
        );
        LogTamperingDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
    });
    let osquery_anomaly_detector = cfg.detectors.osquery_anomaly.enabled.then(|| {
        let d = &cfg.detectors.osquery_anomaly;
        info!(
            cooldown_seconds = d.cooldown_seconds,
            "osquery_anomaly detector enabled"
        );
        OsqueryAnomalyDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
    });
    // Distributed SSH detector - always on when ssh_bruteforce is on
    let distributed_ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        info!(
            threshold = 8,
            window_seconds = 300,
            "distributed_ssh detector enabled"
        );
        DistributedSshDetector::new(&cfg.agent.host_id, 8, 300)
    });
    let mut detectors = DetectorSet {
        ssh: ssh_detector,
        credential_stuffing: credential_stuffing_detector,
        port_scan: port_scan_detector,
        sudo_abuse: sudo_abuse_detector,
        search_abuse: search_abuse_detector,
        web_scan: web_scan_detector,
        user_agent_scanner: user_agent_scanner_detector,
        execution_guard: execution_guard_detector,
        suricata_alert: suricata_alert_detector,
        docker_anomaly: docker_anomaly_detector,
        integrity_alert: integrity_alert_detector,
        log_tampering: log_tampering_detector,
        osquery_anomaly: osquery_anomaly_detector,
        distributed_ssh: distributed_ssh_detector,
        suspicious_login: cfg.detectors.ssh_bruteforce.enabled.then(|| {
            info!("suspicious_login detector enabled");
            SuspiciousLoginDetector::new(&cfg.agent.host_id, 300)
        }),
        c2_callback: Some({
            info!("c2_callback detector enabled (eBPF network monitoring)");
            C2CallbackDetector::new(&cfg.agent.host_id, 600)
        }),
        process_tree: Some({
            info!("process_tree detector enabled (eBPF parent-child tracking)");
            ProcessTreeDetector::new(&cfg.agent.host_id, 600)
        }),
        container_escape: Some({
            info!("container_escape detector enabled");
            ContainerEscapeDetector::new(&cfg.agent.host_id, 600)
        }),
        privesc: Some({
            info!("privesc detector enabled (eBPF commit_creds kprobe)");
            PrivescDetector::new(&cfg.agent.host_id, 600)
        }),
        fileless: Some({
            info!("fileless detector enabled (eBPF memfd/fd/deleted binary detection)");
            FilelessDetector::new(&cfg.agent.host_id, 600)
        }),
        dns_tunneling: cfg.detectors.dns_tunneling.enabled.then(|| {
            let d = &cfg.detectors.dns_tunneling;
            info!(
                entropy_threshold = d.entropy_threshold,
                volume_threshold = d.volume_threshold,
                length_threshold = d.length_threshold,
                window_seconds = d.window_seconds,
                "dns_tunneling detector enabled"
            );
            DnsTunnelingDetector::new(
                &cfg.agent.host_id,
                d.entropy_threshold,
                d.volume_threshold,
                d.length_threshold,
                d.window_seconds,
            )
        }),
        lateral_movement: cfg.detectors.lateral_movement.enabled.then(|| {
            let d = &cfg.detectors.lateral_movement;
            info!(
                ssh_threshold = d.ssh_threshold,
                scan_threshold = d.scan_threshold,
                window_seconds = d.window_seconds,
                "lateral_movement detector enabled"
            );
            LateralMovementDetector::new(
                &cfg.agent.host_id,
                d.ssh_threshold,
                d.scan_threshold,
                d.window_seconds,
            )
        }),
        crypto_miner: cfg.detectors.crypto_miner.enabled.then(|| {
            let d = &cfg.detectors.crypto_miner;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "crypto_miner detector enabled"
            );
            CryptoMinerDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        outbound_anomaly: cfg.detectors.outbound_anomaly.enabled.then(|| {
            let d = &cfg.detectors.outbound_anomaly;
            info!(
                connection_flood_threshold = d.connection_flood_threshold,
                port_spray_threshold = d.port_spray_threshold,
                udp_flood_threshold = d.udp_flood_threshold,
                fanout_threshold = d.fanout_threshold,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "outbound_anomaly detector enabled"
            );
            OutboundAnomalyDetector::new(
                &cfg.agent.host_id,
                d.connection_flood_threshold,
                d.port_spray_threshold,
                d.udp_flood_threshold,
                d.fanout_threshold,
                d.window_seconds,
                d.cooldown_seconds,
            )
        }),
        rootkit: cfg.detectors.rootkit.enabled.then(|| {
            let d = &cfg.detectors.rootkit;
            info!(
                check_interval_seconds = d.check_interval_seconds,
                cooldown_seconds = d.cooldown_seconds,
                timing_enabled = d.timing_enabled,
                timing_min_samples = d.timing_min_samples,
                timing_z_threshold = d.timing_z_threshold,
                timing_consecutive_threshold = d.timing_consecutive_threshold,
                "rootkit detector enabled"
            );
            RootkitDetector::new(
                &cfg.agent.host_id,
                d.check_interval_seconds,
                d.cooldown_seconds,
            )
            .with_timing_config(
                d.timing_enabled,
                d.timing_min_samples,
                d.timing_z_threshold,
                d.timing_consecutive_threshold,
            )
        }),
        reverse_shell: cfg.detectors.reverse_shell.enabled.then(|| {
            let d = &cfg.detectors.reverse_shell;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "reverse_shell detector enabled"
            );
            ReverseShellDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        ssh_key_injection: cfg.detectors.ssh_key_injection.enabled.then(|| {
            let d = &cfg.detectors.ssh_key_injection;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "ssh_key_injection detector enabled"
            );
            SshKeyInjectionDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        web_shell: cfg.detectors.web_shell.enabled.then(|| {
            let d = &cfg.detectors.web_shell;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "web_shell detector enabled"
            );
            WebShellDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        kernel_module_load: cfg.detectors.kernel_module_load.enabled.then(|| {
            let d = &cfg.detectors.kernel_module_load;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "kernel_module_load detector enabled"
            );
            KernelModuleLoadDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        crontab_persistence: cfg.detectors.crontab_persistence.enabled.then(|| {
            let d = &cfg.detectors.crontab_persistence;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "crontab_persistence detector enabled"
            );
            CrontabPersistenceDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        data_exfiltration: cfg.detectors.data_exfiltration.enabled.then(|| {
            let d = &cfg.detectors.data_exfiltration;
            info!(
                correlation_window_seconds = d.correlation_window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "data_exfiltration detector enabled"
            );
            DataExfiltrationDetector::new(
                &cfg.agent.host_id,
                d.correlation_window_seconds,
                d.cooldown_seconds,
            )
        }),
        process_injection: cfg.detectors.process_injection.enabled.then(|| {
            let d = &cfg.detectors.process_injection;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "process_injection detector enabled"
            );
            ProcessInjectionDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        user_creation: cfg.detectors.user_creation.enabled.then(|| {
            let d = &cfg.detectors.user_creation;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "user_creation detector enabled"
            );
            UserCreationDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        systemd_persistence: cfg.detectors.systemd_persistence.enabled.then(|| {
            let d = &cfg.detectors.systemd_persistence;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "systemd_persistence detector enabled"
            );
            SystemdPersistenceDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        ransomware: cfg.detectors.ransomware.enabled.then(|| {
            let d = &cfg.detectors.ransomware;
            info!(
                file_threshold = d.file_threshold,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                entropy_threshold = d.entropy_threshold,
                entropy_count_threshold = d.entropy_count_threshold,
                "ransomware detector enabled"
            );
            RansomwareDetector::new(
                &cfg.agent.host_id,
                d.file_threshold,
                d.window_seconds,
                d.cooldown_seconds,
                d.entropy_threshold,
                d.entropy_count_threshold,
            )
        }),
        credential_harvest: cfg.detectors.credential_harvest.enabled.then(|| {
            let d = &cfg.detectors.credential_harvest;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "credential_harvest detector enabled"
            );
            CredentialHarvestDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        packet_flood: cfg.detectors.packet_flood.enabled.then(|| {
            let d = &cfg.detectors.packet_flood;
            info!(
                syn_threshold = d.syn_threshold,
                http_threshold = d.http_threshold,
                slowloris_threshold = d.slowloris_threshold,
                udp_threshold = d.udp_threshold,
                rate_multiplier = d.rate_multiplier,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "packet_flood detector enabled (DDoS detection)"
            );
            PacketFloodDetector::new(detectors::packet_flood::PacketFloodParams {
                host: cfg.agent.host_id.clone(),
                syn_threshold: d.syn_threshold,
                http_threshold: d.http_threshold,
                slowloris_threshold: d.slowloris_threshold,
                udp_threshold: d.udp_threshold,
                rate_multiplier: d.rate_multiplier,
                window_seconds: d.window_seconds,
                cooldown_seconds: d.cooldown_seconds,
            })
        }),
        sensitive_write: Some({
            info!("sensitive_write detector enabled (sensitive path protection)");
            detectors::sensitive_write::SensitiveWriteDetector::new(&cfg.agent.host_id, 300)
        }),
        io_uring_anomaly: Some({
            info!("io_uring_anomaly detector enabled (io_uring evasion detection)");
            detectors::io_uring_anomaly::IoUringAnomalyDetector::new(&cfg.agent.host_id, 300)
        }),
        container_drift: Some({
            info!("container_drift detector enabled (overlayfs drift detection)");
            detectors::container_drift::ContainerDriftDetector::new(&cfg.agent.host_id, 600)
        }),
        host_drift: Some({
            info!("host_drift detector enabled (non-standard binary execution)");
            detectors::host_drift::HostDriftDetector::new(&cfg.agent.host_id, 600)
        }),
        data_exfil_ebpf: Some({
            info!("data_exfil_ebpf detector enabled (sensitive file read + outbound connect)");
            detectors::data_exfil_ebpf::DataExfilEbpfDetector::new(&cfg.agent.host_id, 60, 600)
        }),
        yara_scan: Some({
            let rules_dir = std::path::Path::new("rules/yara");
            info!("YARA binary scanner enabled");
            detectors::yara_scan::YaraScanDetector::new(&cfg.agent.host_id, rules_dir, 3600)
        }),
        sigma_rule: Some({
            let rules_dir = std::path::Path::new("rules/sigma");
            info!("Sigma rule engine enabled");
            detectors::sigma_rule::SigmaRuleDetector::new(&cfg.agent.host_id, rules_dir, 300)
        }),
    };

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector =
            AuthLogCollector::new(&cfg.collectors.auth_log.path, &cfg.agent.host_id, offset);
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        let shared = Arc::clone(&shared_auth_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2, shared).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if cfg.collectors.integrity.enabled && !cfg.collectors.integrity.paths.is_empty() {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Seed shared hashes with whatever we loaded from state
        *shared_integrity_hashes.lock().unwrap() = known_hashes.clone();

        // Always monitor Inner Warden's own config files for tampering,
        // regardless of user configuration.
        let self_monitor_paths = [
            "/etc/innerwarden/config.toml",
            "/etc/innerwarden/agent.toml",
            "/etc/innerwarden/agent.env",
        ];
        let mut all_paths: Vec<std::path::PathBuf> =
            ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        for sp in &self_monitor_paths {
            let p = Path::new(sp).to_owned();
            if !all_paths.contains(&p) {
                all_paths.push(p);
            }
        }

        let collector = IntegrityCollector::new(
            all_paths.clone(),
            &cfg.agent.host_id,
            ic.poll_seconds,
            known_hashes,
        );
        info!(
            paths = all_paths.len(),
            poll_secs = ic.poll_seconds,
            "starting integrity collector (includes self-monitoring)"
        );
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Spawn journald collector
    if cfg.collectors.journald.enabled {
        let jc = &cfg.collectors.journald;
        let cursor: Option<String> = state
            .get_cursor("journald")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        *shared_journald_cursor.lock().unwrap() = cursor.clone();
        let collector = JournaldCollector::new(&cfg.agent.host_id, jc.units.clone(), cursor);
        info!(units = ?jc.units, "starting journald collector");
        let tx4 = tx.clone();
        let shared = Arc::clone(&shared_journald_cursor);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx4, shared).await {
                tracing::error!("journald collector error: {e:#}");
            }
        });
    }

    // Spawn docker collector
    if cfg.collectors.docker.enabled {
        let since: Option<String> = state
            .get_cursor("docker")
            .and_then(|v| v.as_str().map(str::to_string));
        *shared_docker_since.lock().unwrap() = since.clone();
        let collector = DockerCollector::new(&cfg.agent.host_id, since);
        info!("starting docker collector");
        let tx5 = tx.clone();
        let shared = Arc::clone(&shared_docker_since);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx5, shared).await {
                tracing::error!("docker collector error: {e:#}");
            }
        });
    }

    // Spawn exec_audit collector
    if cfg.collectors.exec_audit.enabled {
        let ec = &cfg.collectors.exec_audit;
        let offset = state
            .get_cursor("exec_audit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_exec_audit_offset.store(offset, Ordering::Relaxed);
        let collector =
            ExecAuditCollector::new(&ec.path, &cfg.agent.host_id, offset, ec.include_tty);
        info!(
            path = %ec.path,
            include_tty = ec.include_tty,
            offset,
            "starting exec_audit collector"
        );
        let tx6 = tx.clone();
        let shared = Arc::clone(&shared_exec_audit_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx6, shared).await {
                tracing::error!("exec_audit collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_access collector
    if cfg.collectors.nginx_access.enabled {
        let nc = &cfg.collectors.nginx_access;
        let offset = state
            .get_cursor("nginx_access")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_offset.store(offset, Ordering::Relaxed);
        let collector = NginxAccessCollector::new(&nc.path, &cfg.agent.host_id, offset);
        info!(path = %nc.path, offset, "starting nginx_access collector");
        let tx7 = tx.clone();
        let shared = Arc::clone(&shared_nginx_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx7, shared).await {
                tracing::error!("nginx_access collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_error collector
    if cfg.collectors.nginx_error.enabled {
        let nec = &cfg.collectors.nginx_error;
        let offset = state
            .get_cursor("nginx_error")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_error_offset.store(offset, Ordering::Relaxed);
        let collector = NginxErrorCollector::new(&nec.path, &cfg.agent.host_id, offset);
        info!(path = %nec.path, offset, "starting nginx_error collector");
        let tx_nginx_error = tx.clone();
        let shared = Arc::clone(&shared_nginx_error_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_nginx_error, shared).await {
                tracing::error!("nginx_error collector error: {e:#}");
            }
        });
    }

    // Spawn suricata_eve collector
    if cfg.collectors.suricata_eve.enabled {
        let sc = &cfg.collectors.suricata_eve;
        let offset = state
            .get_cursor("suricata_eve")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_suricata_offset.store(offset, Ordering::Relaxed);
        let collector =
            SuricataEveCollector::new(&sc.path, &cfg.agent.host_id, offset, sc.event_types.clone());
        info!(
            path = %sc.path,
            event_types = ?sc.event_types,
            offset,
            "starting suricata_eve collector"
        );
        let tx_suricata = tx.clone();
        let shared = Arc::clone(&shared_suricata_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_suricata, shared).await {
                tracing::error!("suricata_eve collector error: {e:#}");
            }
        });
    }

    // Spawn osquery_log collector
    if cfg.collectors.osquery_log.enabled {
        let oc = &cfg.collectors.osquery_log;
        let offset = state
            .get_cursor("osquery_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_osquery_offset.store(offset, Ordering::Relaxed);
        let collector = OsqueryLogCollector::new(&oc.path, &cfg.agent.host_id, offset);
        info!(path = %oc.path, offset, "starting osquery_log collector");
        let tx_osquery = tx.clone();
        let shared = Arc::clone(&shared_osquery_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_osquery, shared).await {
                tracing::error!("osquery_log collector error: {e:#}");
            }
        });
    }

    // Spawn macos_log collector
    if cfg.collectors.macos_log.enabled {
        let collector = MacosLogCollector::new(&cfg.agent.host_id);
        info!("starting macos_log collector");
        let tx_macos = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_macos).await {
                tracing::error!("macos_log collector error: {e:#}");
            }
        });
    }

    // Spawn wazuh_alerts collector
    if cfg.collectors.wazuh_alerts.enabled {
        let wc = &cfg.collectors.wazuh_alerts;
        let offset = state
            .get_cursor("wazuh_alerts")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_wazuh_offset.store(offset, Ordering::Relaxed);
        let collector = WazuhAlertsCollector::new(&wc.path, &cfg.agent.host_id, offset);
        info!(path = %wc.path, offset, "starting wazuh_alerts collector");
        let tx_wazuh = tx.clone();
        let shared = Arc::clone(&shared_wazuh_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_wazuh, shared).await {
                tracing::error!("wazuh_alerts collector error: {e:#}");
            }
        });
    }

    // Spawn syslog_firewall collector
    if cfg.collectors.syslog_firewall.enabled {
        let sc = &cfg.collectors.syslog_firewall;
        let offset = state
            .get_cursor("syslog_firewall")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_syslog_firewall_offset.store(offset, Ordering::Relaxed);
        let collector = SyslogFirewallCollector::new(&sc.path, &cfg.agent.host_id, offset);
        info!(path = %sc.path, offset, "starting syslog_firewall collector");
        let tx_syslog = tx.clone();
        let shared = Arc::clone(&shared_syslog_firewall_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_syslog, shared).await {
                tracing::error!("syslog_firewall collector error: {e:#}");
            }
        });
    }

    // Spawn cloudtrail collector
    if cfg.collectors.cloudtrail.enabled {
        let cc = &cfg.collectors.cloudtrail;
        let collector = CloudTrailCollector::new(&cc.dir, &cfg.agent.host_id);
        info!(dir = %cc.dir, "starting cloudtrail collector");
        let tx_cloudtrail = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_cloudtrail).await {
                tracing::error!("cloudtrail collector error: {e:#}");
            }
        });
    }

    // Spawn eBPF collector (optional - requires Linux 5.8+, CAP_BPF)
    {
        let tx_ebpf = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::ebpf_syscall::run(tx_ebpf, host_id).await;
        });
    }

    // Spawn firmware integrity collector (monitors ESP, UEFI vars, ACPI, DMI, tainted)
    {
        let tx_firmware = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::firmware_integrity::run(tx_firmware, host_id).await;
        });
    }

    // Spawn proc_maps collector (memory forensics: RWX, deleted files, LD_PRELOAD)
    {
        let tx_maps = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::proc_maps::run(tx_maps, host_id, 60).await;
        });
    }

    // Spawn fanotify filesystem monitor (real-time file modification + ransomware detection)
    {
        let tx_fan = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let watch_paths = cfg
            .collectors
            .integrity
            .paths
            .iter()
            .map(|p| p.to_string())
            .collect();
        tokio::spawn(async move {
            collectors::fanotify_watch::run(tx_fan, host_id, watch_paths, 5).await;
        });
    }

    // Spawn kernel integrity monitor (syscall table + eBPF inventory + module baseline)
    {
        let tx_kern = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::kernel_integrity::run(tx_kern, host_id, 120).await;
        });
    }

    // Spawn cgroup resource abuse detector (CPU/memory abuse, cryptominer detection)
    {
        let tx_cg = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            detectors::cgroup_abuse::run(tx_cg, host_id, 30).await;
        });
    }

    // Spawn TLS fingerprint collector (JA3/JA4 — requires CAP_NET_RAW on Linux)
    {
        let tx_tls = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tls_fingerprint::run(tx_tls, host_id, 0).await;
        });
    }

    // Drop the original tx - each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);

    // SIGTERM listener (Unix only)
    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // Main loop: drain events, run detectors, write output
    let mut stats = WriteStats::default();

    // Flush every 5 seconds regardless of event count
    let mut flush_ticker = time::interval(time::Duration::from_secs(5));
    flush_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    'main: loop {
        // Receive next event or signal
        #[cfg(unix)]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received - shutting down");
                break 'main;
            }
            _ = flush_ticker.tick() => {
                if let Err(e) = writer.flush() {
                    warn!("periodic flush failed: {e:#}");
                }
                continue 'main;
            }
        };

        #[cfg(not(unix))]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
            _ = flush_ticker.tick() => {
                if let Err(e) = writer.flush() {
                    warn!("periodic flush failed: {e:#}");
                }
                continue 'main;
            }
        };

        let Some(ev) = received else {
            info!("all collectors stopped");
            break 'main;
        };

        // Publish event to Redis stream (if enabled)
        #[cfg(feature = "redis-sink")]
        if let Some(ref mut rw) = redis_writer {
            if let Err(e) = rw.write_event(&ev).await {
                warn!(kind = %ev.kind, "Redis publish failed: {e:#}");
            }
        }

        process_event(ev, &mut writer, &mut detectors, &mut stats, &mut syslog_writer);

        // Also flush every 50 events as a safety net
        if stats.events_written > 0 && stats.events_written % 50 == 0 {
            if let Err(e) = writer.flush() {
                warn!("count-based flush failed: {e:#}");
            }
        }
    }

    writer.flush()?;
    info!(
        events_written = stats.events_written,
        incidents_written = stats.incidents_written,
        "flushed output"
    );

    // Persist collector state using the latest values from the shared Arcs
    let auth_offset = shared_auth_offset.load(Ordering::Relaxed);
    state.set_cursor("auth_log", serde_json::json!(auth_offset));

    let integrity_hashes = shared_integrity_hashes.lock().unwrap().clone();
    if !integrity_hashes.is_empty() {
        state.set_cursor("integrity", serde_json::to_value(&integrity_hashes)?);
    }

    if let Some(cursor) = shared_journald_cursor.lock().unwrap().clone() {
        state.set_cursor("journald", serde_json::json!(cursor));
    }

    if let Some(since) = shared_docker_since.lock().unwrap().clone() {
        state.set_cursor("docker", serde_json::json!(since));
    }

    let exec_audit_offset = shared_exec_audit_offset.load(Ordering::Relaxed);
    state.set_cursor("exec_audit", serde_json::json!(exec_audit_offset));

    let nginx_offset = shared_nginx_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_access", serde_json::json!(nginx_offset));

    let nginx_error_offset = shared_nginx_error_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_error", serde_json::json!(nginx_error_offset));

    let suricata_offset = shared_suricata_offset.load(Ordering::Relaxed);
    state.set_cursor("suricata_eve", serde_json::json!(suricata_offset));

    let osquery_offset = shared_osquery_offset.load(Ordering::Relaxed);
    state.set_cursor("osquery_log", serde_json::json!(osquery_offset));

    let wazuh_offset = shared_wazuh_offset.load(Ordering::Relaxed);
    state.set_cursor("wazuh_alerts", serde_json::json!(wazuh_offset));

    let syslog_firewall_offset = shared_syslog_firewall_offset.load(Ordering::Relaxed);
    state.set_cursor("syslog_firewall", serde_json::json!(syslog_firewall_offset));

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

/// Sources that already performed their own detection.
/// High/Critical events from these sources are promoted directly to incidents
/// without going through an InnerWarden detector.
fn is_passthrough_source(source: &str) -> bool {
    matches!(source, "suricata" | "wazuh")
}

fn process_event(
    ev: innerwarden_core::event::Event,
    writer: &mut JsonlWriter,
    detectors: &mut DetectorSet,
    stats: &mut WriteStats,
    syslog: &mut Option<sinks::syslog_cef::SyslogCefWriter>,
) {
    use innerwarden_core::event::Severity;

    info!(kind = %ev.kind, summary = %ev.summary, "event");
    if let Err(e) = writer.write_event(&ev) {
        warn!(kind = %ev.kind, "failed to write event: {e:#}");
    } else {
        stats.events_written += 1;
    }
    // Syslog CEF output (if configured)
    if let Some(ref mut cef) = syslog {
        cef.write_event(&ev);
    }

    // LSM blocked execution → immediate Critical incident.
    // The eBPF LSM hook already validated the kill chain pattern in-kernel;
    // promote directly to incident so the agent can auto-enable enforcement,
    // execute the kill-chain-response skill, and notify.
    if ev.kind == "lsm.exec_blocked" {
        use innerwarden_core::incident::Incident;
        let pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let comm = ev
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let filename = ev
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let incident = Incident {
            ts: ev.ts,
            host: ev.host.clone(),
            incident_id: format!("lsm:kill_chain:{}:{}",
                pid, ev.ts.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::Critical,
            title: format!("Kill chain blocked: {comm} (PID {pid})"),
            summary: format!(
                "Kernel LSM blocked execution: process {comm} (PID {pid}) attempted to run {filename} \
                 after accumulating kill chain flags. The attack was prevented at kernel level before \
                 the new process image was loaded."
            ),
            evidence: serde_json::json!([ev.details]),
            recommended_checks: vec![
                "Investigate the parent process that accumulated the kill chain".to_string(),
                "Check network connections from this PID for C2 communication".to_string(),
                "Review other processes from the same user/session".to_string(),
            ],
            tags: ev.tags.clone(),
            entities: ev.entities.clone(),
        };
        write_incident(writer, stats, incident);
    }

    // Incident passthrough: tools that already ran their own detection
    // (Falco, Suricata) emit High/Critical events that are incidents by definition.
    if is_passthrough_source(&ev.source) {
        let is_actionable = matches!(ev.severity, Severity::High | Severity::Critical);
        if is_actionable {
            if let Some(incident) = passthrough_incident(&ev) {
                write_incident(writer, stats, incident);
            }
        }
        // Passthrough sources don't need InnerWarden detectors - return early.
        return;
    }

    if let Some(ref mut det) = detectors.ssh {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.credential_stuffing {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.port_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.sudo_abuse {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.search_abuse {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.web_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.user_agent_scanner {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.execution_guard {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.suricata_alert {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.docker_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.integrity_alert {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.log_tampering {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.osquery_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.distributed_ssh {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.suspicious_login {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.c2_callback {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.process_tree {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.container_escape {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.privesc {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.fileless {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.dns_tunneling {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.lateral_movement {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.crypto_miner {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.outbound_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.rootkit {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.reverse_shell {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.ssh_key_injection {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.web_shell {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.kernel_module_load {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.crontab_persistence {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.data_exfiltration {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.process_injection {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.user_creation {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.systemd_persistence {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.ransomware {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.credential_harvest {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.packet_flood {
        for incident in det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.sensitive_write {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.io_uring_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.container_drift {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.host_drift {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.data_exfil_ebpf {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.yara_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }

    if let Some(ref mut det) = detectors.sigma_rule {
        if let Some(incident) = det.process(&ev) {
            write_incident(writer, stats, incident);
        }
    }
}

/// Build an Incident directly from an event emitted by a passthrough source
/// (Falco, Suricata). The external tool already detected the threat; this
/// promotes it into InnerWarden's incident pipeline for AI triage and response.
fn passthrough_incident(
    ev: &innerwarden_core::event::Event,
) -> Option<innerwarden_core::incident::Incident> {
    use innerwarden_core::incident::Incident;

    let incident_id = format!(
        "{}:{}:{}",
        ev.source,
        ev.kind,
        ev.ts.format("%Y-%m-%dT%H:%MZ")
    );

    let recommended_checks = match ev.source.as_str() {
        "suricata" => vec![
            "Review Suricata IDS signature".to_string(),
            "Check network flow context in eve.json".to_string(),
            "Consider blocking source IP if attack pattern confirmed".to_string(),
        ],
        "wazuh" => vec![
            "Review Wazuh alert rule and level".to_string(),
            "Check agent logs for additional context".to_string(),
            "Consider blocking source IP if attack pattern confirmed".to_string(),
        ],
        _ => vec!["Review source alert details".to_string()],
    };

    Some(Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id,
        severity: ev.severity.clone(),
        title: ev.summary.clone(),
        summary: format!("[{}] {}", ev.source.to_uppercase(), ev.summary),
        evidence: serde_json::json!([ev.details]),
        recommended_checks,
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    })
}

fn write_incident(
    writer: &mut JsonlWriter,
    stats: &mut WriteStats,
    incident: innerwarden_core::incident::Incident,
) {
    info!(
        incident_id = %incident.incident_id,
        severity = ?incident.severity,
        title = %incident.title,
        "INCIDENT"
    );
    if let Err(e) = writer.write_incident(&incident) {
        warn!(incident_id = %incident.incident_id, "failed to write incident: {e:#}");
    } else {
        stats.incidents_written += 1;
        // Note: Syslog CEF incident writing is handled in process_event scope
    }
}
