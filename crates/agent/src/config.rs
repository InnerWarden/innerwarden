use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_core::event::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub narrative: NarrativeConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub correlation: CorrelationConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub responder: ResponderConfig,
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NarrativeConfig {
    /// Generate daily Markdown summaries (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of daily summaries to keep before removing older ones
    #[serde(default = "default_keep_days")]
    pub keep_days: usize,
}

impl Default for NarrativeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_days: default_keep_days(),
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WebhookConfig {
    /// Enable webhook notifications
    #[serde(default)]
    pub enabled: bool,

    /// HTTP endpoint to POST incident payloads to
    #[serde(default)]
    pub url: String,

    /// Minimum severity to notify (default: "medium")
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Request timeout in seconds (default: 10)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: default_min_severity(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

impl WebhookConfig {
    /// Parse min_severity string into a Severity, defaulting to Medium on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised min_severity — defaulting to 'medium'"
                );
                Severity::Medium
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AI provider
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AiConfig {
    /// Enable AI-powered real-time incident analysis
    #[serde(default)]
    pub enabled: bool,

    /// AI provider to use: "openai" | "anthropic" (coming soon) | "ollama" (coming soon)
    #[serde(default = "default_ai_provider")]
    pub provider: String,

    /// API key for the provider. Prefer env var OPENAI_API_KEY / ANTHROPIC_API_KEY.
    #[serde(default)]
    pub api_key: String,

    /// Model identifier (provider-specific, e.g. "gpt-4o-mini")
    #[serde(default = "default_ai_model")]
    pub model: String,

    /// Number of recent events sent as context to the AI
    #[serde(default = "default_context_events")]
    pub context_events: usize,

    /// Minimum AI confidence (0.0–1.0) required to auto-execute a decision
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Poll interval for the fast incident-check loop (seconds)
    #[serde(default = "default_incident_poll_secs")]
    pub incident_poll_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_ai_provider(),
            api_key: String::new(),
            model: default_ai_model(),
            context_events: default_context_events(),
            confidence_threshold: default_confidence_threshold(),
            incident_poll_secs: default_incident_poll_secs(),
        }
    }
}

impl AiConfig {
    /// Resolve the API key: config field takes precedence, then env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        // Try provider-specific env vars
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Temporal correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CorrelationConfig {
    /// Enable lightweight temporal incident correlation (window + entity pivots)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Correlation window in seconds
    #[serde(default = "default_correlation_window_secs")]
    pub window_seconds: u64,

    /// Max number of related incidents attached to AI context
    #[serde(default = "default_max_related_incidents")]
    pub max_related_incidents: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: default_correlation_window_secs(),
            max_related_incidents: default_max_related_incidents(),
        }
    }
}

// ---------------------------------------------------------------------------
// Operational telemetry
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TelemetryConfig {
    /// Enable local operational telemetry JSONL output
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// Honeypot
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HoneypotConfig {
    /// Honeypot mode:
    /// - `demo`: synthetic marker only (safe default)
    /// - `listener`: starts bounded real decoys (ssh/http) with optional redirect
    #[serde(default = "default_honeypot_mode")]
    pub mode: String,

    /// Bind address used in listener mode
    #[serde(default = "default_honeypot_bind_addr")]
    pub bind_addr: String,

    /// Listener port used in listener mode
    #[serde(default = "default_honeypot_port")]
    pub port: u16,

    /// Listener lifetime in seconds used in listener mode
    #[serde(default = "default_honeypot_duration_secs")]
    pub duration_secs: u64,

    /// Enabled decoy services in listener mode.
    /// Supported: `ssh`, `http`.
    #[serde(default = "default_honeypot_services")]
    pub services: Vec<String>,

    /// HTTP decoy port used when `http` service is enabled.
    #[serde(default = "default_honeypot_http_port")]
    pub http_port: u16,

    /// Accept only connections from the action target IP.
    #[serde(default = "default_true")]
    pub strict_target_only: bool,

    /// Allow binding listener on non-loopback addresses.
    /// Default false for safer isolation.
    #[serde(default)]
    pub allow_public_listener: bool,

    /// Hard cap of accepted honeypot connections per session.
    #[serde(default = "default_honeypot_max_connections")]
    pub max_connections: usize,

    /// Max inbound payload bytes captured per connection.
    #[serde(default = "default_honeypot_max_payload_bytes")]
    pub max_payload_bytes: usize,

    /// Isolation profile for listener mode:
    /// - `strict_local` (default): hard guardrails for safer operation
    /// - `standard`: keeps only baseline guards
    #[serde(default = "default_honeypot_isolation_profile")]
    pub isolation_profile: String,

    /// Require non-privileged listener ports (>= 1024).
    #[serde(default = "default_true")]
    pub require_high_ports: bool,

    /// Retain honeypot forensics artifacts for this many days.
    #[serde(default = "default_honeypot_forensics_keep_days")]
    pub forensics_keep_days: usize,

    /// Hard cap for total honeypot forensics storage in MB.
    #[serde(default = "default_honeypot_forensics_max_total_mb")]
    pub forensics_max_total_mb: usize,

    /// Max bytes to render as readable transcript preview in evidence lines.
    #[serde(default = "default_honeypot_transcript_preview_bytes")]
    pub transcript_preview_bytes: usize,

    /// Consider active session lock stale after this many seconds.
    #[serde(default = "default_honeypot_lock_stale_secs")]
    pub lock_stale_secs: u64,

    #[serde(default)]
    pub sandbox: HoneypotSandboxConfig,

    #[serde(default)]
    pub pcap_handoff: HoneypotPcapHandoffConfig,

    #[serde(default)]
    pub redirect: HoneypotRedirectConfig,
}

#[derive(Debug, Deserialize)]
pub struct HoneypotSandboxConfig {
    /// Run decoy listeners in dedicated subprocess workers.
    #[serde(default)]
    pub enabled: bool,

    /// Optional absolute path to runner binary.
    /// Empty means current innerwarden-agent executable.
    #[serde(default)]
    pub runner_path: String,

    /// Clear environment for sandbox workers.
    #[serde(default = "default_true")]
    pub clear_env: bool,
}

impl Default for HoneypotSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runner_path: String::new(),
            clear_env: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotPcapHandoffConfig {
    /// Run bounded pcap capture at session end.
    #[serde(default)]
    pub enabled: bool,

    /// Capture timeout in seconds.
    #[serde(default = "default_honeypot_pcap_timeout_secs")]
    pub timeout_secs: u64,

    /// Max captured packets.
    #[serde(default = "default_honeypot_pcap_max_packets")]
    pub max_packets: u64,
}

impl Default for HoneypotPcapHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_honeypot_pcap_timeout_secs(),
            max_packets: default_honeypot_pcap_max_packets(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotRedirectConfig {
    /// Enable selective redirection rules for target IP.
    #[serde(default)]
    pub enabled: bool,

    /// Redirect backend (`iptables` for now).
    #[serde(default = "default_honeypot_redirect_backend")]
    pub backend: String,
}

impl Default for HoneypotRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_honeypot_redirect_backend(),
        }
    }
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_mode(),
            bind_addr: default_honeypot_bind_addr(),
            port: default_honeypot_port(),
            duration_secs: default_honeypot_duration_secs(),
            services: default_honeypot_services(),
            http_port: default_honeypot_http_port(),
            strict_target_only: default_true(),
            allow_public_listener: false,
            max_connections: default_honeypot_max_connections(),
            max_payload_bytes: default_honeypot_max_payload_bytes(),
            isolation_profile: default_honeypot_isolation_profile(),
            require_high_ports: default_true(),
            forensics_keep_days: default_honeypot_forensics_keep_days(),
            forensics_max_total_mb: default_honeypot_forensics_max_total_mb(),
            transcript_preview_bytes: default_honeypot_transcript_preview_bytes(),
            lock_stale_secs: default_honeypot_lock_stale_secs(),
            sandbox: HoneypotSandboxConfig::default(),
            pcap_handoff: HoneypotPcapHandoffConfig::default(),
            redirect: HoneypotRedirectConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ResponderConfig {
    /// Enable skill execution on AI decisions
    #[serde(default)]
    pub enabled: bool,

    /// Dry-run mode: log decisions but don't execute any system commands.
    /// Start with true for safety; set false when ready to auto-respond.
    #[serde(default = "default_true")]
    pub dry_run: bool,

    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables"
    #[serde(default = "default_block_backend")]
    pub block_backend: String,

    /// Whitelist of skill IDs the agent is allowed to execute automatically.
    /// Example: ["block-ip-ufw", "monitor-ip"]
    #[serde(default = "default_allowed_skills")]
    pub allowed_skills: Vec<String>,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: default_block_backend(),
            allowed_skills: default_allowed_skills(),
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load agent config from a TOML file.
/// If the file doesn't exist, returns `AgentConfig::default()`.
pub fn load(path: &Path) -> Result<AgentConfig> {
    if !path.exists() {
        return Ok(AgentConfig::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read agent config {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("failed to parse agent config {}", path.display()))
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_keep_days() -> usize {
    7
}

fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_ai_provider() -> String {
    "openai".to_string()
}

fn default_ai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_context_events() -> usize {
    20
}

fn default_confidence_threshold() -> f32 {
    0.8
}

fn default_incident_poll_secs() -> u64 {
    2
}

fn default_block_backend() -> String {
    "ufw".to_string()
}

fn default_correlation_window_secs() -> u64 {
    300
}

fn default_max_related_incidents() -> usize {
    8
}

fn default_allowed_skills() -> Vec<String> {
    vec!["block-ip-ufw".to_string(), "monitor-ip".to_string()]
}

fn default_honeypot_mode() -> String {
    "demo".to_string()
}

fn default_honeypot_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_honeypot_port() -> u16 {
    2222
}

fn default_honeypot_duration_secs() -> u64 {
    300
}

fn default_honeypot_services() -> Vec<String> {
    vec!["ssh".to_string()]
}

fn default_honeypot_http_port() -> u16 {
    8080
}

fn default_honeypot_max_connections() -> usize {
    64
}

fn default_honeypot_max_payload_bytes() -> usize {
    512
}

fn default_honeypot_isolation_profile() -> String {
    "strict_local".to_string()
}

fn default_honeypot_forensics_keep_days() -> usize {
    7
}

fn default_honeypot_forensics_max_total_mb() -> usize {
    128
}

fn default_honeypot_transcript_preview_bytes() -> usize {
    96
}

fn default_honeypot_lock_stale_secs() -> u64 {
    1800
}

fn default_honeypot_pcap_timeout_secs() -> u64 {
    15
}

fn default_honeypot_pcap_max_packets() -> u64 {
    120
}

fn default_honeypot_redirect_backend() -> String {
    "iptables".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn defaults_when_no_file() {
        let cfg = load(Path::new("/nonexistent/agent.toml")).unwrap();
        assert!(cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 7);
        assert!(!cfg.webhook.enabled);
        assert_eq!(cfg.webhook.min_severity, "medium");
        assert_eq!(cfg.webhook.timeout_secs, 10);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 300);
        assert_eq!(cfg.correlation.max_related_incidents, 8);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "demo");
        assert_eq!(cfg.honeypot.bind_addr, "127.0.0.1");
        assert_eq!(cfg.honeypot.port, 2222);
        assert_eq!(cfg.honeypot.duration_secs, 300);
        assert_eq!(cfg.honeypot.services, vec!["ssh".to_string()]);
        assert_eq!(cfg.honeypot.http_port, 8080);
        assert!(cfg.honeypot.strict_target_only);
        assert!(!cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 64);
        assert_eq!(cfg.honeypot.max_payload_bytes, 512);
        assert_eq!(cfg.honeypot.isolation_profile, "strict_local");
        assert!(cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 7);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 128);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 96);
        assert_eq!(cfg.honeypot.lock_stale_secs, 1800);
        assert!(!cfg.honeypot.sandbox.enabled);
        assert!(cfg.honeypot.sandbox.runner_path.is_empty());
        assert!(cfg.honeypot.sandbox.clear_env);
        assert!(!cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 15);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 120);
        assert!(!cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
    }

    #[test]
    fn parses_full_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[narrative]
enabled = false
keep_days = 3

[webhook]
enabled = true
url = "https://hooks.example.com/notify"
min_severity = "high"
timeout_secs = 5

[correlation]
enabled = true
window_seconds = 120
max_related_incidents = 4

[telemetry]
enabled = true

[honeypot]
mode = "listener"
bind_addr = "0.0.0.0"
port = 2223
duration_secs = 120
services = ["ssh", "http"]
http_port = 8088
strict_target_only = true
allow_public_listener = true
max_connections = 10
max_payload_bytes = 256
isolation_profile = "standard"
require_high_ports = false
forensics_keep_days = 14
forensics_max_total_mb = 512
transcript_preview_bytes = 192
lock_stale_secs = 600

[honeypot.sandbox]
enabled = true
runner_path = "/usr/local/bin/innerwarden-agent"
clear_env = false

[honeypot.pcap_handoff]
enabled = true
timeout_secs = 20
max_packets = 200

[honeypot.redirect]
enabled = true
backend = "iptables"
"#
        )
        .unwrap();

        let cfg = load(f.path()).unwrap();
        assert!(!cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 3);
        assert!(cfg.webhook.enabled);
        assert_eq!(cfg.webhook.url, "https://hooks.example.com/notify");
        assert_eq!(cfg.webhook.parsed_min_severity(), Severity::High);
        assert_eq!(cfg.webhook.timeout_secs, 5);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 120);
        assert_eq!(cfg.correlation.max_related_incidents, 4);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "listener");
        assert_eq!(cfg.honeypot.bind_addr, "0.0.0.0");
        assert_eq!(cfg.honeypot.port, 2223);
        assert_eq!(cfg.honeypot.duration_secs, 120);
        assert_eq!(
            cfg.honeypot.services,
            vec!["ssh".to_string(), "http".to_string()]
        );
        assert_eq!(cfg.honeypot.http_port, 8088);
        assert!(cfg.honeypot.strict_target_only);
        assert!(cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 10);
        assert_eq!(cfg.honeypot.max_payload_bytes, 256);
        assert_eq!(cfg.honeypot.isolation_profile, "standard");
        assert!(!cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 14);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 512);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 192);
        assert_eq!(cfg.honeypot.lock_stale_secs, 600);
        assert!(cfg.honeypot.sandbox.enabled);
        assert_eq!(
            cfg.honeypot.sandbox.runner_path,
            "/usr/local/bin/innerwarden-agent"
        );
        assert!(!cfg.honeypot.sandbox.clear_env);
        assert!(cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 20);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 200);
        assert!(cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
    }

    #[test]
    fn parsed_min_severity_unknown_defaults_to_medium() {
        let cfg = WebhookConfig {
            min_severity: "bogus".into(),
            ..Default::default()
        };
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }
}
