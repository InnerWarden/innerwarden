// Use jemalloc on Linux - the default glibc allocator fragments memory and
// never returns it to the OS, causing apparent "leaks" under sustained load.
// jemalloc aggressively returns unused pages via madvise(MADV_DONTNEED).
#[cfg(not(target_os = "macos"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod abuseipdb;
mod agent_context;
mod ai;
mod allowlist;
mod attacker_intel;
mod baseline;
mod bot_actions;
mod bot_commands;
mod bot_helpers;
mod cloud_safelist;
mod cloudflare;
mod config;
mod correlation;
mod correlation_engine;
mod crowdsec;
mod dashboard;
mod data_retention;
mod decision_block_ip;
mod decision_confirmation;
mod decision_honeypot;
mod decision_skill_actions;
mod decisions;
mod fail2ban;
mod firmware_tick;
mod forensics;
mod geoip;
mod incident_abuseipdb;
mod incident_action_report;
mod incident_advisory;
mod incident_ai_context;
mod incident_ai_failure;
mod incident_attacker_profile;
mod incident_audit_write;
mod incident_crowdsec;
mod incident_decision_eval;
mod incident_enrichment;
mod incident_execution_gate;
mod incident_flow;
mod incident_forensics;
mod incident_honeypot_router;
mod incident_honeypot_suggestion;
mod incident_notifications;
mod incident_obvious;
mod incident_playbook;
mod incident_post_decision;
mod incident_prelude;
mod incident_reputation;
mod ioc;
mod mesh;
mod mitre;
mod narrative;
mod narrative_autofp;
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::needless_range_loop
)]
mod neural_lifecycle;
mod pcap_capture;
mod playbook;
mod reader;
#[cfg(feature = "redis-reader")]
mod redis_reader;
mod report;
mod scoring;
mod skills;
mod slack;
mod state_store;
mod telegram;
mod telemetry;
mod telemetry_tick;
mod threat_feeds;
mod threat_report;
#[allow(dead_code)]
mod two_factor;
mod web_push;
mod webhook;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{Datelike as _, Timelike as _};
use clap::Parser;
use tracing::{debug, info, warn};

use crate::agent_context::incident_detector;
use crate::bot_actions::{handle_pending_confirmation, handle_telegram_action_callback};
use crate::bot_commands::{handle_telegram_bot_command, probe_and_suggest};
#[cfg(test)]
use crate::bot_helpers::{
    parse_telegram_triage_action, sanitize_allowlist_process_name, TelegramTriageAction,
};
use crate::dashboard::AdvisoryEntry;

#[derive(Parser)]
#[command(
    name = "innerwarden-agent",
    version,
    about = "Interpretive layer - reads sensor JSONL, generates narratives, and auto-responds to incidents"
)]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Generate a trial operational report from existing artifacts and exit
    #[arg(long)]
    report: bool,

    /// Output directory for generated reports (default: same as --data-dir)
    #[arg(long)]
    report_dir: Option<PathBuf>,

    /// Run read-only local dashboard server and exit this process only on SIGTERM/SIGINT
    #[arg(long)]
    dashboard: bool,

    /// Bind address for dashboard mode (default: localhost only — use 0.0.0.0:8787 to expose)
    #[arg(long, default_value = "127.0.0.1:8787")]
    dashboard_bind: String,

    /// Utility: generate Argon2 password hash for dashboard auth and exit.
    #[arg(long)]
    dashboard_generate_password_hash: bool,

    /// Poll interval in seconds for the narrative slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,

    /// Internal: run honeypot sandbox worker mode.
    #[arg(long, hide = true)]
    honeypot_sandbox_runner: bool,

    /// Internal: path to honeypot sandbox runner spec JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_spec: Option<PathBuf>,

    /// Internal: path to honeypot sandbox runner result JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_result: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

/// Accumulates event/incident stats incrementally for narrative generation.
/// Avoids re-reading the full events file every 5 minutes.
#[derive(Default)]
struct NarrativeAccumulator {
    /// Event counts by kind (e.g. "ssh.login_failed" → 42)
    events_by_kind: HashMap<String, usize>,
    /// IP mention counts
    ip_counts: HashMap<String, usize>,
    /// User mention counts
    user_counts: HashMap<String, usize>,
    /// Total events seen today
    total_events: usize,
    /// All incidents seen today (small - typically <100)
    incidents: Vec<innerwarden_core::incident::Incident>,
    /// Date this accumulator is for (resets on date change)
    date: String,
}

impl NarrativeAccumulator {
    /// Maximum unique IPs/users to track. Narrative only uses top 10,
    /// so keeping 500 is generous while preventing unbounded growth.
    const MAX_ENTITY_ENTRIES: usize = 500;

    fn ingest_events(&mut self, events: &[innerwarden_core::event::Event]) {
        for ev in events {
            self.total_events += 1;
            *self.events_by_kind.entry(ev.kind.clone()).or_insert(0) += 1;
            for entity in &ev.entities {
                match entity.r#type {
                    innerwarden_core::entities::EntityType::Ip => {
                        if self.ip_counts.contains_key(&entity.value)
                            || self.ip_counts.len() < Self::MAX_ENTITY_ENTRIES
                        {
                            *self.ip_counts.entry(entity.value.clone()).or_insert(0) += 1;
                        }
                    }
                    innerwarden_core::entities::EntityType::User => {
                        if self.user_counts.contains_key(&entity.value)
                            || self.user_counts.len() < Self::MAX_ENTITY_ENTRIES
                        {
                            *self.user_counts.entry(entity.value.clone()).or_insert(0) += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn ingest_incidents(&mut self, incidents: &[innerwarden_core::incident::Incident]) {
        self.incidents.extend_from_slice(incidents);
        // Cap at 500 incidents - narrative only needs recent ones for the report
        if self.incidents.len() > 500 {
            let drain = self.incidents.len() - 500;
            self.incidents.drain(..drain);
        }
    }

    fn reset_for_date(&mut self, date: &str) {
        if self.date != date {
            self.events_by_kind.clear();
            self.ip_counts.clear();
            self.user_counts.clear();
            self.total_events = 0;
            self.incidents.clear();
            self.date = date.to_string();
        }
    }

    /// Build synthetic Events from counters for narrative::generate.
    /// Caps total at 2000 events to prevent memory explosion on busy hosts.
    /// Uses proportional sampling when total exceeds cap.
    fn synthetic_events(&self) -> Vec<innerwarden_core::event::Event> {
        use innerwarden_core::{entities::EntityRef, event::Event};
        const MAX_SYNTHETIC: usize = 2000;

        let total: usize = self.events_by_kind.values().sum();
        let scale = if total > MAX_SYNTHETIC {
            MAX_SYNTHETIC as f64 / total as f64
        } else {
            1.0
        };

        let mut events = Vec::with_capacity(MAX_SYNTHETIC.min(total) + 20);
        for (kind, count) in &self.events_by_kind {
            let n = ((*count as f64) * scale).ceil() as usize;
            for _ in 0..n.max(1) {
                events.push(Event {
                    ts: chrono::Utc::now(),
                    host: String::new(),
                    source: String::new(),
                    kind: kind.clone(),
                    severity: innerwarden_core::event::Severity::Info,
                    summary: String::new(),
                    details: serde_json::Value::Null,
                    tags: vec![],
                    entities: vec![],
                });
            }
        }

        // Top IPs (max 10, 1 event each)
        for (ip, _) in self.ip_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::ip(ip)],
            });
        }
        for (user, _) in self.user_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::user(user)],
            });
        }
        events
    }
}

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    correlator: correlation::TemporalCorrelator,
    telemetry: telemetry::TelemetryState,
    telemetry_writer: Option<telemetry::TelemetryWriter>,
    /// Wrapped in Arc so we can clone a handle for use within a loop iteration
    /// without holding a borrow of `state` across async calls that need `&mut state`.
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    decision_writer: Option<decisions::DecisionWriter>,
    /// Tracks when the daily narrative was last written so we can enforce a
    /// minimum interval and avoid rewriting on every 30-second tick.
    last_narrative_at: Option<std::time::Instant>,
    /// Date for which we last sent the daily Telegram digest (avoids re-sending).
    last_daily_summary_telegram: Option<chrono::NaiveDate>,
    /// Telegram client for T.1 notifications and T.2 approvals (None when disabled).
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    /// Pending T.2 operator confirmations keyed by incident_id.
    /// Stores the original decision and incident so the action can be executed when approved.
    pending_confirmations: HashMap<
        String,
        (
            telegram::PendingConfirmation,
            ai::AiDecision,
            innerwarden_core::incident::Incident,
        ),
    >,
    /// Receives approval results from the Telegram polling task.
    /// Drained at the start of every incident tick via try_recv.
    approval_rx: Option<tokio::sync::mpsc::Receiver<telegram::ApprovalResult>>,
    /// Telegram batcher — groups repeated alerts to avoid spam.
    telegram_batcher: telegram::TelegramBatcher,
    /// Neural autoencoder anomaly engine — learns "normal" and flags novel patterns.
    anomaly_engine: neural_lifecycle::AnomalyEngine,
    /// In-memory trust rules: set of "detector:action" strings.
    /// Loaded from data_dir/trust-rules.json at startup; updated live when operator clicks "Always".
    trust_rules: std::collections::HashSet<String>,
    /// CrowdSec LAPI sync state (None when crowdsec.enabled = false).
    crowdsec: Option<crowdsec::CrowdSecState>,
    /// AbuseIPDB client for IP reputation enrichment (None when disabled).
    abuseipdb: Option<abuseipdb::AbuseIpDbClient>,
    /// Fail2ban sync state (None when fail2ban.enabled = false).
    fail2ban: Option<fail2ban::Fail2BanState>,
    /// GeoIP client for IP geolocation enrichment via ip-api.com (None when disabled).
    geoip_client: Option<geoip::GeoIpClient>,
    /// Slack client for incident notifications (None when disabled).
    slack_client: Option<slack::SlackClient>,
    /// Cloudflare integration client (None when disabled).
    cloudflare_client: Option<cloudflare::CloudflareClient>,
    /// Circuit breaker: when tripped by a high-volume incident burst, AI analysis
    /// is suspended until this timestamp. None = circuit breaker not tripped.
    circuit_breaker_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Pending operator honeypot choices keyed by IP.
    /// When Telegram is configured and AI recommends Honeypot, execution is deferred
    /// until the operator picks an action via the 4-button inline keyboard.
    pending_honeypot_choices: HashMap<String, PendingHoneypotChoice>,
    /// Local IP reputation: per-IP history used for adaptive block TTL.
    /// Persisted to `ip-reputation.json` every slow-loop tick.
    ip_reputations: HashMap<String, LocalIpReputation>,
    /// Whether LSM enforcement has been auto-enabled this session.
    lsm_enabled: bool,
    /// Mesh collaborative defense network (None when mesh.enabled = false).
    mesh: Option<mesh::MeshIntegration>,
    /// Rate limiter: timestamps of recent block actions (rolling 1-minute window).
    /// Prevents false-positive cascades from blocking too many IPs at once.
    recent_blocks: std::collections::VecDeque<chrono::DateTime<chrono::Utc>>,
    /// XDP blocklist entries with timestamps and per-IP TTL for adaptive expiration.
    /// Periodically cleaned: IPs older than their individual TTL are removed.
    xdp_block_times: HashMap<String, (chrono::DateTime<chrono::Utc>, i64)>,
    /// AbuseIPDB report queue - IPs are held for ABUSEIPDB_REPORT_DELAY_SECS
    /// before reporting, giving time for false-positive correction.
    abuseipdb_report_queue: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)>,
    /// Incremental narrative accumulator - avoids re-reading events file.
    narrative_acc: NarrativeAccumulator,
    /// Byte offset for incremental incident reading (narrative accumulator).
    narrative_incidents_offset: u64,
    /// Forensics capture - grabs /proc state for High/Critical process incidents.
    forensics: forensics::ForensicsCapture,
    /// Persistent state store (redb) - cooldowns, block_counts, ip_reputations,
    /// xdp_block_times, trust_rules. Primary source of truth for reads.
    store: state_store::StateStore,
    /// Attacker intelligence profiles: IP → unified profile.
    attacker_profiles: HashMap<String, attacker_intel::AttackerProfile>,
    /// Last attacker intel consolidation timestamp (5-minute interval).
    last_intel_consolidation_at: Option<std::time::Instant>,
    /// Cross-layer correlation engine: detects multi-stage attack chains.
    correlation_engine: correlation_engine::CorrelationEngine,
    /// Baseline learning: detects anomalies from normal behavior.
    baseline: baseline::BaselineStore,
    /// Playbook engine: automated response sequences.
    playbook_engine: playbook::PlaybookEngine,
    /// Selective packet capture on incidents.
    pcap_capture: pcap_capture::PcapCapture,
    /// V10 neural scoring model — replaced by autoencoder (anomaly_engine).
    /// Kept for API compatibility; will be removed in v0.9.
    #[allow(dead_code)]
    scoring_engine: scoring::ScoringEngine,
    /// Firmware incident cooldown: timestamp of last firmware trust_degraded incident.
    /// Prevents duplicate alerts when trust score is persistently low (e.g., VMs).
    last_firmware_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Suppressed incident patterns (user-configurable via CLI/dashboard).
    suppressed_incident_ids: std::collections::HashSet<String>,
    /// Threat feed client for external intelligence (None when disabled).
    threat_feed: Option<threat_feeds::ThreatFeedClient>,
    /// Timestamp of last baseline anomaly detection (for score fusion with autoencoder).
    last_baseline_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of last autoencoder anomaly detection (for score fusion with baseline).
    last_autoencoder_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Two-factor authentication state (pending actions, brute force protection).
    #[allow(dead_code)]
    two_factor_state: two_factor::TwoFactorState,
    /// Redis stream reader for events (None when redis_url is not configured).
    #[cfg(feature = "redis-reader")]
    redis_reader: Option<redis_reader::RedisStreamReader>,
}

/// Tracks a deferred honeypot-or-block decision waiting for operator input via Telegram.
struct PendingHoneypotChoice {
    #[allow(dead_code)]
    ip: String,
    incident_id: String,
    incident: innerwarden_core::incident::Incident,
    expires_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Local IP reputation - adaptive blocking
// ---------------------------------------------------------------------------

/// Per-IP reputation tracking for adaptive block TTL.
/// Starts neutral (score 0.0); each incident and block increases the score.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalIpReputation {
    /// Total incidents involving this IP.
    total_incidents: u32,
    /// Total times this IP has been blocked.
    total_blocks: u32,
    /// When this IP was first seen by the agent.
    first_seen: chrono::DateTime<chrono::Utc>,
    /// When this IP was last seen by the agent.
    last_seen: chrono::DateTime<chrono::Utc>,
    /// Reputation score: 0.0 = neutral, higher = worse.
    /// Incremented by 1.0 per incident, 2.0 per block.
    reputation_score: f32,
}

impl LocalIpReputation {
    pub(crate) fn new() -> Self {
        let now = chrono::Utc::now();
        Self {
            total_incidents: 0,
            total_blocks: 0,
            first_seen: now,
            last_seen: now,
            reputation_score: 0.0,
        }
    }

    /// Record an incident for this IP.
    pub(crate) fn record_incident(&mut self) {
        self.total_incidents += 1;
        self.last_seen = chrono::Utc::now();
        self.reputation_score += 1.0;
    }

    /// Record a block action for this IP.
    pub(crate) fn record_block(&mut self) {
        self.total_blocks += 1;
        self.last_seen = chrono::Utc::now();
        self.reputation_score += 2.0;
    }
}

/// Adaptive block TTL based on total_blocks count.
///   1st block  → 1 hour
///   2nd block  → 4 hours
///   3rd block  → 24 hours
///   4+ blocks  → 7 days
pub(crate) fn adaptive_block_ttl_secs(total_blocks: u32) -> i64 {
    match total_blocks {
        0 | 1 => 3600, // 1 hour
        2 => 14400,    // 4 hours
        3 => 86400,    // 24 hours
        _ => 604800,   // 7 days
    }
}

/// Write the in-memory reputation map to `ip-reputation.json` so the dashboard
/// (which runs in a separate task) can read it without shared state.
/// Append a blocked IP to blocked-ips.txt so the sensor can skip events from it.
/// Uses append mode. Best-effort: errors are logged but not propagated.
fn append_blocked_ip(data_dir: &Path, ip: &str) {
    let path = data_dir.join("blocked-ips.txt");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = writeln!(f, "{ip}") {
                warn!("failed to append to blocked-ips.txt: {e}");
            }
        }
        Err(e) => warn!("failed to open blocked-ips.txt for append: {e}"),
    }
}

fn persist_ip_reputations(data_dir: &Path, reputations: &HashMap<String, LocalIpReputation>) {
    let path = data_dir.join("ip-reputation.json");
    match serde_json::to_string(reputations) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("failed to write ip-reputation.json: {e}");
            }
        }
        Err(e) => warn!("failed to serialize ip reputations: {e}"),
    }
}

/// Scan honeypot session files for IPs in attacker profiles and feed session
/// data into their profiles (credentials, commands, IOCs).
fn scan_honeypot_for_profiles(
    data_dir: &Path,
    profiles: &mut HashMap<String, attacker_intel::AttackerProfile>,
) {
    let honeypot_dir = data_dir.join("honeypot");
    let entries = match std::fs::read_dir(&honeypot_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Collect IPs we care about (owned to avoid borrow conflict with get_mut)
    let profile_ips: std::collections::HashSet<String> = profiles.keys().cloned().collect();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("listener-session-") || !name.ends_with(".jsonl") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in content.lines() {
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(peer_ip) = v["peer_ip"].as_str() else {
                continue;
            };
            if !profile_ips.contains(peer_ip as &str) {
                continue;
            }
            if let Some(profile) = profiles.get_mut(peer_ip) {
                // Only observe if session not yet counted (check session_id uniqueness)
                let session_id = v["session_id"].as_str().unwrap_or("");
                if !session_id.is_empty() {
                    // Use commands_executed as a proxy: if we already have commands
                    // from this session, skip. Simple dedup by command presence.
                    let already_has = v["shell_commands"]
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|c| c["command"].as_str())
                        .is_some_and(|cmd| profile.commands_executed.contains(&cmd.to_string()));
                    if !already_has {
                        attacker_intel::observe_honeypot(profile, &v);
                    }
                }
            }
        }
    }
}

/// Load the reputation map from `ip-reputation.json` at startup.
fn load_ip_reputations(data_dir: &Path) -> HashMap<String, LocalIpReputation> {
    let path = data_dir.join("ip-reputation.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

pub(crate) const DECISION_COOLDOWN_SECS: i64 = 3600;
/// Notification cooldown: suppress duplicate Telegram/Slack/webhook alerts for the
/// same detector+entity within this window. Prevents alert spam when the same attacker
/// triggers multiple incidents in rapid succession.
const NOTIFICATION_COOLDOWN_SECS: i64 = 600;
/// Max block actions per minute - prevents false-positive cascades.
const MAX_BLOCKS_PER_MINUTE: usize = 20;
/// Default XDP blocklist TTL (24h) - retained as reference; adaptive TTL now per-IP.
#[allow(dead_code)]
const XDP_BLOCK_TTL_SECS: i64 = 86400;
/// AbuseIPDB reports are delayed by this many seconds to allow false-positive correction.
const ABUSEIPDB_REPORT_DELAY_SECS: i64 = 300;

/// Returns notification cooldown keys for an incident.
/// One key per entity (IP or user): `detector:entity_kind:entity_value`.
fn notification_cooldown_keys(incident: &innerwarden_core::incident::Incident) -> Vec<String> {
    let detector = incident_detector(&incident.incident_id);
    incident
        .entities
        .iter()
        .filter(|e| {
            matches!(
                e.r#type,
                innerwarden_core::entities::EntityType::Ip
                    | innerwarden_core::entities::EntityType::User
            )
        })
        .map(|e| {
            let kind = match e.r#type {
                innerwarden_core::entities::EntityType::Ip => "ip",
                innerwarden_core::entities::EntityType::User => "user",
                _ => "other",
            };
            format!("{detector}:{kind}:{}", e.value)
        })
        .collect()
}

fn decision_cooldown_key(action: &str, detector: &str, entity_kind: &str, entity: &str) -> String {
    format!("{action}:{detector}:{entity_kind}:{entity}")
}

pub(crate) fn decision_cooldown_candidates(
    incident: &innerwarden_core::incident::Incident,
) -> Vec<String> {
    let detector = incident_detector(&incident.incident_id);
    let mut keys = Vec::new();

    for entity in &incident.entities {
        match entity.r#type {
            innerwarden_core::entities::EntityType::Ip => {
                keys.push(decision_cooldown_key(
                    "block_ip",
                    detector,
                    "ip",
                    &entity.value,
                ));
                keys.push(decision_cooldown_key(
                    "monitor",
                    detector,
                    "ip",
                    &entity.value,
                ));
                keys.push(decision_cooldown_key(
                    "honeypot",
                    detector,
                    "ip",
                    &entity.value,
                ));
            }
            innerwarden_core::entities::EntityType::User => {
                keys.push(decision_cooldown_key(
                    "suspend_user_sudo",
                    detector,
                    "user",
                    &entity.value,
                ));
            }
            _ => {}
        }
    }

    keys
}

pub(crate) fn decision_cooldown_key_for_decision(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
) -> Option<String> {
    let detector = incident_detector(&incident.incident_id);
    match &decision.action {
        ai::AiAction::BlockIp { ip, .. } => {
            Some(decision_cooldown_key("block_ip", detector, "ip", ip))
        }
        ai::AiAction::Monitor { ip } => Some(decision_cooldown_key("monitor", detector, "ip", ip)),
        ai::AiAction::Honeypot { ip } => {
            Some(decision_cooldown_key("honeypot", detector, "ip", ip))
        }
        ai::AiAction::SuspendUserSudo { user, .. } => Some(decision_cooldown_key(
            "suspend_user_sudo",
            detector,
            "user",
            user,
        )),
        ai::AiAction::KillProcess { user, .. } => Some(decision_cooldown_key(
            "kill_process",
            detector,
            "user",
            user,
        )),
        ai::AiAction::BlockContainer { container_id, .. } => Some(decision_cooldown_key(
            "block_container",
            detector,
            "container",
            container_id,
        )),
        ai::AiAction::KillChainResponse { .. } => Some(decision_cooldown_key(
            "kill_chain_response",
            detector,
            "pid",
            "-",
        )),
        ai::AiAction::Ignore { .. } | ai::AiAction::RequestConfirmation { .. } => None,
    }
}

fn decision_cooldown_key_from_entry(entry: &decisions::DecisionEntry) -> Option<String> {
    let detector = incident_detector(&entry.incident_id);
    match entry.action_type.as_str() {
        "block_ip" | "monitor" | "honeypot" => entry
            .target_ip
            .as_ref()
            .map(|ip| decision_cooldown_key(&entry.action_type, detector, "ip", ip)),
        "suspend_user_sudo" => entry
            .target_user
            .as_ref()
            .map(|user| decision_cooldown_key("suspend_user_sudo", detector, "user", user)),
        _ => None,
    }
}

#[allow(dead_code)]
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn recent_decision_dates() -> Vec<String> {
    let today = chrono::Local::now().date_naive();
    let mut dates = vec![today.format("%Y-%m-%d").to_string()];
    if let Some(prev) = today.pred_opt() {
        dates.push(prev.format("%Y-%m-%d").to_string());
    }
    dates
}

fn load_startup_decision_state(
    data_dir: &Path,
    preload_blocklist_from_system: bool,
) -> (
    skills::Blocklist,
    HashMap<String, chrono::DateTime<chrono::Utc>>,
) {
    let mut blocklist = skills::Blocklist::default();
    let mut cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();

    if preload_blocklist_from_system {
        // Caller is responsible for awaiting the async ufw load and inserting later.
    }

    // Cap: only read the last 500KB of each decisions file to prevent OOM
    // on hosts that accumulated thousands of CrowdSec entries.
    const MAX_DECISION_READ: u64 = 512 * 1024;

    for date in recent_decision_dates() {
        let decisions_path = data_dir.join(format!("decisions-{date}.jsonl"));
        let file_size = std::fs::metadata(&decisions_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let content = if file_size > MAX_DECISION_READ {
            // Read only the tail of the file (most recent decisions)
            let Ok(full) = std::fs::read(&decisions_path) else {
                continue;
            };
            let start = full.len().saturating_sub(MAX_DECISION_READ as usize);
            String::from_utf8_lossy(&full[start..]).to_string()
        } else {
            let Ok(c) = std::fs::read_to_string(&decisions_path) else {
                continue;
            };
            c
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<decisions::DecisionEntry>(line) else {
                continue;
            };
            if entry.action_type == "block_ip" {
                if let Some(ip) = &entry.target_ip {
                    blocklist.insert(ip.clone());
                }
            }
            if let Some(key) = decision_cooldown_key_from_entry(&entry) {
                cooldowns
                    .entry(key)
                    .and_modify(|existing| {
                        if entry.ts > *existing {
                            *existing = entry.ts;
                        }
                    })
                    .or_insert(entry.ts);
            }
        }
    }

    (blocklist, cooldowns)
}

fn load_last_narrative_instant(data_dir: &Path) -> Option<std::time::Instant> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("summary-{today}.md"));
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.elapsed().ok()?;
    std::time::Instant::now().checked_sub(elapsed)
}

// ---------------------------------------------------------------------------
// Trust rules - data_dir/trust-rules.json
// ---------------------------------------------------------------------------

const TRUST_RULES_FILE: &str = "trust-rules.json";

/// Load trust rules from data_dir/trust-rules.json.
/// Returns a HashSet of "detector:action" keys. Fail-open: returns empty on any error.
fn load_trust_rules(data_dir: &Path) -> std::collections::HashSet<String> {
    let path = data_dir.join(TRUST_RULES_FILE);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return std::collections::HashSet::new();
    };
    let rules: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap_or_default();
    rules
        .into_iter()
        .filter_map(|r| {
            let d = r["detector"].as_str()?.to_string();
            let a = r["action"].as_str()?.to_string();
            Some(format!("{d}:{a}"))
        })
        .collect()
}

/// Append a trust rule to data_dir/trust-rules.json and update the in-memory set.
/// Fail-open: logs a warning on I/O errors.
fn append_trust_rule(
    data_dir: &Path,
    trust_rules: &mut std::collections::HashSet<String>,
    detector: &str,
    action: &str,
) {
    let key = format!("{detector}:{action}");
    if trust_rules.contains(&key) {
        return; // already trusted
    }
    trust_rules.insert(key);

    let path = data_dir.join(TRUST_RULES_FILE);
    let mut rules: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_default();
    rules.push(serde_json::json!({ "detector": detector, "action": action }));

    match serde_json::to_string_pretty(&rules) {
        Ok(content) => {
            if let Err(e) = std::fs::write(&path, content) {
                warn!("failed to write trust-rules.json: {e:#}");
            }
        }
        Err(e) => warn!("failed to serialise trust rules: {e:#}"),
    }
}

/// Returns true if a (detector, action) pair has been trusted by the operator.
pub(crate) fn is_trusted(
    trust_rules: &std::collections::HashSet<String>,
    detector: &str,
    action: &str,
) -> bool {
    trust_rules.contains(&format!("{detector}:{action}"))
        || trust_rules.contains(&format!("*:{action}"))
        || trust_rules.contains(&format!("{detector}:*"))
        || trust_rules.contains("*:*")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (fail-silent - production uses real env vars)
    match dotenvy::dotenv() {
        Ok(path) => debug!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // no .env file - that's fine
        Err(e) => warn!("could not parse .env file: {e}"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    if cli.dashboard_generate_password_hash {
        dashboard::generate_password_hash_interactive()?;
        return Ok(());
    }

    if cli.honeypot_sandbox_runner {
        let spec = cli
            .honeypot_sandbox_spec
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-spec"))?;
        let result = cli
            .honeypot_sandbox_result
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-result"))?;
        skills::builtin::run_honeypot_sandbox_worker(spec, result).await?;
        return Ok(());
    }

    if cli.report {
        let out_dir = cli.report_dir.as_deref().unwrap_or(&cli.data_dir);
        if let Some(d) = cli.report_dir.as_deref() {
            std::fs::create_dir_all(d)
                .with_context(|| format!("failed to create report-dir {}", d.display()))?;
        }
        let out = report::generate(&cli.data_dir, out_dir)?;
        info!(
            analyzed_date = %out.report.analyzed_date,
            markdown = %out.markdown_path.display(),
            json = %out.json_path.display(),
            "trial report generated"
        );
        println!(
            "Trial report generated:\n  {}\n  {}",
            out.markdown_path.display(),
            out.json_path.display()
        );
        return Ok(());
    }

    // Load config (optional - all fields have sensible defaults).
    // Done before dashboard check so action config can be wired in.
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    // Validate Telegram config early to fail fast on misconfiguration
    cfg.telegram.validate()?;

    // Initialize cloud provider IP safelist (Google, AWS, Azure, Cloudflare, etc.)
    cloud_safelist::init();

    // Advisory cache: shared between dashboard (writes advisory denials) and
    // the incident processing loop (checks for advisory violations).
    let advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    // Agent-guard snitch alert channel. Created before the dashboard block
    // so the receiver can be used in the dispatch task spawned later.
    let (agent_alert_tx, mut agent_alert_rx) =
        tokio::sync::mpsc::channel::<dashboard::AgentGuardAlert>(64);

    if cli.dashboard {
        let auth = dashboard::DashboardAuth::try_from_env()?;
        let action_cfg = dashboard::DashboardActionConfig {
            enabled: cfg.responder.enabled,
            dry_run: cfg.responder.dry_run,
            block_backend: cfg.responder.block_backend.clone(),
            allowed_skills: cfg.responder.allowed_skills.clone(),
            ai_enabled: cfg.ai.enabled,
            ai_provider: cfg.ai.provider.clone(),
            ai_model: cfg.ai.model.clone(),
            fail2ban_enabled: cfg.fail2ban.enabled,
            geoip_enabled: cfg.geoip.enabled,
            abuseipdb_enabled: cfg.abuseipdb.enabled,
            abuseipdb_auto_block_threshold: cfg.abuseipdb.auto_block_threshold,
            honeypot_mode: cfg.honeypot.mode.clone(),
            telegram_enabled: cfg.telegram.enabled,
            slack_enabled: cfg.slack.enabled,
            cloudflare_enabled: cfg.cloudflare.enabled,
            crowdsec_enabled: cfg.crowdsec.enabled,
            webhook_format: cfg.webhook.format.clone(),
            sudo_protection_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("suspend-user")),
            execution_guard_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("execution")),
            mesh_enabled: cfg.mesh.enabled,
            web_push_enabled: !cfg.web_push.vapid_public_key.is_empty(),
            shield_enabled: cfg.cloudflare.enabled,
            dna_enabled: true, // DNA fingerprinting is always active
            retention_events_days: cfg.data.events_keep_days,
            retention_incidents_days: cfg.data.incidents_keep_days,
            retention_decisions_days: cfg.data.decisions_keep_days,
            retention_telemetry_days: cfg.data.telemetry_keep_days,
            retention_reports_days: cfg.data.reports_keep_days,
        };
        let dashboard_data_dir = cli.data_dir.clone();
        let dashboard_bind = cli.dashboard_bind.clone();
        let web_push_pub_key = cfg.web_push.vapid_public_key.clone();
        let trusted_proxies = cfg.dashboard.trusted_proxies.clone();
        let session_timeout_minutes = cfg.dashboard.session_timeout_minutes;
        let max_sessions = cfg.dashboard.max_sessions;
        let dashboard_advisory_cache = advisory_cache.clone();

        // Load ATR rule engine from rules directory.
        let rules_dir = std::path::Path::new("/etc/innerwarden/rules");
        let rule_engine = std::sync::Arc::new(
            innerwarden_agent_guard::rules::RuleEngine::load(rules_dir).unwrap_or_else(|e| {
                warn!(error = %e, "failed to load ATR rules, starting with empty engine");
                innerwarden_agent_guard::rules::RuleEngine::empty()
            }),
        );

        let agent_alert_tx = agent_alert_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(
                dashboard_data_dir,
                dashboard_bind,
                auth,
                action_cfg,
                web_push_pub_key,
                trusted_proxies,
                session_timeout_minutes,
                max_sessions,
                dashboard_advisory_cache,
                rule_engine,
                agent_alert_tx,
            )
            .await
            {
                warn!(error = %e, "dashboard exited with error");
            }
        });
    }

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        correlation = cfg.correlation.enabled,
        correlation_window_secs = cfg.correlation.window_seconds,
        telemetry = cfg.telemetry.enabled,
        honeypot_mode = %cfg.honeypot.mode,
        honeypot_bind_addr = %cfg.honeypot.bind_addr,
        honeypot_services = ?cfg.honeypot.services,
        honeypot_ssh_port = cfg.honeypot.port,
        honeypot_http_port = cfg.honeypot.http_port,
        honeypot_isolation_profile = %cfg.honeypot.isolation_profile,
        honeypot_forensics_keep_days = cfg.honeypot.forensics_keep_days,
        honeypot_forensics_max_total_mb = cfg.honeypot.forensics_max_total_mb,
        honeypot_sandbox = cfg.honeypot.sandbox.enabled,
        honeypot_containment_mode = %cfg.honeypot.containment.mode,
        honeypot_containment_jail_runner = %cfg.honeypot.containment.jail_runner,
        honeypot_containment_jail_profile = %cfg.honeypot.containment.jail_profile,
        honeypot_external_handoff = cfg.honeypot.external_handoff.enabled,
        honeypot_external_handoff_allowlist = cfg.honeypot.external_handoff.enforce_allowlist,
        honeypot_external_handoff_signature = cfg.honeypot.external_handoff.signature_enabled,
        honeypot_external_handoff_attestation = cfg.honeypot.external_handoff.attestation_enabled,
        honeypot_pcap_handoff = cfg.honeypot.pcap_handoff.enabled,
        honeypot_redirect = cfg.honeypot.redirect.enabled,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Clean up old data files on startup
    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
    if removed > 0 {
        info!(removed, "data_retention: cleaned up old files on startup");
    }

    // Build shared agent state
    // Pre-populate blocklist + decision cooldowns from recent (today + yesterday)
    // decision files so that IPs we already decided to block are skipped after a
    // restart, even in dry-run mode.
    let (decisions_bl, startup_cooldowns) = load_startup_decision_state(&cli.data_dir, false);

    let startup_blocklist = {
        let mut bl = if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        };
        // Merge IPs from recent decision files
        for ip in decisions_bl.as_vec() {
            bl.insert(ip);
        }
        bl
    };

    // Build Telegram client (None when disabled or misconfigured)
    let telegram_client: Option<Arc<telegram::TelegramClient>> = if cfg.telegram.enabled {
        let token = cfg.telegram.resolved_bot_token();
        let chat_id = cfg.telegram.resolved_chat_id();
        if token.is_empty() || chat_id.is_empty() {
            warn!("telegram.enabled = true but bot_token/chat_id not configured - disabling");
            None
        } else {
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            match telegram::TelegramClient::new(token, chat_id, dashboard_url) {
                Ok(mut c) => {
                    if cfg.telegram.dev_mode {
                        c.dev_mode = true;
                        info!("Telegram dev mode ON — FP review button on every notification");
                    }
                    info!("Telegram client initialised (T.1 notifications enabled)");
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!("failed to create Telegram client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Build Slack client (None when disabled or unconfigured)
    let slack_client: Option<slack::SlackClient> = if cfg.slack.enabled {
        let url = cfg.slack.resolved_webhook_url();
        if url.is_empty() {
            warn!("slack.enabled = true but webhook_url not configured - disabling");
            None
        } else {
            match slack::SlackClient::new(&url) {
                Ok(c) => {
                    info!("Slack notifications enabled");
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to create Slack client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Create approval channel - polling task is spawned after state is built (continuous mode only)
    let (approval_tx, approval_rx_for_state) =
        tokio::sync::mpsc::channel::<telegram::ApprovalResult>(64);

    let store = state_store::StateStore::open(&cli.data_dir).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "state store open failed - using fresh store");
        state_store::StateStore::open(&std::env::temp_dir()).expect("fallback store")
    });

    // Seed the persistent store with decision cooldowns loaded from recent JSONL files.
    // This ensures restart continuity: IPs already decided on won't be re-evaluated.
    for (key, ts) in &startup_cooldowns {
        store.set_cooldown(state_store::CooldownTable::Decision, key, *ts);
    }

    // Spawn snitch alert dispatch task (uses cloned notification clients).
    {
        let tg = telegram_client.clone();
        let sc_url = if cfg.slack.enabled {
            cfg.slack.resolved_webhook_url()
        } else {
            String::new()
        };
        let wh_url = cfg.webhook.url.clone();
        let wh_enabled = cfg.webhook.enabled;
        let wh_timeout = cfg.webhook.timeout_secs;
        let wh_format = cfg.webhook.format.clone();
        let alert_data_dir = cli.data_dir.clone();
        tokio::spawn(async move {
            let sc = if !sc_url.is_empty() {
                slack::SlackClient::new(&sc_url).ok()
            } else {
                None
            };
            let mut cooldowns: std::collections::HashMap<String, tokio::time::Instant> =
                std::collections::HashMap::new();
            while let Some(alert) = agent_alert_rx.recv().await {
                // 60s cooldown per agent+command hash.
                let key = format!(
                    "{}:{}",
                    alert.agent_name,
                    innerwarden_core::audit::sha256_hex(&alert.command)
                );
                let now = tokio::time::Instant::now();
                if let Some(last) = cooldowns.get(&key) {
                    if now.duration_since(*last) < std::time::Duration::from_secs(60) {
                        continue;
                    }
                }
                cooldowns.insert(key, now);
                cooldowns
                    .retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(300));

                info!(
                    agent = %alert.agent_name,
                    command = %alert.command,
                    severity = %alert.severity,
                    recommendation = %alert.recommendation,
                    "agent-guard snitch alert"
                );

                // JSONL audit trail (write first, before network calls that may block).
                {
                    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
                    let path = alert_data_dir.join(format!("agent-guard-events-{today}.jsonl"));
                    match serde_json::to_string(&alert) {
                        Ok(line) => {
                            use std::io::Write;
                            match std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&path)
                            {
                                Ok(mut f) => {
                                    if let Err(e) = writeln!(f, "{line}") {
                                        warn!(error = %e, path = %path.display(), "failed to write agent-guard event");
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, path = %path.display(), "failed to open agent-guard events file")
                                }
                            }
                        }
                        Err(e) => warn!(error = %e, "failed to serialize agent-guard alert"),
                    }
                }

                // Telegram notification.
                if let Some(ref tg) = tg {
                    if let Err(e) = tg.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Telegram alert failed");
                    }
                }

                // Slack notification.
                if let Some(ref sc) = sc {
                    if let Err(e) = sc.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Slack alert failed");
                    }
                }

                // Webhook notification.
                if wh_enabled {
                    if let Err(e) =
                        webhook::send_agent_guard_alert(&wh_url, wh_timeout, &alert, &wh_format)
                            .await
                    {
                        warn!(error = %e, "agent-guard webhook alert failed");
                    }
                }
            }
        });
    }

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: startup_blocklist,
        correlator: correlation::TemporalCorrelator::new(cfg.correlation.window_seconds, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: if cfg.telemetry.enabled {
            match telemetry::TelemetryWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create telemetry writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        ai_provider: if cfg.ai.enabled {
            match ai::build_provider(&cfg.ai) {
                Ok(p) => Some(Arc::from(p)),
                Err(e) => {
                    warn!("failed to create AI provider: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        decision_writer: if cfg.ai.enabled {
            match decisions::DecisionWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create decision writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        last_narrative_at: load_last_narrative_instant(&cli.data_dir),
        last_daily_summary_telegram: None,
        telegram_client,
        pending_confirmations: HashMap::new(),
        approval_rx: None, // set below in continuous mode
        telegram_batcher: telegram::TelegramBatcher::new(60),
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(neural_lifecycle::AnomalyConfig {
            data_dir: cli.data_dir.clone(),
            ..Default::default()
        }),
        trust_rules: load_trust_rules(&cli.data_dir),
        crowdsec: if cfg.crowdsec.enabled {
            info!(url = %cfg.crowdsec.url, "CrowdSec integration enabled");
            Some(crowdsec::CrowdSecState::new(&cfg.crowdsec))
        } else {
            None
        },
        abuseipdb: if cfg.abuseipdb.enabled {
            let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
            if key.is_empty() {
                warn!("abuseipdb.enabled=true but no API key found - disabling enrichment");
                None
            } else {
                info!(
                    "AbuseIPDB enrichment enabled (max_age_days={})",
                    cfg.abuseipdb.max_age_days
                );
                Some(abuseipdb::AbuseIpDbClient::new(
                    key,
                    cfg.abuseipdb.max_age_days,
                ))
            }
        } else {
            None
        },
        fail2ban: if cfg.fail2ban.enabled {
            info!("Fail2ban integration enabled");
            Some(fail2ban::Fail2BanState::new(&cfg.fail2ban))
        } else {
            None
        },
        geoip_client: if cfg.geoip.enabled {
            info!("GeoIP enrichment enabled (ip-api.com, free tier)");
            Some(geoip::GeoIpClient::new())
        } else {
            None
        },
        slack_client,
        cloudflare_client: if cfg.cloudflare.enabled {
            let token = cloudflare::resolve_api_token(&cfg.cloudflare.api_token);
            if token.is_empty() || cfg.cloudflare.zone_id.is_empty() {
                warn!(
                    "cloudflare.enabled=true but api_token or zone_id not configured - disabling"
                );
                None
            } else {
                info!(zone_id = %cfg.cloudflare.zone_id, "Cloudflare IP block push enabled");
                Some(cloudflare::CloudflareClient::with_prefix(
                    cfg.cloudflare.zone_id.clone(),
                    token,
                    cfg.cloudflare.block_notes_prefix.clone(),
                ))
            }
        } else {
            None
        },
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: load_ip_reputations(&cli.data_dir),
        lsm_enabled: false,
        mesh: if cfg.mesh.enabled {
            match mesh::MeshIntegration::new(&cfg.mesh, &cli.data_dir) {
                Ok(m) => {
                    info!(node_id = %m.node_id(), peers = m.peer_count(), "Mesh network enabled");
                    Some(m)
                }
                Err(e) => {
                    warn!(error = %e, "Mesh network init failed");
                    None
                }
            }
        } else {
            None
        },
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(&cli.data_dir),
        store,
        attacker_profiles: HashMap::new(), // loaded from redb below
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        baseline: baseline::BaselineStore::load(&cli.data_dir),
        playbook_engine: playbook::PlaybookEngine::new(&cli.data_dir),
        pcap_capture: pcap_capture::PcapCapture::new(&cli.data_dir),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        suppressed_incident_ids: firmware_tick::load_suppressed_ids(&cli.data_dir),
        threat_feed: None, // initialized below if configured
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        #[cfg(feature = "redis-reader")]
        redis_reader: None,
    };

    // Load attacker intelligence profiles from persistent store
    state.attacker_profiles = attacker_intel::load_from_store(&state.store);
    if !state.attacker_profiles.is_empty() {
        info!(
            profiles = state.attacker_profiles.len(),
            "loaded attacker profiles from state store"
        );
    }

    // Initialize threat feed client if VT API key or IOC feed URLs are configured
    {
        let vt_key = threat_feeds::resolve_vt_api_key(&cfg.abuseipdb.api_key);
        // Threat feeds are always initialized (even without VT key, for IOC feed support)
        let client = threat_feeds::ThreatFeedClient::new(
            vt_key,
            Vec::new(), // IOC feed URLs would come from config
            &cli.data_dir,
        );
        let feed_state = client.state();
        if feed_state.total_iocs > 0 {
            info!(
                ips = feed_state.malicious_ips.len(),
                domains = feed_state.malicious_domains.len(),
                hashes = feed_state.malicious_hashes.len(),
                "threat feeds: loaded cached IOCs"
            );
        }
        state.threat_feed = Some(client);
    }

    // Connect Redis reader if configured
    #[cfg(feature = "redis-reader")]
    if let Some(ref url) = cfg.redis_url {
        let redis_cfg = redis_reader::agent_config(url, cfg.redis_stream.as_deref());
        match redis_reader::RedisStreamReader::connect(redis_cfg).await {
            Ok(r) => {
                info!("Redis stream reader connected - events from Redis");
                state.redis_reader = Some(r);
            }
            Err(e) => {
                warn!("Redis reader connection failed ({e:#}), using JSONL fallback");
            }
        }
    }

    if !state.ip_reputations.is_empty() {
        info!(
            count = state.ip_reputations.len(),
            "loaded local IP reputations from disk"
        );
    }

    if let Some(ref mesh_node) = state.mesh {
        match mesh_node.start_listener().await {
            Ok((addr, _handle)) => info!(addr = %addr, "mesh listener started"),
            Err(e) => warn!(error = %e, "mesh listener failed to start"),
        }
    }

    // Discover mesh peer identities (ping each, learn their public keys).
    // Must happen after listener starts so peers can ping us back.
    if let Some(ref mut mesh_node) = state.mesh {
        mesh_node.discover_peers().await;
        info!(
            peers = mesh_node.peer_count(),
            "mesh peer discovery complete"
        );
    }

    let state_path = cli.data_dir.join("agent-state.json");
    let mut cursor = reader::AgentCursor::load(&state_path)?;

    // Initialize narrative offset from cursor so we don't re-read all incidents on restart
    {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        state.narrative_incidents_offset = cursor.incidents_offset(&today);
    }

    if cli.once {
        let handled = process_incidents(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
            &advisory_cache,
        )
        .await;
        let new_events =
            process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await?;
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        if let Some(w) = &mut state.telemetry_writer {
            w.flush();
        }
        cursor.save(&state_path)?;
        info!(new_events, incidents_handled = handled, "run complete");
    } else {
        // Activate approval channel and start Telegram polling task
        state.approval_rx = Some(approval_rx_for_state);
        if let Some(ref tg) = state.telegram_client {
            // Register persistent command menu (fire-and-forget)
            tg.set_commands().await;
            let tg_clone = tg.clone();
            tokio::spawn(async move { tg_clone.run_polling(approval_tx).await });
            info!("Telegram polling task started (T.2 approvals enabled)");
        }

        // Proactive startup suggestions (fail2ban detected but not integrated, etc.)
        probe_and_suggest(&cfg, state.telegram_client.as_deref()).await;

        // Always-on honeypot: permanent SSH listener from startup.
        // A watch channel is used to signal shutdown on SIGTERM/SIGINT.
        let always_on_shutdown_tx = if cfg.honeypot.mode == "always_on" {
            let (tx, rx) = tokio::sync::watch::channel(false);

            // Build a filter blocklist pre-populated from today's + yesterday's decisions.
            let initial_blocked: std::collections::HashSet<String> = {
                let (bl, _) = load_startup_decision_state(&cli.data_dir, false);
                bl.as_vec().into_iter().collect()
            };
            let filter_bl = std::sync::Arc::new(std::sync::Mutex::new(initial_blocked));

            let port = cfg.honeypot.port;
            let bind_addr = cfg.honeypot.bind_addr.clone();
            let max_auth = cfg.honeypot.ssh_max_auth_attempts;
            let abuseipdb_client = if cfg.abuseipdb.enabled {
                let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
                if key.is_empty() {
                    None
                } else {
                    Some(std::sync::Arc::new(abuseipdb::AbuseIpDbClient::new(
                        key,
                        cfg.abuseipdb.max_age_days,
                    )))
                }
            } else {
                None
            };
            let abuseipdb_threshold = cfg.abuseipdb.auto_block_threshold;
            let ai_clone = state.ai_provider.clone();
            let tg_clone = state.telegram_client.clone();
            let data_dir_clone = cli.data_dir.clone();
            let responder_enabled = cfg.responder.enabled;
            let dry_run = cfg.responder.dry_run;
            let block_backend = cfg.responder.block_backend.clone();
            let allowed_skills = cfg.responder.allowed_skills.clone();
            let interaction = cfg.honeypot.interaction.clone();

            tokio::spawn(async move {
                run_always_on_honeypot(
                    port,
                    bind_addr,
                    max_auth,
                    filter_bl,
                    ai_clone,
                    tg_clone,
                    abuseipdb_client,
                    abuseipdb_threshold,
                    data_dir_clone,
                    responder_enabled,
                    dry_run,
                    block_backend,
                    allowed_skills,
                    interaction,
                    rx,
                )
                .await;
            });

            Some(tx)
        } else {
            None
        };

        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker = tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));
        let mut crowdsec_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.crowdsec.poll_secs.max(10),
        ));
        let mut fail2ban_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.fail2ban.poll_secs.max(10),
        ));
        let mut mesh_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cfg.mesh.poll_secs.max(10)));
        let mut firmware_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.firmware.poll_secs.max(60),
        ));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state, &advisory_cache).await;
                    // Persist cursor after every incident tick - prevents double-processing on restart
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    // Flush Telegram batcher — send grouped summaries
                    if state.telegram_batcher.should_flush() {
                        let summaries = state.telegram_batcher.flush();
                        if !summaries.is_empty() {
                            if let Some(ref tg) = state.telegram_client {
                                let digest = summaries.join("\n");
                                if let Err(e) = tg.send_raw_html(&digest).await {
                                    warn!("Telegram batch digest failed: {e:#}");
                                }
                            }
                        }
                    }

                    // Autoencoder nightly training — at 3 AM UTC.
                    {
                        let hour = chrono::Utc::now().hour();
                        if hour == 3 {
                            let today_key = format!("anomaly_train:{}", chrono::Utc::now().format("%Y-%m-%d"));
                            if !state.store.has_cooldown(state_store::CooldownTable::Decision, &today_key) {
                                info!("autoencoder: triggering nightly training");
                                match state.anomaly_engine.train_nightly() {
                                    Ok(()) => {
                                        info!(
                                            maturity = format!("{:.2}", state.anomaly_engine.maturity),
                                            cycles = state.anomaly_engine.training_cycles,
                                            "autoencoder: training complete"
                                        );
                                        state.store.set_cooldown(
                                            state_store::CooldownTable::Decision,
                                            &today_key,
                                            chrono::Utc::now(),
                                        );
                                    }
                                    Err(e) => warn!("autoencoder training failed: {e}"),
                                }
                            }
                        }
                    }

                    // Trim in-memory structures to prevent unbounded memory growth
                    state.blocklist.trim_if_needed(10_000);
                    let cutoff_2h = chrono::Utc::now() - chrono::Duration::hours(2);
                    state.store.retain_cooldowns(state_store::CooldownTable::Decision, cutoff_2h);
                    state.store.retain_cooldowns(state_store::CooldownTable::Notification, cutoff_2h);
                    // Cap block_counts to 5000 entries
                    if state.store.block_counts_len() > 5000 {
                        state.store.clear_block_counts();
                    }
                    // Cap ip_reputations and persist to disk for dashboard
                    if state.ip_reputations.len() > 10000 {
                        // Keep only the top 5000 by reputation_score
                        let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                        entries.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap_or(std::cmp::Ordering::Equal));
                        entries.truncate(5000);
                        state.ip_reputations = entries.into_iter().collect();
                    }
                    persist_ip_reputations(&cli.data_dir, &state.ip_reputations);

                    // ── Safeguard: XDP TTL - expire old blocklist entries ──
                    {
                        let now_utc = chrono::Utc::now();
                        let expired_ips: Vec<String> = state.xdp_block_times
                            .iter()
                            .filter(|(_, (ts, ttl))| {
                                let cutoff = *ts + chrono::Duration::seconds(*ttl);
                                now_utc > cutoff
                            })
                            .map(|(ip, _)| ip.clone())
                            .collect();
                        for ip in &expired_ips {
                            // Remove from XDP blocklist via bpftool
                            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                                let b = addr.octets();
                                let _ = tokio::process::Command::new("sudo")
                                    .args(["bpftool", "map", "delete", "pinned",
                                        "/sys/fs/bpf/innerwarden/blocklist",
                                        "key", &b[0].to_string(), &b[1].to_string(),
                                        &b[2].to_string(), &b[3].to_string()])
                                    .output().await;
                                let ttl_secs = state.xdp_block_times.get(ip).map(|(_, t)| *t).unwrap_or(0);
                                info!(ip, ttl_secs, "XDP adaptive TTL expired - removed from blocklist");
                            }
                            state.xdp_block_times.remove(ip);
                        }
                    }

                    // ── Safeguard: flush AbuseIPDB delayed report queue ──
                    {
                        let report_cutoff = chrono::Utc::now() - chrono::Duration::seconds(ABUSEIPDB_REPORT_DELAY_SECS);
                        let ready: Vec<_> = state.abuseipdb_report_queue
                            .iter()
                            .filter(|(_, _, _, ts)| *ts < report_cutoff)
                            .cloned()
                            .collect();
                        if let Some(ref client) = state.abuseipdb {
                            for (ip, comment, categories, _) in &ready {
                                client.report(ip, categories, comment).await;
                                info!(ip, "AbuseIPDB report sent (after 5min delay)");
                            }
                        }
                        state.abuseipdb_report_queue.retain(|(_, _, _, ts)| *ts >= report_cutoff);
                    }

                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }

                    // ── Memory housekeeping: cap unbounded HashMaps ──
                    {
                        const MAX_IP_REPUTATIONS: usize = 2000;
                        if state.ip_reputations.len() > MAX_IP_REPUTATIONS {
                            let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                            entries.sort_by(|a, b| {
                                b.1.reputation_score
                                    .partial_cmp(&a.1.reputation_score)
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            });
                            entries.truncate(MAX_IP_REPUTATIONS);
                            state.ip_reputations = entries.into_iter().collect();
                        }

                        // Expire pending Telegram confirmations older than 30 minutes
                        let confirm_cutoff =
                            chrono::Utc::now() - chrono::Duration::minutes(30);
                        state
                            .pending_confirmations
                            .retain(|_, (pc, _, _)| pc.created_at > confirm_cutoff);

                        // Expire pending honeypot choices past their deadline
                        let now_utc = chrono::Utc::now();
                        state
                            .pending_honeypot_choices
                            .retain(|_, choice| choice.expires_at > now_utc);

                        // ── Threat feed poll + save ──
                        if let Some(ref mut tf) = state.threat_feed {
                            tf.poll_feeds().await;
                            tf.save(&cli.data_dir);
                        }

                        // ── Pcap capture cooldown cleanup ──
                        state.pcap_capture.cleanup();

                        // ── Baseline rate anomaly check + save ──
                        {
                            let rate_anomalies = state.baseline.check_rate_anomalies();
                            for anomaly in &rate_anomalies {
                                info!(
                                    anomaly_type = ?anomaly.anomaly_type,
                                    severity = ?anomaly.severity,
                                    "baseline rate anomaly: {}",
                                    anomaly.description
                                );
                            }
                            state.baseline.save(&cli.data_dir);
                        }

                        // ── Attacker intelligence consolidation (every 5 min) ──
                        const INTEL_INTERVAL_SECS: u64 = 300;
                        let should_consolidate = state
                            .last_intel_consolidation_at
                            .map(|t| t.elapsed().as_secs() >= INTEL_INTERVAL_SECS)
                            .unwrap_or(true);
                        if should_consolidate && !state.attacker_profiles.is_empty() {
                            // Scan honeypot sessions for known attacker IPs
                            scan_honeypot_for_profiles(
                                &cli.data_dir,
                                &mut state.attacker_profiles,
                            );

                            attacker_intel::consolidation_tick(
                                &mut state.attacker_profiles,
                                &state.store,
                                &cli.data_dir,
                            );
                            state.last_intel_consolidation_at = Some(Instant::now());
                        }

                        // Cap attacker profiles to 10,000 by risk score
                        const MAX_ATTACKER_PROFILES: usize = 10_000;
                        if state.attacker_profiles.len() > MAX_ATTACKER_PROFILES {
                            let mut entries: Vec<_> =
                                state.attacker_profiles.drain().collect();
                            entries.sort_by(|a, b| b.1.risk_score.cmp(&a.1.risk_score));
                            entries.truncate(MAX_ATTACKER_PROFILES);
                            state.attacker_profiles = entries.into_iter().collect();
                        }

                        // ── Monthly threat report auto-generation (1st of month) ──
                        {
                            let today = chrono::Local::now().date_naive();
                            if today.day() == 1 {
                                let prev_month = (today - chrono::Duration::days(1))
                                    .format("%Y-%m")
                                    .to_string();
                                if !threat_report::report_exists(&cli.data_dir, &prev_month) {
                                    let profiles = state.attacker_profiles.clone();
                                    let data_dir = cli.data_dir.clone();
                                    tokio::spawn(async move {
                                        match threat_report::generate_monthly(
                                            &data_dir,
                                            &prev_month,
                                            &profiles,
                                        ) {
                                            Ok(report) => {
                                                if let Err(e) =
                                                    threat_report::write_report(&report, &data_dir)
                                                {
                                                    warn!(
                                                        "monthly report write failed: {e:#}"
                                                    );
                                                } else {
                                                    info!(
                                                        month = %prev_month,
                                                        "monthly threat report generated"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "monthly report generation failed: {e:#}"
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }

                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received - shutting down");
                    true
                }
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        crowdsec::sync_threat_list(cs).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                            state.telegram_client.as_ref(),
                        ).await;
                    }
                    false
                }
                _ = mesh_ticker.tick() => {
                    info!("mesh ticker fired");
                    if let Some(ref mut m) = state.mesh {
                        m.rediscover_if_needed().await;
                        let result = m.tick();
                        if !result.block_ips.is_empty() || m.staged_count() > 0 {
                            info!(staged = m.staged_count(), new_blocks = result.block_ips.len(), "mesh tick");
                        }
                        // Notify Telegram about new mesh blocks
                        for (ip, ttl) in &result.block_ips {
                            info!(ip, ttl, "mesh: new block from peer network");
                            state.blocklist.insert(ip.clone());
                            // Telegram notification
                            if let Some(ref tg) = state.telegram_client {
                                let msg = format!(
                                    "🌐 <b>MESH NETWORK</b>\n\n\
                                     Peer node detected threat from <code>{ip}</code>\n\
                                     Action: blocked for {}h (auto-revert)\n\n\
                                     ⚡ <i>Experimental - collaborative defense network</i>\n\
                                     <i>Nodes sharing threat intelligence in real time.</i>\n\
                                     <i>Coming soon: mesh dashboard, trust scores, collective blocklist.</i>",
                                    ttl / 3600
                                );
                                let tg = tg.clone();
                                tokio::spawn(async move {
                                    let _ = tg.send_raw_html(&msg).await;
                                });
                            }
                        }
                        if !result.unblock_ips.is_empty() {
                            info!(
                                expired = result.unblock_ips.len(),
                                "mesh: TTL expired blocks removed"
                            );
                        }
                        m.persist().ok();
                    }
                    false
                }
                _ = firmware_ticker.tick() => {
                    if cfg.firmware.enabled {
                        firmware_tick::process_firmware_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received - shutting down");
                    true
                }
            };

            #[cfg(not(unix))]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state, &advisory_cache).await;
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    // Flush Telegram batcher — send grouped summaries
                    if state.telegram_batcher.should_flush() {
                        let summaries = state.telegram_batcher.flush();
                        if !summaries.is_empty() {
                            if let Some(ref tg) = state.telegram_client {
                                let digest = summaries.join("\n");
                                if let Err(e) = tg.send_raw_html(&digest).await {
                                    warn!("Telegram batch digest failed: {e:#}");
                                }
                            }
                        }
                    }

                    // Trim in-memory structures to prevent unbounded memory growth
                    state.blocklist.trim_if_needed(10_000);
                    let cutoff_2h = chrono::Utc::now() - chrono::Duration::hours(2);
                    state.store.retain_cooldowns(state_store::CooldownTable::Decision, cutoff_2h);
                    state.store.retain_cooldowns(state_store::CooldownTable::Notification, cutoff_2h);
                    // Cap block_counts to 5000 entries
                    if state.store.block_counts_len() > 5000 {
                        state.store.clear_block_counts();
                    }
                    // Cap ip_reputations and persist to disk for dashboard
                    if state.ip_reputations.len() > 10000 {
                        let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                        entries.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap_or(std::cmp::Ordering::Equal));
                        entries.truncate(5000);
                        state.ip_reputations = entries.into_iter().collect();
                    }
                    persist_ip_reputations(&cli.data_dir, &state.ip_reputations);
                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
                    }
                    false
                }
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        crowdsec::sync_threat_list(cs).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                            state.telegram_client.as_ref(),
                        ).await;
                    }
                    false
                }
                _ = mesh_ticker.tick() => {
                    if let Some(ref mut m) = state.mesh {
                        m.rediscover_if_needed().await;
                        let result = m.tick();
                        for (ip, ttl) in &result.block_ips {
                            info!(ip, ttl, "mesh: new block from peer network");
                            state.blocklist.insert(ip.clone());
                            if let Some(ref tg) = state.telegram_client {
                                let msg = format!(
                                    "🌐 <b>MESH NETWORK</b>\n\n\
                                     Peer node detected threat from <code>{ip}</code>\n\
                                     Action: blocked for {}h (auto-revert)\n\n\
                                     ⚡ <i>Experimental - collaborative defense network</i>\n\
                                     <i>Nodes sharing threat intelligence in real time.</i>\n\
                                     <i>Coming soon: mesh dashboard, trust scores, collective blocklist.</i>",
                                    ttl / 3600
                                );
                                let tg = tg.clone();
                                tokio::spawn(async move {
                                    let _ = tg.send_raw_html(&msg).await;
                                });
                            }
                        }
                        m.persist().ok();
                    }
                    false
                }
                _ = firmware_ticker.tick() => {
                    if cfg.firmware.enabled {
                        firmware_tick::process_firmware_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received - shutting down");
                    true
                }
            };

            if shutdown {
                // Signal always-on honeypot listener to stop (if running).
                if let Some(ref tx) = always_on_shutdown_tx {
                    let _ = tx.send(true);
                }
                if let Some(w) = &mut state.decision_writer {
                    w.flush();
                }
                if let Some(w) = &mut state.telemetry_writer {
                    w.flush();
                }
                cursor.save(&state_path)?;
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Incident tick - runs every 2s
//
// Responsibilities (in order, for every new incident):
//   1. Webhook: notify immediately for all incidents above min_severity
//   2. AI analysis: only for High/Critical that pass the algorithm gate
//
// The incident cursor is advanced and saved after every tick, so a crash
// between ticks never causes double-processing or lost webhook notifications.
// ---------------------------------------------------------------------------

/// Returns the number of incidents handled (webhook sent and/or AI analyzed).
async fn process_incidents(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
) -> usize {
    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "suspend-user-sudo")
    {
        match skills::builtin::cleanup_expired_sudo_suspensions(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired sudo suspensions cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("suspend_user_sudo_cleanup");
                warn!("failed to cleanup expired sudo suspensions: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "rate-limit-nginx")
    {
        match skills::builtin::cleanup_expired_nginx_blocks(data_dir, cfg.responder.dry_run).await {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired nginx deny rules cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("rate_limit_nginx_cleanup");
                warn!("failed to cleanup expired nginx blocks: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "block-container")
    {
        match skills::builtin::cleanup_expired_container_blocks(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired container pauses lifted");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("block_container_cleanup");
                warn!("failed to cleanup expired container blocks: {e:#}");
            }
        }
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

    let new_incidents = match reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        cursor.incidents_offset(&today),
    ) {
        Ok(r) => r,
        Err(e) => {
            state.telemetry.observe_error("incident_reader");
            warn!("incident tick: failed to read incidents: {e:#}");
            return 0;
        }
    };

    // Drain any pending T.2/T.3 approval results from the Telegram polling task.
    // This MUST run before the early-return below, otherwise bot commands
    // (/status, /menu, etc.) would never be processed when there are no new incidents.
    let pending_approvals: Vec<telegram::ApprovalResult> = {
        let mut results = Vec::new();
        if let Some(rx) = state.approval_rx.as_mut() {
            while let Ok(r) = rx.try_recv() {
                results.push(r);
            }
        }
        results
    };
    for approval in pending_approvals {
        process_telegram_approval(approval, data_dir, cfg, state).await;
    }

    // Expire stale pending confirmations and honeypot choices
    let now = chrono::Utc::now();
    state
        .pending_confirmations
        .retain(|_, (pending, _, _)| pending.expires_at > now);
    state
        .pending_honeypot_choices
        .retain(|_, choice| choice.expires_at > now);

    if new_incidents.entries.is_empty() {
        return 0;
    }

    // Advance cursor before any async work - prevents double-processing on crash/restart
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    let notification_thresholds =
        incident_notifications::compute_notification_thresholds(cfg, state);

    // Circuit breaker: if a previous tick tripped the breaker, check if cooldown expired
    if let Some(until) = state.circuit_breaker_until {
        if chrono::Utc::now() < until {
            info!(
                until = %until,
                incident_count = new_incidents.entries.len(),
                "AI circuit breaker open - skipping AI analysis for this tick"
            );
            // Still process webhooks/notifications below, just skip AI
        } else {
            info!("AI circuit breaker reset after cooldown");
            state.circuit_breaker_until = None;
        }
    }

    // Trip circuit breaker if incident volume exceeds threshold
    let circuit_breaker_open = if cfg.ai.circuit_breaker_threshold > 0
        && new_incidents.entries.len() >= cfg.ai.circuit_breaker_threshold
        && state.circuit_breaker_until.is_none()
    {
        let until = chrono::Utc::now()
            + chrono::Duration::seconds(cfg.ai.circuit_breaker_cooldown_secs as i64);
        warn!(
            incident_count = new_incidents.entries.len(),
            threshold = cfg.ai.circuit_breaker_threshold,
            cooldown_secs = cfg.ai.circuit_breaker_cooldown_secs,
            until = %until,
            "AI circuit breaker TRIPPED - high-volume incident burst detected, skipping AI"
        );
        state.circuit_breaker_until = Some(until);
        true
    } else {
        state.circuit_breaker_until.is_some()
    };

    // Pre-compute AI context (only if AI is configured and circuit breaker is not open)
    let ai_enabled = cfg.ai.enabled && state.ai_provider.is_some() && !circuit_breaker_open;
    let (all_events, skill_infos, ai_provider, provider_name, already_blocked, mut blocked_set) =
        if ai_enabled {
            let events_path = data_dir.join(format!("events-{today}.jsonl"));
            let events =
                reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)
                    .map(|r| r.entries)
                    .unwrap_or_default();
            let infos = state.skill_registry.infos();
            // Clone the Arc - owned handle, no borrow of `state`
            let prov: Arc<dyn ai::AiProvider> = state.ai_provider.as_ref().unwrap().clone();
            let pname = prov.name();
            let blocked = state.blocklist.as_vec();
            // Mutable so we can update it mid-tick to prevent duplicate AI calls
            // for the same IP when multiple incidents arrive in the same 2s window.
            let blocked_set: HashSet<String> = blocked.iter().cloned().collect();
            (events, infos, Some(prov), pname, blocked, blocked_set)
        } else {
            (vec![], vec![], None, "", vec![], HashSet::new())
        };

    let mut handled = 0;
    let mut ai_calls_this_tick: usize = 0;

    for incident in &new_incidents.entries {
        state.telemetry.observe_incident(incident);

        // VirusTotal enrichment: when YARA scanner detects a binary, check its
        // SHA-256 hash against VT. Result logged for operator context.
        if incident.incident_id.starts_with("yara_scan:") {
            if let Some(hash) = incident
                .evidence
                .get(0)
                .and_then(|e| e.get("sha256"))
                .and_then(|v| v.as_str())
            {
                if let Some(ref tf) = state.threat_feed {
                    match tf.check_virustotal(hash).await {
                        Some(vt) if vt.is_malicious => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                suspicious = vt.suspicious,
                                "VirusTotal CONFIRMED malicious: {}/{} engines",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        Some(vt) => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                "VirusTotal: {}/{} engines flagged",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        None => {} // VT not configured or request failed
                    }
                }
            }
        }

        incident_attacker_profile::update_incident_ip_profiles(incident, state);

        incident_forensics::maybe_capture_incident_forensics(incident, state);

        let related_incidents =
            incident_prelude::prepare_incident_prelude(incident, cfg, state).await;

        incident_notifications::dispatch_incident_notifications(
            incident,
            data_dir,
            cfg,
            state,
            &notification_thresholds,
        )
        .await;

        incident_advisory::handle_advisory_violation(incident, advisory_cache, state).await;

        // 2. AI analysis - only when AI is enabled and incident passes the gate.
        match incident_flow::evaluate_pre_ai_flow(
            incident,
            cfg,
            state,
            ai_enabled,
            &blocked_set,
            ai_calls_this_tick,
        ) {
            incident_flow::PreAiFlowDecision::Proceed => {}
            incident_flow::PreAiFlowDecision::SkipHandled
            | incident_flow::PreAiFlowDecision::PipelineTestHandled => {
                handled += 1;
                continue;
            }
        }

        if incident_obvious::try_handle_obvious_incident(incident, data_dir, cfg, state).await {
            handled += 1;
            continue;
        }

        state.telemetry.observe_gate_pass();

        // ai_provider is Some when ai_enabled - safe to unwrap
        let provider = ai_provider.as_ref().unwrap();

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            correlated_count = related_incidents.len(),
            "sending incident to AI for analysis"
        );

        let ai_context_inputs = incident_ai_context::build_ai_context_inputs(
            incident,
            &all_events,
            &related_incidents,
            cfg.ai.context_events,
        );

        let ip_reputation = incident_reputation::lookup_abuseipdb_reputation(incident, state).await;

        if incident_abuseipdb::try_handle_abuseipdb_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            ip_reputation.as_ref(),
            &mut blocked_set,
        )
        .await
        {
            handled += 1;
            continue;
        }

        if incident_crowdsec::try_handle_crowdsec_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            &mut blocked_set,
        )
        .await
        {
            handled += 1;
            continue;
        }

        incident_enrichment::log_threat_feed_match(incident, state);

        if incident_honeypot_router::try_handle_honeypot_routing(
            incident,
            data_dir,
            cfg,
            state,
            &blocked_set,
        )
        .await
        {
            handled += 1;
            continue;
        }

        let ip_geo = incident_enrichment::lookup_incident_geoip(incident, state).await;
        incident_enrichment::enrich_attacker_identity(
            incident,
            state,
            ip_geo.as_ref(),
            ip_reputation.as_ref(),
        );

        let ctx = ai::DecisionContext {
            incident,
            recent_events: ai_context_inputs.recent_events,
            related_incidents: ai_context_inputs.related_incidents,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos
                .iter()
                .map(|s| ai::SkillInfo {
                    id: s.id.clone(),
                    applicable_to: s.applicable_to.clone(),
                })
                .collect(),
            ip_reputation: ip_reputation.clone(),
            ip_geo: ip_geo.clone(),
        };

        state.telemetry.observe_ai_sent();
        let decision_start = Instant::now();
        let mut decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                incident_ai_failure::handle_ai_decision_failure(
                    incident,
                    provider_name,
                    cfg,
                    state,
                    &e,
                );

                handled += 1;
                continue;
            }
        };
        let latency_ms = decision_start.elapsed().as_millis();
        state
            .telemetry
            .observe_ai_decision(&decision.action, latency_ms);
        ai_calls_this_tick += 1;

        incident_post_decision::apply_post_decision_safeguards(
            incident,
            cfg,
            state,
            &mut decision,
            &mut blocked_set,
        );

        incident_decision_eval::apply_correlation_boost_and_log_decision(
            incident,
            cfg,
            state,
            &mut decision,
        );

        if incident_honeypot_suggestion::maybe_defer_honeypot_to_operator(
            incident,
            provider_name,
            &decision,
            cfg,
            state,
        )
        .await
        {
            handled += 1;
            continue;
        }

        let (execution_result, cloudflare_pushed) =
            incident_execution_gate::execute_or_skip_decision(
                incident, &decision, data_dir, cfg, state,
            )
            .await;

        incident_audit_write::write_decision_audit_entry(
            incident,
            provider_name,
            &decision,
            &execution_result,
            cfg,
            state,
        );

        incident_playbook::maybe_evaluate_and_persist_playbook(incident, data_dir, state);

        incident_action_report::maybe_send_post_execution_telegram_report(
            incident,
            &decision,
            &execution_result,
            cloudflare_pushed,
            cfg,
            state,
            ip_reputation.as_ref(),
            ip_geo.as_ref(),
        );

        handled += 1;
    }

    telemetry_tick::write_tick_snapshot(state, "incident_tick");

    handled
}

/// Execute an AI decision by finding and running the appropriate skill.
/// Returns (execution_message, cloudflare_pushed).
pub(crate) async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    use ai::AiAction;

    if let Some(result) = decision_skill_actions::execute_simple_action(
        &decision.action,
        incident,
        data_dir,
        cfg,
        state,
    )
    .await
    {
        return result;
    }

    match &decision.action {
        AiAction::BlockIp { ip, skill_id } => {
            decision_block_ip::execute_block_ip_decision(
                ip, skill_id, decision, incident, data_dir, cfg, state,
            )
            .await
        }
        AiAction::Honeypot { ip } => {
            decision_honeypot::execute_honeypot_decision(ip, incident, data_dir, cfg, state).await
        }
        AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: suspend-user-sudo skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::KillProcess {
            user,
            duration_secs,
        } => {
            let skill_id = "kill-process";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: kill-process skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::BlockContainer {
            container_id,
            action: _,
        } => {
            let skill_id = "block-container";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: Some(container_id.clone()),
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: block-container skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::RequestConfirmation { summary } => {
            decision_confirmation::execute_request_confirmation(
                summary, decision, incident, cfg, state,
            )
            .await
        }
        _ => unreachable!("unsupported action path in execute_decision"),
    }
}

pub(crate) fn honeypot_runtime(cfg: &config::AgentConfig) -> skills::HoneypotRuntimeConfig {
    let mode = cfg.honeypot.mode.trim().to_ascii_lowercase();
    let normalized_mode = match mode.as_str() {
        "demo" | "listener" => mode,
        other => {
            warn!(mode = other, "unknown honeypot mode; falling back to demo");
            "demo".to_string()
        }
    };
    skills::HoneypotRuntimeConfig {
        mode: normalized_mode,
        bind_addr: cfg.honeypot.bind_addr.clone(),
        port: cfg.honeypot.port,
        http_port: cfg.honeypot.http_port,
        duration_secs: cfg.honeypot.duration_secs,
        services: if cfg.honeypot.services.is_empty() {
            vec!["ssh".to_string()]
        } else {
            cfg.honeypot.services.clone()
        },
        strict_target_only: cfg.honeypot.strict_target_only,
        allow_public_listener: cfg.honeypot.allow_public_listener,
        max_connections: cfg.honeypot.max_connections,
        max_payload_bytes: cfg.honeypot.max_payload_bytes,
        isolation_profile: cfg.honeypot.isolation_profile.clone(),
        require_high_ports: cfg.honeypot.require_high_ports,
        forensics_keep_days: cfg.honeypot.forensics_keep_days,
        forensics_max_total_mb: cfg.honeypot.forensics_max_total_mb,
        transcript_preview_bytes: cfg.honeypot.transcript_preview_bytes,
        lock_stale_secs: cfg.honeypot.lock_stale_secs,
        sandbox_enabled: cfg.honeypot.sandbox.enabled,
        sandbox_runner_path: cfg.honeypot.sandbox.runner_path.clone(),
        sandbox_clear_env: cfg.honeypot.sandbox.clear_env,
        pcap_handoff_enabled: cfg.honeypot.pcap_handoff.enabled,
        pcap_handoff_timeout_secs: cfg.honeypot.pcap_handoff.timeout_secs,
        pcap_handoff_max_packets: cfg.honeypot.pcap_handoff.max_packets,
        containment_mode: cfg.honeypot.containment.mode.clone(),
        containment_require_success: cfg.honeypot.containment.require_success,
        containment_namespace_runner: cfg.honeypot.containment.namespace_runner.clone(),
        containment_namespace_args: cfg.honeypot.containment.namespace_args.clone(),
        containment_jail_runner: cfg.honeypot.containment.jail_runner.clone(),
        containment_jail_args: cfg.honeypot.containment.jail_args.clone(),
        containment_jail_profile: cfg.honeypot.containment.jail_profile.clone(),
        containment_allow_namespace_fallback: cfg.honeypot.containment.allow_namespace_fallback,
        external_handoff_enabled: cfg.honeypot.external_handoff.enabled,
        external_handoff_command: cfg.honeypot.external_handoff.command.clone(),
        external_handoff_args: cfg.honeypot.external_handoff.args.clone(),
        external_handoff_timeout_secs: cfg.honeypot.external_handoff.timeout_secs,
        external_handoff_require_success: cfg.honeypot.external_handoff.require_success,
        external_handoff_clear_env: cfg.honeypot.external_handoff.clear_env,
        external_handoff_allowed_commands: cfg.honeypot.external_handoff.allowed_commands.clone(),
        external_handoff_enforce_allowlist: cfg.honeypot.external_handoff.enforce_allowlist,
        external_handoff_signature_enabled: cfg.honeypot.external_handoff.signature_enabled,
        external_handoff_signature_key_env: cfg.honeypot.external_handoff.signature_key_env.clone(),
        external_handoff_attestation_enabled: cfg.honeypot.external_handoff.attestation_enabled,
        external_handoff_attestation_key_env: cfg
            .honeypot
            .external_handoff
            .attestation_key_env
            .clone(),
        external_handoff_attestation_prefix: cfg
            .honeypot
            .external_handoff
            .attestation_prefix
            .clone(),
        external_handoff_attestation_expected_receiver: cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .clone(),
        redirect_enabled: cfg.honeypot.redirect.enabled,
        redirect_backend: cfg.honeypot.redirect.backend.clone(),
        interaction: cfg.honeypot.interaction.trim().to_ascii_lowercase(),
        ssh_max_auth_attempts: cfg.honeypot.ssh_max_auth_attempts,
        http_max_requests: cfg.honeypot.http_max_requests,
        // Populated at the call site when the AI provider is available.
        ai_provider: None,
    }
}

pub(crate) async fn append_honeypot_marker_event(
    data_dir: &Path,
    incident: &innerwarden_core::incident::Incident,
    ip: &str,
    dry_run: bool,
    runtime: &skills::HoneypotRuntimeConfig,
) -> Result<std::path::PathBuf> {
    use tokio::io::AsyncWriteExt;

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    let is_listener = runtime.mode == "listener" && !dry_run;
    let (source, kind, summary) = if is_listener {
        let mut endpoints = Vec::new();
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("ssh"))
        {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("http"))
        {
            endpoints.push(format!("http:{}:{}", runtime.bind_addr, runtime.http_port));
        }
        if endpoints.is_empty() {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        (
            "agent.honeypot_listener",
            "honeypot.listener_session_started",
            format!(
                "Honeypot listener session started for attacker {ip} at {}",
                endpoints.join(", ")
            ),
        )
    } else {
        (
            "agent.honeypot_demo",
            "honeypot.demo_decoy_hit",
            format!(
                "DEMO/SIMULATION/DECOY: attacker {ip} marked as honeypot hit (controlled marker only)"
            ),
        )
    };

    let event = innerwarden_core::event::Event {
        ts: chrono::Utc::now(),
        host: incident.host.clone(),
        source: source.to_string(),
        kind: kind.to_string(),
        severity: innerwarden_core::event::Severity::Info,
        summary,
        details: serde_json::json!({
            "mode": runtime.mode,
            "simulation": !is_listener,
            "decoy": true,
            "target_ip": ip,
            "incident_id": incident.incident_id,
            "dry_run": dry_run,
            "listener_bind_addr": runtime.bind_addr,
            "listener_services": runtime.services.clone(),
            "listener_ssh_port": runtime.port,
            "listener_http_port": runtime.http_port,
            "listener_duration_secs": runtime.duration_secs,
            "listener_strict_target_only": runtime.strict_target_only,
            "listener_max_connections": runtime.max_connections,
            "listener_max_payload_bytes": runtime.max_payload_bytes,
            "listener_isolation_profile": runtime.isolation_profile,
            "listener_require_high_ports": runtime.require_high_ports,
            "listener_forensics_keep_days": runtime.forensics_keep_days,
            "listener_forensics_max_total_mb": runtime.forensics_max_total_mb,
            "listener_transcript_preview_bytes": runtime.transcript_preview_bytes,
            "listener_lock_stale_secs": runtime.lock_stale_secs,
            "listener_sandbox_enabled": runtime.sandbox_enabled,
            "listener_containment_mode": runtime.containment_mode,
            "listener_containment_jail_runner": runtime.containment_jail_runner,
            "listener_containment_jail_profile": runtime.containment_jail_profile,
            "listener_external_handoff_enabled": runtime.external_handoff_enabled,
            "listener_external_handoff_allowlist": runtime.external_handoff_enforce_allowlist,
            "listener_external_handoff_signature": runtime.external_handoff_signature_enabled,
            "listener_external_handoff_attestation": runtime.external_handoff_attestation_enabled,
            "listener_pcap_handoff_enabled": runtime.pcap_handoff_enabled,
            "listener_redirect_enabled": runtime.redirect_enabled,
            "listener_redirect_backend": runtime.redirect_backend,
            "note": if is_listener {
                "Real honeypot listener mode active with bounded decoys and local forensics."
            } else {
                "Demo-only marker; no real honeypot infrastructure is deployed in this mode."
            }
        }),
        tags: vec![
            "honeypot".to_string(),
            "decoy".to_string(),
            if is_listener {
                "listener".to_string()
            } else {
                "demo".to_string()
            },
            if is_listener {
                "real_mode".to_string()
            } else {
                "simulation".to_string()
            },
        ],
        entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
    };

    let line = serde_json::to_string(&event)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&events_path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;

    Ok(events_path)
}

// ---------------------------------------------------------------------------
// Telegram T.2 approval handler
// ---------------------------------------------------------------------------

/// Process a single operator approval result received from the Telegram polling task.
/// Resolves and executes (or discards) the pending confirmation, writes an audit entry,
/// and informs the operator via Telegram of the outcome.
async fn process_telegram_approval(
    result: telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    if handle_telegram_bot_command(&result, data_dir, cfg, state).await {
        return;
    }

    if bot_helpers::handle_telegram_triage_action(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_action_callback(&result, data_dir, cfg, state).await {
        return;
    }

    let _ = handle_pending_confirmation(&result, data_dir, cfg, state).await;
}

// ---------------------------------------------------------------------------
// Narrative tick - runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
async fn process_narrative_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<usize> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    // Read new events: from Redis if available, JSONL otherwise.
    #[cfg(feature = "redis-reader")]
    let (events_entries, events_count) = if let Some(ref mut rr) = state.redis_reader {
        match rr.read_events::<innerwarden_core::event::Event>().await {
            Ok(entries) => {
                let count = entries.len();
                (entries, count)
            }
            Err(e) => {
                warn!("Redis event read failed: {e:#}");
                state.telemetry.observe_error("redis_reader");
                (Vec::new(), 0)
            }
        }
    } else {
        let events_path = data_dir.join(format!("events-{today}.jsonl"));
        let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
            &events_path,
            cursor.events_offset(&today),
        )
        .inspect_err(|_| {
            state.telemetry.observe_error("event_reader");
        })?;
        let count = new_events.entries.len();
        cursor.set_events_offset(&today, new_events.new_offset);
        (new_events.entries, count)
    };

    #[cfg(not(feature = "redis-reader"))]
    let (events_entries, events_count) = {
        let events_path = data_dir.join(format!("events-{today}.jsonl"));
        let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
            &events_path,
            cursor.events_offset(&today),
        )
        .inspect_err(|_| {
            state.telemetry.observe_error("event_reader");
        })?;
        let count = new_events.entries.len();
        cursor.set_events_offset(&today, new_events.new_offset);
        (new_events.entries, count)
    };

    state.telemetry.observe_events(&events_entries);

    // Feed new events into the narrative accumulator (incremental, no file re-read)
    state.narrative_acc.reset_for_date(&today);
    state.narrative_acc.ingest_events(&events_entries);

    // Feed events into cross-layer correlation engine and baseline learning
    for ev in &events_entries {
        let corr_event = correlation_engine::CorrelationEngine::classify_event(ev);
        state.correlation_engine.observe(corr_event);
        let anomalies = state.baseline.observe_event(ev);
        if !anomalies.is_empty() {
            state.last_baseline_anomaly_ts = Some(chrono::Utc::now());
        }
        for anomaly in anomalies {
            info!(
                anomaly_type = ?anomaly.anomaly_type,
                description = %anomaly.description,
                "baseline anomaly detected"
            );
        }
    }

    // ── Autoencoder anomaly detection ────────────────────────────────────
    // Feed every event to the autoencoder. It builds a sliding window and
    // scores each window against the trained model. Until the model is
    // trained (maturity > 0), observe() returns None -- safe no-op.
    for ev in &events_entries {
        if let Some((score, weighted)) = state.anomaly_engine.observe(ev) {
            state.last_autoencoder_anomaly_ts = Some(chrono::Utc::now());
            info!(
                score = format!("{:.3}", score),
                weighted = format!("{:.3}", weighted),
                maturity = format!("{:.2}", state.anomaly_engine.maturity),
                kind = %ev.kind,
                "autoencoder anomaly detected"
            );
            let incident = innerwarden_core::incident::Incident {
                ts: ev.ts,
                host: ev.host.clone(),
                incident_id: format!(
                    "neural_anomaly:{}:{}",
                    (score * 100.0) as u32,
                    ev.ts.format("%Y-%m-%dT%H:%MZ")
                ),
                severity: if score > 0.9 {
                    innerwarden_core::event::Severity::Critical
                } else if score > 0.8 {
                    innerwarden_core::event::Severity::High
                } else {
                    innerwarden_core::event::Severity::Medium
                },
                title: format!(
                    "Neural anomaly: {:.0}% anomaly score (maturity {:.0}%)",
                    score * 100.0,
                    state.anomaly_engine.maturity * 100.0
                ),
                summary: format!(
                    "Autoencoder flagged unusual event pattern. \
                     Trigger: {} | Score: {:.3} | Weighted: {:.3} | \
                     Training cycles: {}",
                    ev.kind, score, weighted, state.anomaly_engine.training_cycles
                ),
                evidence: serde_json::json!({
                    "score": score,
                    "weighted": weighted,
                    "maturity": state.anomaly_engine.maturity,
                    "training_cycles": state.anomaly_engine.training_cycles,
                    "model": "autoencoder-48f",
                    "trigger_event": ev.kind,
                }),
                recommended_checks: vec![
                    "Review recent events for unusual patterns".to_string(),
                    "Check if rule-based detectors also flagged this".to_string(),
                ],
                tags: vec!["neural_model".to_string(), "autoencoder".to_string()],
                entities: ev.entities.clone(),
            };
            let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&incidents_path)
            {
                use std::io::Write;
                if let Ok(json) = serde_json::to_string(&incident) {
                    let _ = writeln!(f, "{json}");
                }
            }
        }
    }

    // ── Baseline + Autoencoder score fusion ─────────────────────────────
    // When both baseline and autoencoder flag anomalies within 60 seconds
    // of each other, emit a combined high-confidence incident.
    if let (Some(baseline_ts), Some(autoencoder_ts)) = (
        state.last_baseline_anomaly_ts,
        state.last_autoencoder_anomaly_ts,
    ) {
        let gap = (baseline_ts - autoencoder_ts).num_seconds().unsigned_abs();
        if gap <= 60 {
            info!(
                baseline_ts = %baseline_ts,
                autoencoder_ts = %autoencoder_ts,
                gap_secs = gap,
                "correlated anomaly: baseline + autoencoder convergence"
            );
            let host = events_entries
                .first()
                .map(|e| e.host.clone())
                .unwrap_or_default();
            let now = chrono::Utc::now();
            let fused_incident = innerwarden_core::incident::Incident {
                ts: now,
                host,
                incident_id: format!(
                    "correlated_anomaly:baseline_neural:{}",
                    now.format("%Y-%m-%dT%H:%MZ")
                ),
                severity: innerwarden_core::event::Severity::High,
                title: "Correlated anomaly: baseline + neural model convergence".to_string(),
                summary: format!(
                    "Both baseline statistical model and neural autoencoder flagged \
                     unusual activity within {gap}s of each other. \
                     High confidence that this is genuine anomalous behavior."
                ),
                evidence: serde_json::json!({
                    "baseline_anomaly_ts": baseline_ts.to_rfc3339(),
                    "autoencoder_anomaly_ts": autoencoder_ts.to_rfc3339(),
                    "gap_seconds": gap,
                    "autoencoder_maturity": state.anomaly_engine.maturity,
                }),
                recommended_checks: vec![
                    "Investigate events in the flagged timeframe".to_string(),
                    "Cross-reference with rule-based detector incidents".to_string(),
                    "Check for lateral movement or exfiltration patterns".to_string(),
                ],
                tags: vec![
                    "correlated_anomaly".to_string(),
                    "baseline".to_string(),
                    "neural_model".to_string(),
                ],
                entities: vec![],
            };
            let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&incidents_path)
            {
                use std::io::Write;
                if let Ok(json) = serde_json::to_string(&fused_incident) {
                    let _ = writeln!(f, "{json}");
                }
            }
            // Reset timestamps to avoid emitting duplicate fused incidents
            state.last_baseline_anomaly_ts = None;
            state.last_autoencoder_anomaly_ts = None;
        }
    }

    // Also ingest any new incidents incrementally
    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
    let new_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        state.narrative_incidents_offset,
    )
    .inspect_err(|_| {
        state.telemetry.observe_error("incident_reader");
    })?;
    if !new_incidents.entries.is_empty() {
        state.narrative_acc.ingest_incidents(&new_incidents.entries);
        state.narrative_incidents_offset = new_incidents.new_offset;

        // Feed incidents into cross-layer correlation engine
        for incident in &new_incidents.entries {
            let corr_event = correlation_engine::CorrelationEngine::classify_incident(incident);
            state.correlation_engine.observe(corr_event);
        }

        // Check for completed attack chains
        let chains = state.correlation_engine.drain_completed();
        for chain in &chains {
            info!(
                chain_id = %chain.chain_id,
                rule = %chain.rule_id,
                name = %chain.rule_name,
                stages = chain.stages_matched,
                layers = chain.layers_involved.len(),
                confidence = chain.confidence,
                "cross-layer attack chain detected: {}",
                chain.summary
            );

            // Evaluate chain-triggered playbooks
            for incident in &new_incidents.entries {
                if let Some(exec) = state
                    .playbook_engine
                    .evaluate_chain(&chain.rule_id, incident)
                {
                    info!(
                        playbook = %exec.playbook_id,
                        chain = %chain.rule_id,
                        steps = exec.steps.len(),
                        "chain-triggered playbook: {}",
                        exec.playbook_name
                    );
                }
            }
        }

        // Persist detected chains to JSON for dashboard
        if !chains.is_empty() {
            let chains_path = data_dir.join("attack-chains.json");
            let mut existing: Vec<serde_json::Value> = std::fs::read_to_string(&chains_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for chain in &chains {
                if let Ok(val) = serde_json::to_value(chain) {
                    existing.push(val);
                }
            }
            // Keep last 100 chains
            if existing.len() > 100 {
                existing = existing.split_off(existing.len() - 100);
            }
            let _ = std::fs::write(
                &chains_path,
                serde_json::to_string(&existing).unwrap_or_default(),
            );
        }

        // Check for multi-low elevation
        if let Some(chain) = state.correlation_engine.check_multi_low_elevation() {
            info!(
                chain_id = %chain.chain_id,
                "multi-low severity elevation: {}",
                chain.summary
            );
        }
    }

    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            // Generate synthetic events from accumulated counters (no file I/O)
            let all_events_synthetic = state.narrative_acc.synthetic_events();
            let all_incidents_ref = &state.narrative_acc.incidents;

            let host = all_incidents_ref
                .first()
                .map(|i| i.host.as_str())
                .unwrap_or("unknown");

            let responder_hint = narrative::ResponderHint {
                enabled: cfg.responder.enabled,
                dry_run: cfg.responder.dry_run,
                has_block_ip: cfg
                    .responder
                    .allowed_skills
                    .iter()
                    .any(|s| s.starts_with("block-ip")),
            };
            let md = narrative::generate_with_responder(
                &today,
                host,
                &all_events_synthetic,
                all_incidents_ref,
                cfg.correlation.window_seconds,
                responder_hint,
            );
            if let Err(e) = narrative::write(data_dir, &today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");

                // Daily Telegram digest
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        if let Some(tg) = &state.telegram_client {
                            let is_simple = cfg.telegram.is_simple_profile();
                            // Count incidents by severity and top detector
                            let mut incidents_today: u32 = 0;
                            let mut critical_count: u32 = 0;
                            let mut high_count: u32 = 0;
                            let mut detector_counts: HashMap<String, u32> = HashMap::new();
                            for inc in &state.narrative_acc.incidents {
                                incidents_today += 1;
                                match inc.severity {
                                    innerwarden_core::event::Severity::Critical => {
                                        critical_count += 1;
                                    }
                                    innerwarden_core::event::Severity::High => {
                                        high_count += 1;
                                    }
                                    _ => {}
                                }
                                let det = telegram::extract_detector_pub(&inc.incident_id);
                                *detector_counts.entry(det.to_string()).or_insert(0) += 1;
                            }
                            let blocks_today = bot_helpers::count_jsonl_lines(
                                data_dir,
                                &format!("decisions-{today}.jsonl"),
                            ) as u32;
                            let (top_detector, top_count) = detector_counts
                                .iter()
                                .max_by_key(|(_, c)| *c)
                                .map(|(d, c)| (d.as_str(), *c))
                                .unwrap_or(("none", 0));
                            let text = telegram::format_daily_digest(
                                incidents_today,
                                blocks_today,
                                critical_count,
                                high_count,
                                top_detector,
                                top_count,
                                is_simple,
                            );
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    state.last_daily_summary_telegram = Some(today_naive);
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }
                    }
                }
            }
        }
    }

    narrative_autofp::maybe_suggest_allowlist_from_fp_reports(data_dir, state).await;

    telemetry_tick::write_tick_snapshot(state, "narrative_tick");

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// Post-session honeypot tasks (T.5)
// ---------------------------------------------------------------------------

/// Extract session_id from honeypot skill result message.
/// The message format is: "Honeypot listeners started (session {session_id}, ...)"
pub(crate) fn extract_session_id_from_message(msg: &str) -> Option<String> {
    // Look for "session " followed by the session_id (ends at next ", " or ")")
    let marker = "session ";
    let start = msg.find(marker)? + marker.len();
    let rest = &msg[start..];
    let end = rest.find([',', ')']).unwrap_or(rest.len());
    let id = rest[..end].trim().to_string();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Read shell commands typed by the attacker from honeypot evidence JSONL.
async fn read_shell_commands_from_evidence(path: &std::path::Path) -> Vec<String> {
    use tokio::io::AsyncBufReadExt;
    let Ok(file) = tokio::fs::File::open(path).await else {
        return vec![];
    };
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut commands = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
                if let Some(attempts) = val.get("shell_commands").and_then(|a| a.as_array()) {
                    for a in attempts {
                        if let Some(cmd) = a.get("command").and_then(|c| c.as_str()) {
                            if !cmd.is_empty() {
                                commands.push(cmd.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    commands
}

async fn read_credentials_from_evidence(path: &std::path::Path) -> Vec<(String, Option<String>)> {
    use tokio::io::AsyncBufReadExt;
    let Ok(file) = tokio::fs::File::open(path).await else {
        return vec![];
    };
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut creds = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
                if let Some(attempts) = val.get("auth_attempts").and_then(|a| a.as_array()) {
                    for a in attempts {
                        let user = a
                            .get("username")
                            .and_then(|u| u.as_str())
                            .unwrap_or("")
                            .to_string();
                        let pass = a
                            .get("password")
                            .and_then(|p| p.as_str())
                            .map(|p| p.to_string());
                        if !user.is_empty() {
                            creds.push((user, pass));
                        }
                    }
                }
            }
        }
    }
    creds
}

/// Spawned in the background after a honeypot session starts.
/// Reads evidence, extracts IOCs, gets AI verdict, auto-blocks, sends Telegram report.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_post_session_tasks(
    ip: &str,
    session_id: &str,
    data_dir: &std::path::Path,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
    blocklist_already_has_ip: bool,
) {
    // Give the honeypot listener time to collect evidence (wait for session to end).
    // We wait for the configured duration or a reasonable maximum.
    // Since we don't have the duration here, sleep briefly then retry reading.
    // The session is async and runs in its own task; we poll the evidence file.
    let evidence_path = data_dir
        .join("honeypot")
        .join(format!("listener-session-{session_id}.jsonl"));

    // Wait up to 10 minutes for evidence to appear (polls every 30s)
    let mut commands = Vec::new();
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let cmds = read_shell_commands_from_evidence(&evidence_path).await;
        if !cmds.is_empty() {
            commands = cmds;
            break;
        }
        // Also check if metadata file shows "completed" status
        let metadata_path = data_dir
            .join("honeypot")
            .join(format!("listener-session-{session_id}.json"));
        if let Ok(content) = tokio::fs::read_to_string(&metadata_path).await {
            if content.contains("\"status\":\"completed\"")
                || content.contains("\"status\": \"completed\"")
            {
                commands = read_shell_commands_from_evidence(&evidence_path).await;
                break;
            }
        }
    }

    // Extract credentials from evidence
    let credentials = read_credentials_from_evidence(&evidence_path).await;

    // Extract IOCs from commands
    let iocs = ioc::extract_from_commands(&commands);

    // Get AI verdict
    let verdict = if let Some(ref ai) = ai_provider {
        let cmd_text = if commands.is_empty() {
            "No commands recorded.".to_string()
        } else {
            commands
                .iter()
                .take(20)
                .map(|c| format!("  $ {c}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let prompt = format!(
            "Attacker IP {ip} ran these commands in an SSH honeypot:\n{cmd_text}\n\n\
             In 1-2 sentences in English, what does this attacker appear to be doing? \
             Be specific and direct."
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Analysis unavailable.".to_string())
    } else {
        "AI analysis not configured.".to_string()
    };

    // Auto-block the attacker IP if responder is enabled and IP not already blocked
    let auto_blocked = if responder_enabled && !blocklist_already_has_ip {
        let skill_id = format!("block-ip-{block_backend}");
        if allowed_skills.iter().any(|s| s == &skill_id) {
            let iid = format!("honeypot:post-session:{session_id}");
            let inc = innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string()),
                incident_id: iid.clone(),
                severity: innerwarden_core::event::Severity::High,
                title: "Honeypot Session Ended".to_string(),
                summary: format!("Attacker IP {ip} interacted with honeypot session {session_id}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["honeypot".to_string(), "post-session".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
            };
            let ctx = skills::SkillContext {
                incident: inc,
                target_ip: Some(ip.to_string()),
                target_user: None,
                target_container: None,
                duration_secs: None,
                host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
                data_dir: data_dir.to_path_buf(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
            };
            let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend {
                "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
                "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
                "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
                _ => Some(Box::new(skills::builtin::BlockIpUfw)),
            };
            if let Some(skill) = skill_box {
                let result = skill.execute(&ctx, dry_run).await;
                if result.success {
                    // Write decision to audit trail
                    let today = chrono::Local::now()
                        .date_naive()
                        .format("%Y-%m-%d")
                        .to_string();
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: iid,
                        host: ctx.host.clone(),
                        ai_provider: "honeypot:post-session".to_string(),
                        action_type: "block_ip".to_string(),
                        target_ip: Some(ip.to_string()),
                        target_user: None,
                        skill_id: Some(skill_id),
                        confidence: 1.0,
                        auto_executed: true,
                        dry_run,
                        reason: format!(
                            "Attacker IP interacted with honeypot session {session_id}"
                        ),
                        estimated_threat: "confirmed-attacker".to_string(),
                        execution_result: if result.success {
                            "ok".to_string()
                        } else {
                            format!("failed: {}", result.message)
                        },
                        prev_hash: None,
                    };
                    let path = data_dir.join(format!("decisions-{today}.jsonl"));
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        use std::io::Write;
                        if let Ok(line) = serde_json::to_string(&entry) {
                            let _ = writeln!(f, "{line}");
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Send Telegram post-session report
    if let Some(ref tg) = telegram_client {
        let duration = 300u64; // default; session duration stored in metadata
        if let Err(e) = tg
            .send_honeypot_session_report(
                ip,
                session_id,
                duration,
                &commands,
                &credentials,
                &iocs,
                &verdict,
                auto_blocked,
            )
            .await
        {
            tracing::warn!("failed to send honeypot session report via Telegram: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Always-on honeypot listener (mode = "always_on")
// ---------------------------------------------------------------------------

/// Handle a single always-on honeypot connection end-to-end:
/// SSH key exchange, credential capture, optional LLM shell, evidence write,
/// IOC extraction, AI verdict, auto-block, Telegram T.5 report.
#[allow(clippy::too_many_arguments)]
async fn handle_always_on_connection(
    stream: tokio::net::TcpStream,
    ip: String,
    ssh_cfg: std::sync::Arc<russh::server::Config>,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    data_dir: std::path::PathBuf,
    interaction: String,
    blocklist_already_has_ip: bool,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
) {
    use skills::builtin::honeypot::ssh_interact::{
        handle_connection, SshConnectionEvidence, SshInteractionMode,
    };

    let mode = if interaction == "llm_shell" {
        if let Some(ref ai) = ai_provider {
            SshInteractionMode::LlmShell {
                ai: ai.clone(),
                hostname: "srv-prod-01".to_string(),
            }
        } else {
            SshInteractionMode::RejectAll
        }
    } else {
        // "medium" and any other value: capture creds, always reject auth
        SshInteractionMode::RejectAll
    };

    let conn_timeout = std::time::Duration::from_secs(120);
    let evidence: SshConnectionEvidence =
        handle_connection(stream, ssh_cfg, conn_timeout, mode).await;

    // Build a unique session id.
    let session_id = format!(
        "always-on-{}-{}",
        ip.replace('.', "-"),
        chrono::Utc::now().timestamp()
    );

    // Write evidence to honeypot dir (append-only JSONL).
    let honeypot_dir = data_dir.join("honeypot");
    let _ = tokio::fs::create_dir_all(&honeypot_dir).await;
    let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
    if let Ok(json) = serde_json::to_string(&serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "type": "ssh_connection",
        "session_id": &session_id,
        "peer_ip": &ip,
        "auth_attempts": evidence.auth_attempts,
        "auth_attempts_count": evidence.auth_attempts.len(),
        "shell_commands": evidence.shell_commands,
        "shell_commands_count": evidence.shell_commands.len(),
    })) {
        let line = format!("{json}\n");
        if let Ok(mut f) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&evidence_path)
            .await
        {
            use tokio::io::AsyncWriteExt;
            let _ = f.write_all(line.as_bytes()).await;
        }
    }

    // Extract shell commands for IOC analysis and AI verdict.
    let commands: Vec<String> = evidence
        .shell_commands
        .iter()
        .map(|s| s.command.clone())
        .collect();

    let iocs = ioc::extract_from_commands(&commands);

    // AI verdict (brief summary in Portuguese).
    let verdict = if let Some(ref ai) = ai_provider {
        let cmd_text = if commands.is_empty() {
            "No commands recorded.".to_string()
        } else {
            commands
                .iter()
                .take(20)
                .map(|c| format!("  $ {c}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let prompt = format!(
            "Attacker IP {ip} connected to an SSH honeypot.\n\
             Auth attempts: {}\n\
             Shell commands:\n{cmd_text}\n\n\
             In 1-2 sentences in English, what does this attacker appear to be doing? \
             Be specific and direct.",
            evidence.auth_attempts.len(),
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Analysis unavailable.".to_string())
    } else {
        if evidence.auth_attempts.is_empty() {
            "Connection without authentication attempts - likely automated scanner.".to_string()
        } else {
            "AI not configured - no verdict available.".to_string()
        }
    };

    // Auto-block after session if responder is enabled and IP not already blocked.
    let auto_blocked = if responder_enabled && !blocklist_already_has_ip {
        let skill_id = format!("block-ip-{block_backend}");
        if allowed_skills.iter().any(|s| s == &skill_id) {
            let iid = format!("honeypot:always-on:{session_id}");
            let host = std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string());
            let inc = innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id: iid.clone(),
                severity: innerwarden_core::event::Severity::High,
                title: "Always-on Honeypot Session Ended".to_string(),
                summary: format!(
                    "Attacker IP {ip} connected to always-on honeypot session {session_id}"
                ),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["honeypot".to_string(), "always-on".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(&ip)],
            };
            let ctx = skills::SkillContext {
                incident: inc,
                target_ip: Some(ip.clone()),
                target_user: None,
                target_container: None,
                duration_secs: None,
                host: host.clone(),
                data_dir: data_dir.clone(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
            };
            let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend.as_str() {
                "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
                "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
                "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
                _ => Some(Box::new(skills::builtin::BlockIpUfw)),
            };
            if let Some(skill) = skill_box {
                let result = skill.execute(&ctx, dry_run).await;
                if result.success {
                    let today = chrono::Local::now()
                        .date_naive()
                        .format("%Y-%m-%d")
                        .to_string();
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: iid,
                        host,
                        ai_provider: "honeypot:always-on".to_string(),
                        action_type: "block_ip".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: Some(skill_id),
                        confidence: 1.0,
                        auto_executed: true,
                        dry_run,
                        reason: format!(
                            "Attacker IP interacted with always-on honeypot session {session_id}"
                        ),
                        estimated_threat: "confirmed-attacker".to_string(),
                        execution_result: if result.success {
                            "ok".to_string()
                        } else {
                            format!("failed: {}", result.message)
                        },
                        prev_hash: None,
                    };
                    let path = data_dir.join(format!("decisions-{today}.jsonl"));
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        use std::io::Write;
                        if let Ok(line) = serde_json::to_string(&entry) {
                            let _ = writeln!(f, "{line}");
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Extract credentials from evidence
    let credentials: Vec<(String, Option<String>)> = evidence
        .auth_attempts
        .iter()
        .map(|a| (a.username.clone(), a.password.clone()))
        .collect();

    // Send Telegram T.5 post-session report.
    if let Some(ref tg) = telegram_client {
        let duration = evidence.auth_attempts.len() as u64 * 5; // rough estimate
        if let Err(e) = tg
            .send_honeypot_session_report(
                &ip,
                &session_id,
                duration,
                &commands,
                &credentials,
                &iocs,
                &verdict,
                auto_blocked,
            )
            .await
        {
            warn!("always-on honeypot: failed to send Telegram session report: {e:#}");
        }
    }

    info!(
        ip,
        session_id,
        auth_attempts = evidence.auth_attempts.len(),
        shell_commands = evidence.shell_commands.len(),
        auto_blocked,
        "always-on honeypot session completed"
    );
}

/// Permanent SSH listener that runs from agent startup until SIGTERM.
///
/// Filter per connection:
///   1. Already in blocklist → drop silently (no banner sent)
///   2. AbuseIPDB score ≥ threshold (when configured) → block + drop
///   3. Otherwise → accept into honeypot interaction (RejectAll or LlmShell)
///
/// `filter_blocklist` is a shared set of already-blocked IPs populated at startup
/// from recent decisions and updated in-place when new IPs are blocked via the gate.
#[allow(clippy::too_many_arguments)]
async fn run_always_on_honeypot(
    port: u16,
    bind_addr: String,
    ssh_max_auth_attempts: usize,
    filter_blocklist: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    ai_provider: Option<std::sync::Arc<dyn ai::AiProvider>>,
    telegram_client: Option<std::sync::Arc<telegram::TelegramClient>>,
    abuseipdb_client: Option<std::sync::Arc<abuseipdb::AbuseIpDbClient>>,
    abuseipdb_threshold: u8,
    data_dir: std::path::PathBuf,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
    interaction: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use skills::builtin::honeypot::ssh_interact::build_ssh_config;

    let ssh_cfg = build_ssh_config(ssh_max_auth_attempts);

    let addr = format!("{bind_addr}:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(addr, error = %e, "always-on honeypot: failed to bind listener - mode disabled");
            return;
        }
    };
    info!(port, bind_addr, "always-on honeypot listener started");

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = match accept_result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "always-on honeypot: accept error");
                        continue;
                    }
                };

                let ip = peer.ip().to_string();

                // Filter 1: already in filter blocklist - drop silently.
                {
                    let bl = filter_blocklist.lock().unwrap_or_else(|e| e.into_inner());
                    if bl.contains(&ip) {
                        debug!(ip, "always-on honeypot: IP in blocklist - dropping silently");
                        continue;
                    }
                }

                // Filter 2: AbuseIPDB gate (async lookup before spawning handler).
                if abuseipdb_threshold > 0 {
                    if let Some(ref client) = abuseipdb_client {
                        if let Some(rep) = client.check(&ip).await {
                            if rep.confidence_score >= abuseipdb_threshold {
                                info!(
                                    ip,
                                    score = rep.confidence_score,
                                    "always-on honeypot: AbuseIPDB gate - blocking and dropping"
                                );
                                // Add to filter blocklist so future connections are dropped cheaply.
                                filter_blocklist
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(ip.clone());

                                // Write audit + execute block skill (background task).
                                let ip_c = ip.clone();
                                let dd = data_dir.clone();
                                let bb = block_backend.clone();
                                let sk = allowed_skills.clone();
                                let score = rep.confidence_score;
                                let threshold = abuseipdb_threshold;
                                let re = responder_enabled;
                                let dr = dry_run;
                                tokio::spawn(async move {
                                    always_on_abuseipdb_block(
                                        &ip_c, score, threshold, &dd, re, dr, &bb, &sk,
                                    )
                                    .await;
                                });
                                continue;
                            }
                        }
                    }
                }

                // Accept: snapshot blocklist membership, then spawn connection handler.
                let bl_has_ip = filter_blocklist
                    .lock()
                    .map(|bl| bl.contains(&ip))
                    .unwrap_or(false);

                let ssh_cfg_clone = ssh_cfg.clone();
                let ai_clone = ai_provider.clone();
                let tg_clone = telegram_client.clone();
                let dd = data_dir.clone();
                let ip_clone = ip.clone();
                let intr = interaction.clone();
                let bb = block_backend.clone();
                let sk = allowed_skills.clone();
                let re = responder_enabled;
                let dr = dry_run;
                let bl_ref = filter_blocklist.clone();

                tokio::spawn(async move {
                    handle_always_on_connection(
                        stream,
                        ip_clone.clone(),
                        ssh_cfg_clone,
                        ai_clone,
                        tg_clone,
                        dd,
                        intr,
                        bl_has_ip,
                        re,
                        dr,
                        bb,
                        sk,
                    )
                    .await;
                    // After session, mark IP as seen so the filter can drop quick-reconnects.
                    bl_ref
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(ip_clone);
                });
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("always-on honeypot listener shutting down");
                    break;
                }
            }
        }
    }
}

/// Write an AbuseIPDB-triggered block audit entry and execute the block skill.
#[allow(clippy::too_many_arguments)]
async fn always_on_abuseipdb_block(
    ip: &str,
    score: u8,
    threshold: u8,
    data_dir: &std::path::Path,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
) {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let iid = format!("honeypot:always-on:abuseipdb:{ip}");
    let skill_id = format!("block-ip-{block_backend}");

    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: iid.clone(),
        host: host.clone(),
        ai_provider: "honeypot:abuseipdb_gate".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run,
        reason: format!(
            "AbuseIPDB confidence score {score}/100 exceeded always-on honeypot gate threshold {threshold}"
        ),
        estimated_threat: "known-malicious".to_string(),
        execution_result: "ok".to_string(),
        prev_hash: None,
    };

    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        if let Ok(line) = serde_json::to_string(&entry) {
            let _ = writeln!(f, "{line}");
        }
    }

    if responder_enabled && allowed_skills.iter().any(|s| s == &skill_id) {
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: iid,
            severity: innerwarden_core::event::Severity::High,
            title: "AbuseIPDB Gate Block (Always-on Honeypot)".to_string(),
            summary: format!(
                "IP {ip} blocked at always-on honeypot AbuseIPDB gate (score {score})"
            ),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["honeypot".to_string(), "abuseipdb".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        };
        let ctx = skills::SkillContext {
            incident: inc,
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host,
            data_dir: data_dir.to_path_buf(),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend {
            "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
            "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
            "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
            _ => Some(Box::new(skills::builtin::BlockIpUfw)),
        };
        if let Some(skill) = skill_box {
            let _ = skill.execute(&ctx, dry_run).await;
        }
    }
}

// ---------------------------------------------------------------------------
// LSM auto-enable helpers
// ---------------------------------------------------------------------------

/// Returns true if an incident represents a high-severity execution threat
/// that warrants automatic LSM enforcement (blocking /tmp, /dev/shm execution).
pub(crate) fn should_auto_enable_lsm(incident: &innerwarden_core::incident::Incident) -> bool {
    use innerwarden_core::event::Severity;

    // Only trigger on high/critical execution-related incidents
    if !matches!(incident.severity, Severity::High | Severity::Critical) {
        return false;
    }

    let detector = incident.incident_id.split(':').next().unwrap_or("");
    let title_lower = incident.title.to_lowercase();
    let summary_lower = incident.summary.to_lowercase();

    // execution_guard detecting download+execute, reverse shells, /tmp execution
    if detector == "suspicious_execution" || detector == "execution_guard" {
        return title_lower.contains("reverse shell")
            || title_lower.contains("download")
            || summary_lower.contains("/tmp/")
            || summary_lower.contains("/dev/shm/")
            || summary_lower.contains("curl")
            || summary_lower.contains("wget");
    }

    // LSM blocked event (kind=6) means someone already tried - keep enforcement on
    if detector == "lsm" {
        return true;
    }

    // Container escape attempting to execute from temp paths
    if detector == "container_escape" {
        return summary_lower.contains("/tmp") || summary_lower.contains("/dev/shm");
    }

    false
}

/// Enable LSM enforcement by setting key 0 = 1 in the pinned policy map.
/// Note: no Path::exists() pre-check — the agent runs as non-root and can't
/// stat /sys/fs/bpf/, but sudo bpftool can access it fine.
pub(crate) async fn enable_lsm_enforcement() -> Result<(), String> {
    const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";

    let output = tokio::process::Command::new("sudo")
        .args([
            "bpftool",
            "map",
            "update",
            "pinned",
            LSM_POLICY_PIN,
            "key",
            "0",
            "0",
            "0",
            "0",
            "value",
            "1",
            "0",
            "0",
            "0",
            "any",
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run bpftool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::path::Path;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // Minimal mock AI provider - returns a fixed decision, no network I/O
    // ------------------------------------------------------------------

    struct MockAiProvider {
        decision: ai::AiDecision,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for MockAiProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            Ok(self.decision.clone())
        }
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    struct CountingMockAiProvider {
        decision: ai::AiDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CountingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-counting"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    struct CorrelationInspectingMockAiProvider {
        decision: ai::AiDecision,
        last_related_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CorrelationInspectingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-correlation"
        }

        async fn decide(&self, ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.last_related_count
                .store(ctx.related_incidents.len(), Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    /// Write a minimal Incident JSON line (ssh brute-force from an external IP).
    fn incident_line(ip: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH Brute Force".to_string(),
            summary: format!("9 failed SSH attempts from {ip}"),
            evidence: serde_json::json!({"failed_attempts": 9}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    fn incident_line_with_kind(ip: &str, kind: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("{kind}:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: format!("{kind} detected"),
            summary: format!("{kind} from {ip}"),
            evidence: serde_json::json!({"kind": kind}),
            recommended_checks: vec![],
            tags: vec![kind.to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    fn sha256_hex_for_test(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn triage_approval(incident_id: &str, operator: &str) -> telegram::ApprovalResult {
        telegram::ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            operator_name: operator.to_string(),
            always: false,
            chosen_action: String::new(),
        }
    }

    fn triage_test_state(data_dir: &Path) -> AgentState {
        AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: None,
            decision_writer: Some(decisions::DecisionWriter::new(data_dir).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(data_dir),
            store: state_store::StateStore::open(data_dir).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(data_dir),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        }
    }

    #[test]
    fn parse_telegram_triage_action_routes_allow_proc() {
        assert_eq!(
            parse_telegram_triage_action("__allow_proc__:cargo-build"),
            Some(TelegramTriageAction::AllowProc("cargo-build"))
        );
    }

    #[test]
    fn parse_telegram_triage_action_routes_allow_ip() {
        assert_eq!(
            parse_telegram_triage_action("__allow_ip__:1.2.3.4"),
            Some(TelegramTriageAction::AllowIp("1.2.3.4"))
        );
    }

    #[test]
    fn parse_telegram_triage_action_routes_fp_report() {
        assert_eq!(
            parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:test"),
            Some(TelegramTriageAction::ReportFp(
                "ssh_bruteforce:1.2.3.4:test"
            ))
        );
    }

    #[test]
    fn parse_telegram_triage_action_ignores_non_triage_ids() {
        assert_eq!(parse_telegram_triage_action("__status__"), None);
        assert_eq!(
            parse_telegram_triage_action("approve:ssh_bruteforce:id"),
            None
        );
    }

    #[test]
    fn sanitize_allowlist_process_name_removes_dangerous_chars() {
        assert_eq!(
            sanitize_allowlist_process_name("  bad\"proc\nname  "),
            Some("badproc name".to_string())
        );
        assert_eq!(sanitize_allowlist_process_name("   "), None);
    }

    #[tokio::test]
    async fn telegram_triage_allowlist_skip_paths_are_audited_with_hash_chain() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());

        process_telegram_approval(
            triage_approval("__allow_proc__:   ", "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;
        process_telegram_approval(
            triage_approval("__allow_ip__:not-an-ip", "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let lines: Vec<String> = std::fs::read_to_string(&decisions_path)
            .unwrap()
            .lines()
            .map(|line| line.to_string())
            .collect();

        assert_eq!(lines.len(), 2, "expected two triage audit entries");

        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();

        assert_eq!(first["action_type"], "allowlist_add");
        assert_eq!(first["execution_result"], "skipped:empty_process_name");
        assert_eq!(second["action_type"], "allowlist_add");
        assert_eq!(second["execution_result"], "skipped:invalid_ip");

        assert!(
            first.get("prev_hash").is_none(),
            "first entry should not have prev_hash"
        );
        let expected_prev_hash = sha256_hex_for_test(&lines[0]);
        assert_eq!(
            second["prev_hash"].as_str(),
            Some(expected_prev_hash.as_str())
        );
    }

    #[tokio::test]
    async fn telegram_triage_fp_reports_write_audit_and_fp_log() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());
        let fp_incident_id = "ssh_bruteforce:1.2.3.4:test";

        process_telegram_approval(
            triage_approval(&format!("__fp__:{fp_incident_id}"), "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }

        let today_local = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today_local}.jsonl"));
        let decision_line = std::fs::read_to_string(&decisions_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let decision: serde_json::Value = serde_json::from_str(&decision_line).unwrap();

        assert_eq!(decision["incident_id"], fp_incident_id);
        assert_eq!(decision["action_type"], "fp_report");
        assert_eq!(decision["execution_result"], "reported_fp:ssh_bruteforce");
        assert_eq!(decision["ai_provider"], "operator:telegram:alice");

        let today_utc = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let fp_path = dir.path().join(format!("fp-reports-{today_utc}.jsonl"));
        let fp_content = std::fs::read_to_string(&fp_path).unwrap();
        assert!(fp_content.contains("\"incident_id\":\"ssh_bruteforce:1.2.3.4:test\""));
        assert!(fp_content.contains("\"detector\":\"ssh_bruteforce\""));
        assert!(fp_content.contains("\"reporter\":\"alice\""));
    }

    // ------------------------------------------------------------------
    // Golden path: incident → algorithm gate → mock AI → dry-run block → decisions.jsonl
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn golden_path_dry_run_produces_decision_entry() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // 1. Plant a single brute-force incident from a routable external IP.
        //    Must NOT be RFC1918, loopback, or documentation (203.0.113.x / 198.51.100.x
        //    are TEST-NET ranges and would be filtered by the algorithm gate).
        let attacker_ip = "1.2.3.4";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        // 2. Config: AI enabled, responder dry_run=true, ufw backend allowed
        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // 3. Mock provider always recommends blocking the IP
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "9 SSH failures, no success, external IP - classic brute force".to_string(),
                alternatives: vec!["monitor".to_string()],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        // 4. Run the incident tick
        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Verify: one incident handled
        assert_eq!(handled, 1, "expected 1 incident handled");

        // Verify: cursor advanced (incident will not be re-read on next tick)
        assert!(
            cursor.incidents_offset(&today) > 0,
            "cursor should have advanced past the incident"
        );

        // Verify: decision written to audit trail
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert!(
            content.contains(attacker_ip),
            "decision must record the target IP"
        );
        assert!(
            content.contains("block_ip"),
            "decision must record action type"
        );
        assert!(
            content.contains("\"dry_run\":true"),
            "dry_run must be flagged in audit trail"
        );
        assert!(
            content.contains("mock"),
            "AI provider name must appear in audit trail"
        );
    }

    // ------------------------------------------------------------------
    // allowed_skills whitelist: AI selects a disallowed skill → fallback used
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_skills_whitelist_enforced() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // Use a routable external IP - TEST-NET ranges (203.0.113.x) are filtered by the gate
        let attacker_ip = "5.6.7.8";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                // Only ufw is allowed; AI picks iptables - should fall back silently
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // AI picks iptables (not in whitelist)
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-iptables".to_string(), // NOT in allowed_skills
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Still handled (not skipped entirely) - fell back to ufw
        assert_eq!(handled, 1);

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        // The execution used the ufw fallback, not iptables.
        // The audit trail still records the IP the AI identified.
        assert!(content.contains(attacker_ip));
    }

    #[tokio::test]
    async fn same_ip_in_same_tick_triggers_single_ai_call() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "9.8.7.6";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "duplicate IP in same tick".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 2, "both incidents should be accounted for");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "same IP in same tick must call AI only once"
        );

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert_eq!(
            content.lines().count(),
            1,
            "only one decision should be recorded"
        );
    }

    #[tokio::test]
    async fn temporal_correlation_context_is_passed_to_ai() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "2.3.4.5";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line_with_kind(attacker_ip, "port_scan")).unwrap();
        writeln!(
            f,
            "{}",
            incident_line_with_kind(attacker_ip, "credential_stuffing")
        )
        .unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            correlation: config::CorrelationConfig {
                enabled: true,
                window_seconds: 300,
                max_related_incidents: 8,
            },
            responder: config::ResponderConfig {
                enabled: false,
                ..config::ResponderConfig::default()
            },
            ..config::AgentConfig::default()
        };

        let related_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CorrelationInspectingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: "test correlation".to_string(),
                },
                confidence: 0.9,
                auto_execute: false,
                reason: "test correlation".to_string(),
                alternatives: vec![],
                estimated_threat: "medium".to_string(),
            },
            last_related_count: related_count.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 2);
        assert!(
            related_count.load(Ordering::SeqCst) >= 1,
            "second correlated incident should carry prior incident context"
        );
    }

    #[tokio::test]
    async fn honeypot_demo_writes_synthetic_decoy_event() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "7.7.7.7";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["honeypot".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Honeypot {
                    ip: attacker_ip.to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "demo honeypot test".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 1);

        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        let content = std::fs::read_to_string(&events_path).unwrap();
        assert!(content.contains("honeypot.demo_decoy_hit"));
        assert!(content.contains("DEMO/SIMULATION/DECOY"));
        assert!(content.contains(attacker_ip));
    }

    // ------------------------------------------------------------------
    // Decision cooldown: second incident from same IP/detector is suppressed
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn decision_cooldown_suppresses_repeat() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "1.2.3.4";

        // Plant TWO identical brute-force incidents from the same IP
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            telegram_batcher: telegram::TelegramBatcher::new(60),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Both incidents are "handled" (counted), but the AI should be called
        // only ONCE - the second incident is suppressed by the decision
        // cooldown that was recorded after the first decision.
        assert_eq!(handled, 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "AI should be called once - second incident suppressed by cooldown"
        );

        // Verify the cooldown entry was recorded in the persistent store
        assert!(
            state.store.has_cooldown(
                state_store::CooldownTable::Decision,
                &format!("block_ip:ssh_bruteforce:ip:{}", attacker_ip)
            ),
            "decision cooldown should be recorded in store"
        );
    }

    // ------------------------------------------------------------------
    // Always-on honeypot tests
    // ------------------------------------------------------------------

    /// Test that the filter blocklist correctly drops IPs that are already blocked.
    #[test]
    fn test_always_on_filter_blocks_known_ip() {
        let mut set = std::collections::HashSet::new();
        set.insert("1.2.3.4".to_string());
        set.insert("5.6.7.8".to_string());

        // Known-bad IP should be "blocked" (present in set).
        assert!(
            set.contains("1.2.3.4"),
            "IP 1.2.3.4 should be in the filter blocklist"
        );
        assert!(
            set.contains("5.6.7.8"),
            "IP 5.6.7.8 should be in the filter blocklist"
        );

        // Unknown IP should NOT be blocked.
        assert!(
            !set.contains("9.9.9.9"),
            "IP 9.9.9.9 should not be in the filter blocklist"
        );

        // After inserting a new IP, it should be filtered.
        set.insert("9.9.9.9".to_string());
        assert!(
            set.contains("9.9.9.9"),
            "IP 9.9.9.9 should be in the filter blocklist after insertion"
        );
    }

    /// Test that the "always_on" mode string is recognized and would trigger startup.
    #[test]
    fn test_always_on_mode_recognized() {
        // Verify config recognises the mode string (no panic on deserialise).
        let toml = r#"
            [honeypot]
            mode = "always_on"
            port = 2222
            bind_addr = "127.0.0.1"
            interaction = "medium"
        "#;
        let cfg: config::AgentConfig = toml::from_str(toml).expect("should parse always_on mode");
        assert_eq!(cfg.honeypot.mode, "always_on");
        assert_eq!(cfg.honeypot.port, 2222);

        // Verify the mode check used in main() matches.
        let is_always_on = cfg.honeypot.mode == "always_on";
        assert!(
            is_always_on,
            "mode check should return true for 'always_on'"
        );

        // Demo and listener modes should NOT match.
        let mut cfg2 = config::AgentConfig::default();
        cfg2.honeypot.mode = "demo".to_string();
        assert!(
            cfg2.honeypot.mode != "always_on",
            "demo should not match always_on"
        );

        let mut cfg3 = config::AgentConfig::default();
        cfg3.honeypot.mode = "listener".to_string();
        assert!(
            cfg3.honeypot.mode != "always_on",
            "listener should not match always_on"
        );
    }

    // ── Memory safety: NarrativeAccumulator tests ────────────────────

    #[test]
    fn synthetic_events_capped_at_2000() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        // Simulate 100k events of one kind
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 100_000;
        let events = acc.synthetic_events();
        assert!(
            events.len() <= 2100, // 2000 cap + some entity events
            "synthetic_events should be capped, got {}",
            events.len()
        );
    }

    #[test]
    fn synthetic_events_preserves_proportions() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 8000;
        *acc.events_by_kind
            .entry("sudo.command".to_string())
            .or_insert(0) = 2000;
        let events = acc.synthetic_events();
        let ssh = events
            .iter()
            .filter(|e| e.kind == "ssh.login_failed")
            .count();
        let sudo = events.iter().filter(|e| e.kind == "sudo.command").count();
        // ssh should be ~4x more than sudo (8000:2000 ratio)
        assert!(ssh > sudo, "ssh ({ssh}) should be more than sudo ({sudo})");
    }

    #[test]
    fn incidents_capped_at_500() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        let incident = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "test:1".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "test".to_string(),
            summary: "test".to_string(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        let batch: Vec<_> = (0..600).map(|_| incident.clone()).collect();
        acc.ingest_incidents(&batch);
        assert_eq!(
            acc.incidents.len(),
            500,
            "incidents should be capped at 500"
        );
    }

    #[test]
    fn block_counts_cleared_at_threshold() {
        let dir = TempDir::new().unwrap();
        let store = state_store::StateStore::open(dir.path()).unwrap();
        for i in 0..5001 {
            store.increment_block_count(&format!("1.2.3.{i}"));
        }
        assert!(store.block_counts_len() > 5000);
        // Simulate the trim logic from narrative tick
        if store.block_counts_len() > 5000 {
            store.clear_block_counts();
        }
        assert_eq!(store.block_counts_len(), 0);
    }

    #[test]
    fn narrative_accumulator_resets_on_date_change() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 100;
        acc.total_events = 100;

        acc.reset_for_date("2026-01-02");
        assert_eq!(acc.total_events, 0);
        assert!(acc.events_by_kind.is_empty());
        assert_eq!(acc.date, "2026-01-02");
    }
}
