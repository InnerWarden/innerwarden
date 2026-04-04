use std::collections::HashMap;
use std::path::Path;

use crate::agent_context::incident_detector;
use crate::{ai, decisions, skills};

pub(crate) const DECISION_COOLDOWN_SECS: i64 = 3600;
/// Notification cooldown: suppress duplicate Telegram/Slack/webhook alerts for the
/// same detector+entity within this window. Prevents alert spam when the same attacker
/// triggers multiple incidents in rapid succession.
pub(crate) const NOTIFICATION_COOLDOWN_SECS: i64 = 600;
/// Max block actions per minute - prevents false-positive cascades.
pub(crate) const MAX_BLOCKS_PER_MINUTE: usize = 20;
/// Default XDP blocklist TTL (24h) - retained as reference; adaptive TTL now per-IP.
#[allow(dead_code)]
pub(crate) const XDP_BLOCK_TTL_SECS: i64 = 86400;
/// AbuseIPDB reports are delayed by this many seconds to allow false-positive correction.
pub(crate) const ABUSEIPDB_REPORT_DELAY_SECS: i64 = 300;

/// Returns notification cooldown keys for an incident.
/// One key per entity (IP or user): `detector:entity_kind:entity_value`.
pub(crate) fn notification_cooldown_keys(
    incident: &innerwarden_core::incident::Incident,
) -> Vec<String> {
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

pub(crate) fn decision_cooldown_key_from_entry(entry: &decisions::DecisionEntry) -> Option<String> {
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

pub(crate) fn recent_decision_dates() -> Vec<String> {
    let today = chrono::Local::now().date_naive();
    let mut dates = vec![today.format("%Y-%m-%d").to_string()];
    if let Some(prev) = today.pred_opt() {
        dates.push(prev.format("%Y-%m-%d").to_string());
    }
    dates
}

pub(crate) fn load_startup_decision_state(
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

pub(crate) fn load_last_narrative_instant(data_dir: &Path) -> Option<std::time::Instant> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("summary-{today}.md"));
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.elapsed().ok()?;
    std::time::Instant::now().checked_sub(elapsed)
}

#[allow(dead_code)]
pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
