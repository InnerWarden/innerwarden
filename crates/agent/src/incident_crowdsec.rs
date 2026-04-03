use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    ai, allowlist, attacker_intel, config, decision_cooldown_key_for_decision, decisions,
    execute_decision, state_store, AgentState,
};

/// CrowdSec gate: auto-block IPs already listed as known community threats.
/// Returns true when the incident is fully handled (auto-block path).
pub(crate) async fn try_handle_crowdsec_autoblock(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    blocked_set: &mut HashSet<String>,
) -> bool {
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let Some(ip) = primary_ip else {
        return false;
    };

    let is_known_threat = state
        .crowdsec
        .as_ref()
        .is_some_and(|cs| cs.is_known_threat(&ip));
    if !is_known_threat
        || blocked_set.contains(&ip)
        || state.blocklist.contains(&ip)
        || allowlist::is_ip_allowlisted(&ip, &cfg.ai.protected_ips)
    {
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        "CrowdSec threat list match - auto-blocking, skipping AI"
    );

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id,
        },
        confidence: 1.0,
        auto_execute: true,
        reason: "CrowdSec community threat list match".to_string(),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

    blocked_set.insert(ip.clone());
    state.blocklist.insert(ip.clone());

    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    let (execution_result, _cf_pushed) = if cfg.responder.enabled {
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await
    } else {
        ("skipped: responder disabled".to_string(), false)
    };

    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            "crowdsec",
            &auto_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Some(profile) = state.attacker_profiles.get_mut(ip.as_str()) {
            attacker_intel::observe_decision(profile, &entry);
        }
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write CrowdSec decision: {e:#}");
        }
    }

    true
}
