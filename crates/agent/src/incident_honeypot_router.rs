use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    ai, allowlist, config, decision_cooldown_key_for_decision, decisions, execute_decision,
    state_store, AgentState,
};

/// Honeypot smart routing gate: route selected attackers to honeypot listener
/// instead of immediate block to collect more intelligence.
/// Returns true when the incident is fully handled by this gate.
pub(crate) async fn try_handle_honeypot_routing(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    blocked_set: &HashSet<String>,
) -> bool {
    if cfg.honeypot.mode != "listener" || !cfg.responder.enabled {
        return false;
    }

    let detector = incident.incident_id.split(':').next().unwrap_or("");
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let Some(ip) = primary_ip else {
        return false;
    };

    let is_new_attacker = !state.blocklist.contains(&ip)
        && !blocked_set.contains(&ip)
        && state.store.get_block_count(&ip) == 0;

    // suspicious_login = brute-force followed by success -> HIGH VALUE.
    // Route to honeypot to observe what they do with access.
    let should_honeypot = (detector == "suspicious_login" && is_new_attacker)
        // First-time SSH brute-force with low attempt count.
        || (detector == "ssh_bruteforce"
            && is_new_attacker
            && !allowlist::is_ip_allowlisted(&ip, &cfg.ai.protected_ips)
            // Only route ~20% of new attackers to honeypot (the rest get blocked).
            && ip.as_bytes().last().copied().unwrap_or(0) % 5 == 0);

    if !should_honeypot {
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        detector,
        "honeypot routing: interesting attacker -> redirecting to honeypot"
    );

    let honeypot_decision = ai::AiDecision {
        action: ai::AiAction::Honeypot { ip: ip.clone() },
        confidence: 0.95,
        auto_execute: true,
        reason: format!(
            "Smart routing: {} - interesting attacker redirected to honeypot for intel gathering",
            detector
        ),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

    if let Some(key) = decision_cooldown_key_for_decision(incident, &honeypot_decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    let (execution_result, _) = if cfg.responder.enabled {
        execute_decision(&honeypot_decision, incident, data_dir, cfg, state).await
    } else {
        ("skipped: responder disabled".to_string(), false)
    };

    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            "honeypot-router",
            &honeypot_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write honeypot routing decision: {e:#}");
        }
    }

    true
}
