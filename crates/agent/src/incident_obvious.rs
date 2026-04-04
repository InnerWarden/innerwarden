use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::incident_detector;
use crate::config::ChannelFilterLevel;
use crate::{
    ai, config, decision_cooldown_key_for_decision, decisions, execute_decision, AgentState,
    LocalIpReputation,
};

/// Obvious incident gate: skip AI for high-confidence detectors + known attacker IP.
/// Returns true when the incident was fully handled (auto-block path).
pub(crate) async fn try_handle_obvious_incident(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let detector = incident_detector(&incident.incident_id);
    let is_obvious_detector = matches!(
        detector,
        "ssh_bruteforce" | "credential_stuffing" | "packet_flood" | "port_scan"
    );
    let is_high_or_critical = matches!(
        incident.severity,
        innerwarden_core::event::Severity::High | innerwarden_core::event::Severity::Critical
    );
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    let ip_seen_before = primary_ip.is_some_and(|ip| {
        // Check if this IP was already blocked or has prior incidents
        // (total_incidents > 1 because the current incident already incremented it)
        state.blocklist.contains(ip)
            || state
                .ip_reputations
                .get(ip)
                .is_some_and(|r| r.total_incidents > 1)
    });

    if !(is_obvious_detector && is_high_or_critical && ip_seen_before && cfg.responder.enabled) {
        return false;
    }

    let Some(ip) = primary_ip else {
        return false;
    };

    info!(
        incident_id = %incident.incident_id,
        "skipping AI for obvious incident: {detector} from {ip}"
    );
    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id,
        },
        confidence: 0.95,
        auto_execute: true,
        reason: format!("Auto-blocked: obvious {detector} from repeat offender {ip}"),
        alternatives: vec![],
        estimated_threat: "high".to_string(),
    };
    let (execution_result, cloudflare_pushed) =
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await;

    // Write decision entry
    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "obvious-gate".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: None,
        confidence: 0.95,
        auto_executed: true,
        dry_run: cfg.responder.dry_run,
        reason: auto_decision.reason.clone(),
        estimated_threat: "high".to_string(),
        execution_result: execution_result.clone(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write obvious-gate decision: {e:#}");
        }
    }

    // Update IP reputation
    let rep = state
        .ip_reputations
        .entry(ip.to_string())
        .or_insert_with(LocalIpReputation::new);
    rep.record_incident();
    if !execution_result.starts_with("skipped") {
        rep.record_block();
    }

    // Set decision cooldown
    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision) {
        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    // Telegram action report — only send when notification level is All.
    // At the default Actionable level, the incident alert was already sent (or
    // suppressed by grouping), so the "Threat neutralized" follow-up is noise.
    let send_action_report = cfg.telegram.channel_notifications.notification_level
        == ChannelFilterLevel::All;
    if send_action_report
        && !execution_result.starts_with("skipped")
        && cfg.telegram.bot.enabled
    {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let title = incident.title.clone();
            let host = incident.host.clone();
            let ip_owned = ip.to_string();
            tokio::spawn(async move {
                let _ = tg
                    .send_action_report(
                        "Blocked (obvious)",
                        &ip_owned,
                        &title,
                        0.95,
                        &host,
                        false,
                        None,
                        None,
                        cloudflare_pushed,
                    )
                    .await;
            });
        }
    }

    true
}
