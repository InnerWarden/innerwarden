use tracing::{info, warn};

use crate::{ai, config, decisions, AgentState, PendingHoneypotChoice};

/// Handle honeypot operator suggestion flow via Telegram.
/// Returns true when the incident is deferred to operator choice.
pub(crate) async fn maybe_defer_honeypot_to_operator(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    decision: &ai::AiDecision,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let ai::AiAction::Honeypot { ip } = &decision.action else {
        return false;
    };

    let should_auto = decision.auto_execute && decision.confidence >= cfg.ai.confidence_threshold;
    if should_auto {
        // Auto-execute honeypot - same as operator clicking "Honeypot".
        info!(
            ip = %ip,
            confidence = decision.confidence,
            "AI auto-activating honeypot (high confidence)"
        );
        // Fall through to normal execution below (don't defer to Telegram).
        return false;
    }

    let Some(ref tg) = state.telegram_client else {
        return false;
    };

    let ttl = cfg.telegram.approval_ttl_secs;
    let tg_clone = tg.clone();
    let reason = decision.reason.clone();
    let confidence = decision.confidence;
    let incident_clone = incident.clone();
    let ip_clone = ip.clone();

    match tg_clone
        .send_honeypot_suggestion(&incident_clone, &ip_clone, &reason, confidence, "honeypot")
        .await
    {
        Ok(_msg_id) => {
            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
            state.pending_honeypot_choices.insert(
                ip_clone.clone(),
                PendingHoneypotChoice {
                    ip: ip_clone.clone(),
                    incident_id: incident.incident_id.clone(),
                    incident: incident_clone,
                    expires_at,
                },
            );

            // Write an audit entry noting the operator was asked.
            if let Some(writer) = &mut state.decision_writer {
                let entry = decisions::build_entry(
                    &incident.incident_id,
                    &incident.host,
                    provider_name,
                    decision,
                    cfg.responder.dry_run,
                    "pending: operator honeypot choice requested via Telegram",
                );
                if let Err(e) = writer.write(&entry) {
                    state.telemetry.observe_error("decision_writer");
                    warn!("failed to write honeypot-pending decision: {e:#}");
                }
            }
            true
        }
        Err(e) => {
            warn!(
                incident_id = %incident.incident_id,
                "Telegram honeypot suggestion failed: {e:#} - falling through to auto-execute"
            );
            false
        }
    }
}
