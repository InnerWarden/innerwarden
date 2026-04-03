use crate::{ai, config, telegram, AgentState};

/// Execute operator confirmation flow:
/// Telegram approval request first, then webhook fallback when configured.
pub(crate) async fn execute_request_confirmation(
    summary: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // T.2 - send inline keyboard approval request via Telegram when enabled.
    let tg = state.telegram_client.clone();
    let req_detector = crate::agent_context::incident_detector(&incident.incident_id).to_string();
    let req_action = decision.action.name();
    if let Some(tg) = tg {
        let ttl = cfg.telegram.approval_ttl_secs;
        match tg
            .send_confirmation_request(incident, summary, req_action, decision.confidence, ttl)
            .await
        {
            Ok(msg_id) => {
                let now = chrono::Utc::now();
                let pending = telegram::PendingConfirmation {
                    incident_id: incident.incident_id.clone(),
                    telegram_message_id: msg_id,
                    action_description: summary.to_string(),
                    created_at: now,
                    expires_at: now + chrono::Duration::seconds(ttl as i64),
                    detector: req_detector,
                    action_name: req_action.to_string(),
                };
                state.pending_confirmations.insert(
                    incident.incident_id.clone(),
                    (pending, decision.clone(), incident.clone()),
                );
                return (
                    "pending: operator confirmation requested via Telegram".to_string(),
                    false,
                );
            }
            Err(e) => {
                tracing::warn!("Telegram confirmation request failed: {e:#}");
            }
        }
    }

    // Fallback: webhook notification when Telegram is not configured.
    if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        let payload = serde_json::json!({
            "type": "confirmation_required",
            "incident_id": incident.incident_id,
            "summary": summary,
            "decision_reason": decision.reason,
        });
        let client = reqwest::Client::new();
        match client.post(&cfg.webhook.url).json(&payload).send().await {
            Ok(_) => ("confirmation request sent via webhook".to_string(), false),
            Err(e) => (format!("confirmation webhook failed: {e}"), false),
        }
    } else {
        (
            "confirmation requested (no Telegram or webhook configured)".to_string(),
            false,
        )
    }
}
