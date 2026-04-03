use tracing::warn;

use crate::{ai, config, decisions, AgentState};

/// Handle AI provider failure for one incident and record a fallback audit entry.
pub(crate) fn handle_ai_decision_failure(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    error: &anyhow::Error,
) {
    state.telemetry.observe_error("ai_provider");
    state.telemetry.observe_ai_decision(
        &ai::AiAction::Ignore {
            reason: "ai_error".to_string(),
        },
        0,
    );
    warn!(incident_id = %incident.incident_id, "AI decision failed: {error:#}");

    // Write a fallback decision so the audit trail records the failure.
    if let Some(ref mut writer) = state.decision_writer {
        let entry = decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: incident.host.clone(),
            ai_provider: provider_name.to_string(),
            action_type: "error".to_string(),
            target_ip: None,
            target_user: None,
            skill_id: None,
            confidence: 0.0,
            auto_executed: false,
            dry_run: cfg.responder.dry_run,
            reason: format!("{error:#}"),
            estimated_threat: "unknown".to_string(),
            execution_result: "ai_error".to_string(),
            prev_hash: None,
        };
        if let Err(writer_err) = writer.write(&entry) {
            warn!("failed to write fallback decision: {writer_err:#}");
        }
    }
}
