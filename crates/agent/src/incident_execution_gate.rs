use std::path::Path;

use tracing::info;

use crate::agent_context::incident_detector;
use crate::{ai, config, execute_decision, is_trusted, AgentState};

/// Execute a decision when it passes trust/confidence/responder gates,
/// otherwise return a deterministic skip reason.
pub(crate) async fn execute_or_skip_decision(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // Execute if:
    //   (a) AI flagged auto_execute, OR operator has trusted this detector+action pair
    //   AND confidence >= threshold
    //   AND responder is enabled
    let detector = incident_detector(&incident.incident_id);
    let action_name = decision.action.name();
    let trusted = is_trusted(&state.trust_rules, detector, action_name);

    if (decision.auto_execute || trusted)
        && decision.confidence >= cfg.ai.confidence_threshold
        && cfg.responder.enabled
    {
        if trusted && !decision.auto_execute {
            info!(
                incident_id = %incident.incident_id,
                detector,
                action = action_name,
                "trust rule override: executing without AI auto_execute flag"
            );
        }
        state
            .telemetry
            .observe_execution_path(cfg.responder.dry_run);
        execute_decision(decision, incident, data_dir, cfg, state).await
    } else if !cfg.responder.enabled {
        ("skipped: responder disabled".to_string(), false)
    } else if !decision.auto_execute && !trusted {
        (
            "skipped: AI did not recommend auto-execution (no trust rule)".to_string(),
            false,
        )
    } else {
        (
            format!(
                "skipped: confidence {:.2} below threshold {:.2}",
                decision.confidence, cfg.ai.confidence_threshold
            ),
            false,
        )
    }
}
