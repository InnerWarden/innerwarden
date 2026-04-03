use tracing::info;

use crate::{ai, config, correlation, AgentState};

/// Apply correlation confidence boost and emit the canonical decision log.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
) {
    // If the same IP triggered multiple distinct detectors within the
    // correlation window, boost the confidence.
    let (boosted_confidence, correlated_detectors) = if cfg.correlation.enabled {
        let (b, k) = correlation::cross_detector_boost(
            &mut state.correlator,
            incident,
            decision.confidence as f64,
        );
        (b as f32, k)
    } else {
        (decision.confidence, vec![])
    };

    if boosted_confidence > decision.confidence {
        info!(
            incident_id = %incident.incident_id,
            base_confidence = decision.confidence,
            boosted_confidence,
            correlated_detectors = ?correlated_detectors,
            "cross-detector correlation boost applied"
        );
        decision.confidence = boosted_confidence;
        decision.reason = format!(
            "{} [correlated: {}]",
            decision.reason,
            correlated_detectors.join(", ")
        );
    }

    info!(
        incident_id = %incident.incident_id,
        action = ?decision.action,
        confidence = decision.confidence,
        auto_execute = decision.auto_execute,
        reason = %decision.reason,
        "AI decision"
    );
}
