use tracing::warn;

use crate::{ai, attacker_intel, config, decisions, AgentState};

/// Write the main decision entry to the audit trail and mirror it into attacker intel.
pub(crate) fn write_decision_audit_entry(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    decision: &ai::AiDecision,
    execution_result: &str,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            provider_name,
            decision,
            cfg.responder.dry_run,
            execution_result,
        );
        // Attacker intelligence: observe this decision.
        if let Some(ref ip) = entry.target_ip {
            if let Some(profile) = state.attacker_profiles.get_mut(ip) {
                attacker_intel::observe_decision(profile, &entry);
            }
        }
        if let Err(e) = writer.write(&entry) {
            state.telemetry.observe_error("decision_writer");
            warn!("failed to write decision entry: {e:#}");
        }
    }
}
