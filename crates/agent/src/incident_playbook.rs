use std::path::Path;

use tracing::info;

use crate::AgentState;

/// Evaluate playbooks for an incident and persist recent executions to JSON log.
pub(crate) fn maybe_evaluate_and_persist_playbook(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    state: &mut AgentState,
) {
    // Playbook evaluation: check if this incident triggers a playbook.
    if let Some(exec) = state.playbook_engine.evaluate(incident) {
        info!(
            playbook = %exec.playbook_id,
            incident = %exec.incident_id,
            steps = exec.steps.len(),
            "playbook triggered: {}",
            exec.playbook_name
        );

        // Persist playbook execution to JSON log.
        let log_path = data_dir.join("playbook-log.json");
        let mut log: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if let Ok(val) = serde_json::to_value(&exec) {
            log.push(val);
        }
        if log.len() > 100 {
            log = log.split_off(log.len() - 100);
        }
        let _ = std::fs::write(&log_path, serde_json::to_string(&log).unwrap_or_default());
    }
}
