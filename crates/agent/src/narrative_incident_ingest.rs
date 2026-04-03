use std::path::Path;

use anyhow::Result;
use tracing::info;

use crate::{correlation_engine, reader, AgentState};

/// Ingest newly written incidents and update narrative/correlation state.
pub(crate) fn ingest_new_incidents(
    data_dir: &Path,
    today: &str,
    state: &mut AgentState,
) -> Result<()> {
    // Also ingest any new incidents incrementally
    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
    let new_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        state.narrative_incidents_offset,
    )
    .inspect_err(|_| {
        state.telemetry.observe_error("incident_reader");
    })?;
    if !new_incidents.entries.is_empty() {
        state.narrative_acc.ingest_incidents(&new_incidents.entries);
        state.narrative_incidents_offset = new_incidents.new_offset;

        // Feed incidents into cross-layer correlation engine
        for incident in &new_incidents.entries {
            let corr_event = correlation_engine::CorrelationEngine::classify_incident(incident);
            state.correlation_engine.observe(corr_event);
        }

        // Check for completed attack chains
        let chains = state.correlation_engine.drain_completed();
        for chain in &chains {
            info!(
                chain_id = %chain.chain_id,
                rule = %chain.rule_id,
                name = %chain.rule_name,
                stages = chain.stages_matched,
                layers = chain.layers_involved.len(),
                confidence = chain.confidence,
                "cross-layer attack chain detected: {}",
                chain.summary
            );

            // Evaluate chain-triggered playbooks
            for incident in &new_incidents.entries {
                if let Some(exec) = state
                    .playbook_engine
                    .evaluate_chain(&chain.rule_id, incident)
                {
                    info!(
                        playbook = %exec.playbook_id,
                        chain = %chain.rule_id,
                        steps = exec.steps.len(),
                        "chain-triggered playbook: {}",
                        exec.playbook_name
                    );
                }
            }
        }

        // Persist detected chains to JSON for dashboard
        if !chains.is_empty() {
            let chains_path = data_dir.join("attack-chains.json");
            let mut existing: Vec<serde_json::Value> = std::fs::read_to_string(&chains_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for chain in &chains {
                if let Ok(val) = serde_json::to_value(chain) {
                    existing.push(val);
                }
            }
            // Keep last 100 chains
            if existing.len() > 100 {
                existing = existing.split_off(existing.len() - 100);
            }
            let _ = std::fs::write(
                &chains_path,
                serde_json::to_string(&existing).unwrap_or_default(),
            );
        }

        // Check for multi-low elevation
        if let Some(chain) = state.correlation_engine.check_multi_low_elevation() {
            info!(
                chain_id = %chain.chain_id,
                "multi-low severity elevation: {}",
                chain.summary
            );
        }
    }

    Ok(())
}
