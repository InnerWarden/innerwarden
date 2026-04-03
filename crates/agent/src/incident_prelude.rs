use tracing::{info, warn};

use crate::{config, AgentState};

/// Run pre-AI orchestration for one incident:
/// 1) temporal correlation lookup/observe
/// 2) one-way LSM auto-enable escalation when a high-risk execution pattern appears
pub(crate) async fn prepare_incident_prelude(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Vec<innerwarden_core::incident::Incident> {
    let related_incidents = if cfg.correlation.enabled {
        state
            .correlator
            .related_to(incident, cfg.correlation.max_related_incidents)
    } else {
        Vec::new()
    };

    if cfg.correlation.enabled {
        if !related_incidents.is_empty() {
            info!(
                incident_id = %incident.incident_id,
                correlated_count = related_incidents.len(),
                "temporal correlation: related incidents found"
            );
        }
        // Observe early so correlation history stays consistent even when this
        // incident is later skipped by gate or AI call fails.
        state.correlator.observe(incident);
    }

    // 0. LSM auto-enable - when we see a high-severity execution incident
    //    (download+execute, reverse shell, /tmp execution), automatically enable
    //    LSM enforcement to block future execution from dangerous paths.
    //    This is a one-way escalation: once enabled, stays on until reboot.
    if crate::should_auto_enable_lsm(incident) && !state.lsm_enabled {
        info!(
            incident_id = %incident.incident_id,
            "LSM auto-enable: high-severity execution threat detected - activating kernel enforcement"
        );
        match crate::enable_lsm_enforcement().await {
            Ok(()) => {
                state.lsm_enabled = true;
                info!(
                    "LSM enforcement activated - /tmp, /dev/shm, /var/tmp execution now blocked at kernel level"
                );
            }
            Err(e) => {
                warn!(error = %e, "LSM auto-enable failed (BPF LSM may not be available)");
            }
        }
    }

    related_incidents
}
