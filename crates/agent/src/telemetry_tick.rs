use tracing::warn;

use crate::AgentState;

/// Persist a telemetry snapshot for a loop tick and record writer failures.
pub(crate) fn write_tick_snapshot(state: &mut AgentState, tick_name: &str) {
    let snapshot = state.telemetry.snapshot(tick_name);
    let mut telemetry_write_failed = false;
    if let Some(writer) = &mut state.telemetry_writer {
        if let Err(e) = writer.write(&snapshot) {
            warn!("failed to write telemetry snapshot: {e:#}");
            telemetry_write_failed = true;
        }
    }
    if telemetry_write_failed {
        state.telemetry.observe_error("telemetry_writer");
    }
}
