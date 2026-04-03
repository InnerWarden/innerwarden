use tracing::info;

use crate::AgentState;

/// Best-effort forensics capture for high-severity incidents.
/// Captures /proc state by PID and selective pcap by primary attacker IP.
pub(crate) fn maybe_capture_incident_forensics(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) {
    if !matches!(
        incident.severity,
        innerwarden_core::event::Severity::High | innerwarden_core::event::Severity::Critical
    ) {
        return;
    }

    if let Some(pid) = incident.evidence.get("pid").and_then(|v| v.as_u64()) {
        let pid = pid as u32;
        if let Some(report) = state.forensics.try_capture(pid, &incident.incident_id) {
            info!(
                pid = report.pid,
                incident_id = %incident.incident_id,
                exe = ?report.exe,
                "forensics: process state captured"
            );
        }
    }

    // Selective pcap capture: capture traffic for the attacker IP.
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        if let Some(result) = state.pcap_capture.try_capture(ip, &incident.incident_id) {
            info!(
                ip = %result.ip,
                pcap = %result.pcap_path.display(),
                duration = result.duration_secs,
                "pcap: capture initiated for incident"
            );
        }
    }
}
