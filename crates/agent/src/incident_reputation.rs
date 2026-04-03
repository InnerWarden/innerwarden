use crate::{abuseipdb, AgentState};

/// Lookup AbuseIPDB reputation for the incident primary IP, when enabled.
pub(crate) async fn lookup_abuseipdb_reputation(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<abuseipdb::IpReputation> {
    let client = state.abuseipdb.as_ref()?;

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        client.check(ip).await
    } else {
        None
    }
}
