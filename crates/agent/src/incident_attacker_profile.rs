use crate::{attacker_intel, AgentState, LocalIpReputation};

/// Update local IP reputation and attacker profile for all IP entities in the incident.
pub(crate) fn update_incident_ip_profiles(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) {
    for entity in &incident.entities {
        if entity.r#type == innerwarden_core::entities::EntityType::Ip {
            state
                .ip_reputations
                .entry(entity.value.clone())
                .or_insert_with(LocalIpReputation::new)
                .record_incident();

            // Attacker intelligence: build unified profile.
            let profile = state
                .attacker_profiles
                .entry(entity.value.clone())
                .or_insert_with(|| attacker_intel::new_profile(&entity.value, incident.ts));
            attacker_intel::observe_incident(profile, incident);
        }
    }
}
