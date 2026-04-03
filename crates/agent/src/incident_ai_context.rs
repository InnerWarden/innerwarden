use std::collections::HashSet;

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Event;
use innerwarden_core::incident::Incident;

pub(crate) struct AiContextInputs<'a> {
    pub(crate) recent_events: Vec<&'a Event>,
    pub(crate) related_incidents: Vec<&'a Incident>,
}

/// Build AI context inputs for one incident.
/// Keeps context selection logic localized and out of `process_incidents`.
pub(crate) fn build_ai_context_inputs<'a>(
    incident: &Incident,
    all_events: &'a [Event],
    related_incidents: &'a [Incident],
    context_events: usize,
) -> AiContextInputs<'a> {
    let entity_ips: HashSet<&str> = incident
        .entities
        .iter()
        .filter(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str())
        .collect();
    let entity_users: HashSet<&str> = incident
        .entities
        .iter()
        .filter(|e| e.r#type == EntityType::User)
        .map(|e| e.value.as_str())
        .collect();

    let recent_events: Vec<&Event> = all_events
        .iter()
        .filter(|ev| {
            ev.entities.iter().any(|e| {
                (e.r#type == EntityType::Ip && entity_ips.contains(e.value.as_str()))
                    || (e.r#type == EntityType::User && entity_users.contains(e.value.as_str()))
            })
        })
        .rev()
        .take(context_events)
        .collect();
    let related_incidents: Vec<&Incident> = related_incidents.iter().collect();

    AiContextInputs {
        recent_events,
        related_incidents,
    }
}
