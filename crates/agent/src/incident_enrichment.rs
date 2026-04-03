use tracing::info;

use crate::{abuseipdb, attacker_intel, geoip, AgentState};

pub(crate) fn log_threat_feed_match(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) {
    // Threat feed gate: if the IP is in any threat feed, log it for enrichment.
    // This is informational - does not auto-block (feeds may have false positives).
    let Some(tf) = state.threat_feed.as_ref() else {
        return;
    };

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        if tf.is_known_malicious_ip(ip) {
            info!(
                ip,
                incident_id = %incident.incident_id,
                "threat feed match: IP found in external IOC feed"
            );
        }
    }
}

pub(crate) async fn lookup_incident_geoip(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<geoip::GeoInfo> {
    let Some(client) = state.geoip_client.as_ref() else {
        return None;
    };

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        client.lookup(ip).await
    } else {
        None
    }
}

pub(crate) fn enrich_attacker_identity(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
    ip_geo: Option<&geoip::GeoInfo>,
    ip_reputation: Option<&abuseipdb::IpReputation>,
) {
    // Enrich attacker profile with GeoIP + AbuseIPDB (only on first encounter).
    if ip_geo.is_none() && ip_reputation.is_none() {
        return;
    }

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        let crowdsec_listed = state
            .crowdsec
            .as_ref()
            .is_some_and(|cs| cs.is_known_threat(ip));
        if let Some(profile) = state.attacker_profiles.get_mut(ip) {
            if profile.geo.is_none() || profile.abuseipdb_score.is_none() {
                attacker_intel::enrich_identity(profile, ip_geo, ip_reputation, crowdsec_listed);
            }
        }
    }
}
