use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    abuseipdb, ai, allowlist, attacker_intel, cloud_safelist, config,
    decision_cooldown_key_for_decision, decisions, execute_decision, state_store, AgentState,
};

/// AbuseIPDB gate: auto-block high-confidence malicious IPs before AI analysis.
/// Returns true when the incident is fully handled (auto-block path).
pub(crate) async fn try_handle_abuseipdb_autoblock(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    ip_reputation: Option<&abuseipdb::IpReputation>,
    blocked_set: &mut HashSet<String>,
) -> bool {
    let Some(rep) = ip_reputation else {
        return false;
    };

    let threshold = cfg.abuseipdb.auto_block_threshold;
    if threshold == 0 || rep.confidence_score < threshold {
        return false;
    }

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let Some(ip) = primary_ip else {
        return false;
    };

    // Protected IP check: skip auto-block for protected ranges.
    if allowlist::is_ip_allowlisted(&ip, &cfg.ai.protected_ips) {
        warn!(
            ip = %ip,
            incident_id = %incident.incident_id,
            "AbuseIPDB auto-block tried to block protected IP {ip} - skipped"
        );
        return false;
    }

    if cloud_safelist::is_cloud_provider_ip(&ip) {
        let provider = cloud_safelist::identify_provider(&ip).unwrap_or("Unknown Cloud");
        warn!(
            ip = %ip,
            provider,
            score = rep.confidence_score,
            incident_id = %incident.incident_id,
            "AbuseIPDB auto-block skipped: {ip} belongs to {provider}. \
             Sending to AI for evaluation instead."
        );
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        score = rep.confidence_score,
        threshold,
        "AbuseIPDB auto-block: score exceeds threshold, skipping AI"
    );

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id,
        },
        confidence: 1.0,
        auto_execute: true,
        reason: format!(
            "AbuseIPDB auto-block: score={}/100 (threshold={})",
            rep.confidence_score, threshold
        ),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    let (execution_result, _cf_pushed) = if cfg.responder.enabled {
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await
    } else {
        ("skipped: responder disabled".to_string(), false)
    };

    // Only mark as blocked if the execution actually succeeded.
    // Previously this was BEFORE execute_decision, so failed blocks
    // (e.g., XDP map missing) still marked the IP as "blocked",
    // causing the AI gate to skip all future detections for this IP.
    if !execution_result.starts_with("skipped") && !execution_result.starts_with("rate-limited") {
        blocked_set.insert(ip.clone());
        state.blocklist.insert(ip.clone());
    } else {
        warn!(
            ip,
            execution_result, "AbuseIPDB auto-block: execution failed, IP NOT marked as blocked"
        );
    }

    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            "abuseipdb",
            &auto_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Some(profile) = state.attacker_profiles.get_mut(&ip) {
            attacker_intel::observe_decision(profile, &entry);
        }
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write abuseipdb auto-block decision: {e:#}");
        }
    }

    // Telegram notification for auto-block.
    if cfg.telegram.bot.enabled {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let ip_clone = ip.clone();
            let score = rep.confidence_score;
            let total_reports = rep.total_reports;
            let title_clone = incident.title.clone();
            let dry_run = cfg.responder.dry_run;
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            // Resolve GeoIP synchronously (already have client ref).
            let geo = if let Some(ref gc) = state.geoip_client {
                gc.lookup(&ip).await
            } else {
                None
            };
            // Enrich attacker profile with AbuseIPDB + GeoIP.
            if let Some(profile) = state.attacker_profiles.get_mut(&ip) {
                if profile.geo.is_none() {
                    let crowdsec_listed = state
                        .crowdsec
                        .as_ref()
                        .is_some_and(|cs| cs.is_known_threat(&ip));
                    attacker_intel::enrich_identity(
                        profile,
                        geo.as_ref(),
                        Some(rep),
                        crowdsec_listed,
                    );
                }
            }
            let country = geo.as_ref().map(|g| g.country_code.clone());
            let isp = geo.as_ref().map(|g| g.isp.clone());
            tokio::spawn(async move {
                let _ = tg
                    .send_abuseipdb_autoblock(
                        &ip_clone,
                        score,
                        threshold,
                        total_reports,
                        country.as_deref(),
                        isp.as_deref(),
                        &title_clone,
                        dry_run,
                        dashboard_url.as_deref(),
                    )
                    .await;
            });
        }
    }

    true
}
