use std::path::Path;

use tracing::{info, warn};

use crate::{abuseipdb, ai, config, skills, AgentState};

/// Execute the layered `BlockIp` decision path (XDP + firewall + Cloudflare + AbuseIPDB report).
pub(crate) async fn execute_block_ip_decision(
    ip: &str,
    skill_id: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // Safeguard: reject empty IPs.
    if ip.is_empty() {
        warn!("block decision has empty IP - skipping");
        return ("skipped: block decision has empty IP".to_string(), false);
    }

    // Safeguard: rate limit.
    // Prevent false-positive cascades - max N blocks per minute.
    let now_utc = chrono::Utc::now();
    let one_minute_ago = now_utc - chrono::Duration::seconds(60);
    state.recent_blocks.retain(|ts| *ts > one_minute_ago);
    if state.recent_blocks.len() >= crate::MAX_BLOCKS_PER_MINUTE {
        warn!(
            ip,
            blocks_last_minute = state.recent_blocks.len(),
            "rate limit: too many blocks in last minute, skipping"
        );
        return (
            format!(
                "rate-limited: {ip} (>{} blocks/min)",
                crate::MAX_BLOCKS_PER_MINUTE
            ),
            false,
        );
    }
    state.recent_blocks.push_back(now_utc);

    // Adaptive TTL: use local IP reputation to escalate block duration.
    let block_ttl_secs = {
        let total_blocks = state
            .ip_reputations
            .get(ip)
            .map(|r| r.total_blocks)
            .unwrap_or(0);
        crate::adaptive_block_ttl_secs(total_blocks)
    };

    let ctx = skills::SkillContext {
        incident: incident.clone(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: Some(block_ttl_secs as u64),
        host: incident.host.clone(),
        data_dir: data_dir.to_path_buf(),
        honeypot: crate::honeypot_runtime(cfg),
        ai_provider: state.ai_provider.clone(),
    };

    let mut layers_applied = Vec::new();
    let mut any_success = false;

    // Layer 1: XDP wire-speed drop (if available).
    if let Some(xdp_skill) = state.skill_registry.get("block-ip-xdp") {
        let xdp_result = xdp_skill.execute(&ctx, cfg.responder.dry_run).await;
        if xdp_result.success {
            layers_applied.push("XDP");
            any_success = true;
            // Track for TTL expiration (with per-IP adaptive TTL).
            state
                .xdp_block_times
                .insert(ip.to_string(), (chrono::Utc::now(), block_ttl_secs));
        }
    }

    // Layer 2: Firewall rule (ufw/iptables/nftables - configured backend).
    // The configured block_backend is always allowed, regardless of allowed_skills.
    let effective_id: String = if cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
        skill_id.to_string()
    } else {
        format!("block-ip-{}", cfg.responder.block_backend)
    };
    // Don't double-execute if the configured backend IS xdp.
    if effective_id != "block-ip-xdp" {
        if let Some(fw_skill) = state.skill_registry.get(&effective_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        }) {
            let fw_result = fw_skill.execute(&ctx, cfg.responder.dry_run).await;
            if fw_result.success {
                let backend = cfg.responder.block_backend.as_str();
                layers_applied.push(match backend {
                    "iptables" => "iptables",
                    "nftables" => "nftables",
                    _ => "ufw",
                });
                any_success = true;
            } else {
                warn!(
                    ip,
                    skill = effective_id,
                    reason = fw_result.message,
                    "firewall block skill execution failed"
                );
            }
        } else {
            warn!(
                ip,
                skill = effective_id,
                "firewall block skill not found in registry"
            );
        }
    }

    if any_success {
        state.blocklist.insert(ip.to_string());

        // Feedback loop: write blocked IP to file so the sensor can
        // skip events from this IP, reducing noise.
        crate::append_blocked_ip(data_dir, ip);

        // Layer 2.5: Mesh broadcast -- share with peer nodes.
        if let Some(ref mesh) = state.mesh {
            let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
            let evidence = decision.reason.as_bytes();
            mesh.broadcast_local_block(
                ip,
                detector,
                decision.confidence,
                evidence,
                block_ttl_secs as u64,
            )
            .await;
            layers_applied.push("Mesh");
        }
    }

    // Layer 3: Cloudflare edge block.
    let mut cf_pushed = false;
    if any_success && cfg.cloudflare.enabled && cfg.cloudflare.auto_push_blocks {
        if let Some(ref cf) = state.cloudflare_client {
            let reason = format!("{}: {}", incident.incident_id, decision.reason);
            if let Some(rule_id) = cf.push_block(ip, &reason).await {
                info!(ip, rule_id, "Cloudflare edge block pushed");
                layers_applied.push("Cloudflare");
                cf_pushed = true;
            }
        }
    }

    // Layer 4: AbuseIPDB community report (delayed - 5 min grace period).
    // Reports are queued and sent after ABUSEIPDB_REPORT_DELAY_SECS to allow
    // false-positive correction before permanently marking an IP as malicious.
    if any_success && cfg.abuseipdb.enabled && cfg.abuseipdb.report_blocks {
        let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
        let categories = abuseipdb::detector_to_categories(detector);
        let comment = format!(
            "InnerWarden auto-block: {} (confidence {:.0}%)",
            decision.reason,
            decision.confidence * 100.0
        );
        state.abuseipdb_report_queue.push((
            ip.to_string(),
            comment,
            categories.to_string(),
            chrono::Utc::now(),
        ));
        layers_applied.push("AbuseIPDB(queued)");
    }

    if any_success {
        let layers = layers_applied.join(" + ");
        (format!("Blocked {ip} via {layers}"), cf_pushed)
    } else {
        (format!("skipped: no block skill available for {ip}"), false)
    }
}
