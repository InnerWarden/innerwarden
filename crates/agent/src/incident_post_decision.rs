use std::collections::HashSet;

use tracing::{info, warn};

use crate::{
    adaptive_block_ttl_secs, ai, allowlist, config, decision_cooldown_key_for_decision,
    state_store, AgentState, LocalIpReputation,
};

/// Apply post-decision safeguards and state updates before execution.
/// Includes protected-IP sandboxing, decision cooldown registration,
/// per-tick dedup state updates, and repeat-offender annotation.
pub(crate) fn apply_post_decision_safeguards(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    blocked_set: &mut HashSet<String>,
) {
    // Protected IP sandbox: if AI tries to block a protected IP (RFC 1918,
    // loopback, or operator-configured ranges), downgrade to ignore.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        if allowlist::is_ip_allowlisted(ip, &cfg.ai.protected_ips) {
            warn!(
                ip = %ip,
                incident_id = %incident.incident_id,
                "AI tried to block protected IP {ip} - downgraded to ignore"
            );
            *decision = ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: format!(
                        "protected IP: AI recommended blocking {ip} but it matches a protected range"
                    ),
                },
                confidence: decision.confidence,
                auto_execute: false,
                reason: format!(
                    "{} [BLOCKED: target IP {ip} is in protected range]",
                    decision.reason
                ),
                alternatives: decision.alternatives.clone(),
                estimated_threat: decision.estimated_threat.clone(),
            };
        }
    }

    // Update the in-memory blocked_set immediately after a BlockIp decision.
    // This prevents a second incident from the same IP (arriving in the same 2s tick)
    // from triggering a duplicate AI call. The actual blocklist persists separately;
    // this is only a per-tick deduplication guard.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        blocked_set.insert(ip.clone());
    }

    // Record decision cooldown so the same action:detector:entity scope is not
    // re-evaluated by AI within the cooldown window (default 1h).
    if let Some(key) = decision_cooldown_key_for_decision(incident, decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    // Update in-memory blocklist immediately for BlockIp decisions so subsequent
    // ticks don't re-evaluate the same IP even when the responder is disabled or
    // dry_run is true. Without this, state.blocklist is only updated inside
    // execute_decision (which is skipped when responder.enabled = false), leaving
    // cross-tick deduplication to the cooldown alone - which breaks on restart if
    // the decision was not yet flushed to the decisions file.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        state.blocklist.insert(ip.clone());

        // Track repeat offenders: increment the block count for this IP.
        // When an IP has been blocked more than once, annotate the decision
        // reason so it surfaces in the audit trail and notifications.
        let block_count = state.store.increment_block_count(ip);

        // Update local IP reputation - record incident + block.
        let rep = state
            .ip_reputations
            .entry(ip.clone())
            .or_insert_with(LocalIpReputation::new);
        rep.record_incident();
        rep.record_block();
        let ttl_secs = adaptive_block_ttl_secs(rep.total_blocks);
        let ttl_label = match ttl_secs {
            t if t >= 604800 => format!("{} days", t / 86400),
            t if t >= 86400 => format!("{} hours", t / 3600),
            t => format!("{} hours", t / 3600),
        };
        info!(
            ip = %ip,
            total_blocks = rep.total_blocks,
            reputation_score = rep.reputation_score,
            ttl = ttl_label,
            "adaptive TTL applied"
        );

        if block_count > 1 {
            warn!(ip = %ip, block_count, "repeat offender detected");
            decision.reason = format!(
                "{} [repeat offender - blocked {} times, TTL {}]",
                decision.reason, block_count, ttl_label
            );
        }
    }
}
