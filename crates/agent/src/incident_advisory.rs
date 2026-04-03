use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use tracing::{info, warn};

use crate::dashboard::AdvisoryEntry;
use crate::AgentState;

pub(crate) async fn handle_advisory_violation(
    incident: &innerwarden_core::incident::Incident,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    state: &AgentState,
) {
    // Advisory correlation - check if this execution incident matches
    // a recent advisory denial from the /api/advisor/check-command endpoint.
    // If so, the AI agent ignored Inner Warden's security recommendation.
    if !incident.tags.contains(&"execution".to_string())
        && !incident.tags.contains(&"suspicious".to_string())
    {
        return;
    }

    let Some(advisory) = check_advisory_match(advisory_cache, incident) else {
        return;
    };

    info!(
        advisory_id = %advisory.advisory_id,
        command = %advisory.command_preview,
        risk_score = advisory.risk_score,
        "AI agent ignored security advisory"
    );

    // Send Telegram notification about the advisory violation
    if let Some(tg) = &state.telegram_client {
        let msg = format!(
            "\u{26a0}\u{fe0f} <b>Advisory Ignored</b>\n\n\
            Your AI agent executed a command that Inner Warden recommended <b>{}</b>.\n\n\
            <b>Command:</b> <code>{}</code>\n\
            <b>Risk score:</b> {}/100\n\
            <b>Signals:</b> {}\n\
            <b>Advisory ID:</b> <code>{}</code>\n\n\
            The command was executed despite the warning. Review the audit trail.",
            advisory.recommendation,
            advisory
                .command_preview
                .replace('<', "&lt;")
                .replace('>', "&gt;"),
            advisory.risk_score,
            advisory.signals.join(", "),
            advisory.advisory_id,
        );
        if let Err(e) = tg.send_raw_html(&msg).await {
            warn!("failed to send advisory ignored alert: {e:#}");
        }
    }

    // Remove the matched entry from cache (consumed)
    if let Ok(mut cache) = advisory_cache.write() {
        cache.retain(|e| e.advisory_id != advisory.advisory_id);
    }
}

fn check_advisory_match(
    cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    incident: &innerwarden_core::incident::Incident,
) -> Option<AdvisoryEntry> {
    // Extract command from incident evidence (array of evidence objects)
    let command = incident
        .evidence
        .as_array()?
        .iter()
        .find_map(|e| e.get("command").and_then(|c| c.as_str()))?;

    let command_hash = innerwarden_core::audit::sha256_hex(&command.to_lowercase());

    let cache = cache.read().ok()?;
    cache
        .iter()
        .find(|e| e.command_hash == command_hash)
        .cloned()
}
