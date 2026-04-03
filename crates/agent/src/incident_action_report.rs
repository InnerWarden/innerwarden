use crate::{abuseipdb, ai, config, geoip, AgentState};

/// Send a post-execution action report to Telegram when an action was executed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_send_post_execution_telegram_report(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    execution_result: &str,
    cloudflare_pushed: bool,
    cfg: &config::AgentConfig,
    state: &AgentState,
    ip_reputation: Option<&abuseipdb::IpReputation>,
    ip_geo: Option<&geoip::GeoInfo>,
) {
    // In GUARD/DryRun mode, send a post-execution Telegram report so the
    // operator knows what was done (action report replaces a manual ask).
    let was_executed = !execution_result.starts_with("skipped");
    if !was_executed || !cfg.telegram.bot.enabled {
        return;
    }

    let Some(ref tg) = state.telegram_client else {
        return;
    };

    use ai::AiAction;
    let (action_label, target) = match &decision.action {
        AiAction::BlockIp { ip, .. } => ("Blocked".to_string(), ip.clone()),
        AiAction::Monitor { ip } => ("Monitoring traffic from".to_string(), ip.clone()),
        AiAction::Honeypot { ip } => ("Redirected to honeypot".to_string(), ip.clone()),
        AiAction::SuspendUserSudo { user, .. } => ("Suspended sudo for".to_string(), user.clone()),
        AiAction::KillProcess { user, .. } => ("Killed processes for".to_string(), user.clone()),
        AiAction::BlockContainer { container_id, .. } => {
            ("Paused container".to_string(), container_id.clone())
        }
        AiAction::KillChainResponse { .. } => (
            "Kill chain response".to_string(),
            format!(
                "PID {}",
                incident.incident_id.split(':').nth(2).unwrap_or("-")
            ),
        ),
        AiAction::Ignore { .. } => ("Ignored".to_string(), "-".to_string()),
        AiAction::RequestConfirmation { .. } => {
            ("Requested confirmation for".to_string(), "-".to_string())
        }
    };

    let tg = tg.clone();
    let title = incident.title.clone();
    let host = incident.host.clone();
    let confidence = decision.confidence;
    let dry_run = cfg.responder.dry_run;
    let rep_clone = ip_reputation.cloned();
    let geo_clone = ip_geo.cloned();
    tokio::spawn(async move {
        let _ = tg
            .send_action_report(
                &action_label,
                &target,
                &title,
                confidence,
                &host,
                dry_run,
                rep_clone.as_ref(),
                geo_clone.as_ref(),
                cloudflare_pushed,
            )
            .await;
    });
}
