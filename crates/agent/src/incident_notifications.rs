use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::guardian_mode;
use crate::{config, state_store, web_push, webhook, AgentState};

pub(crate) struct NotificationThresholds {
    pub(crate) webhook_min_rank: Option<u8>,
    pub(crate) telegram_min_rank: Option<u8>,
    pub(crate) slack_min_rank: Option<u8>,
}

pub(crate) fn compute_notification_thresholds(
    cfg: &config::AgentConfig,
    state: &AgentState,
) -> NotificationThresholds {
    let webhook_min_rank = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(webhook::severity_rank(&cfg.webhook.parsed_min_severity()))
    } else {
        None
    };

    let telegram_min_rank = if cfg.telegram.enabled && state.telegram_client.is_some() {
        Some(webhook::severity_rank(&cfg.telegram.parsed_min_severity()))
    } else {
        None
    };

    let slack_min_rank = if cfg.slack.enabled && state.slack_client.is_some() {
        Some(webhook::severity_rank(&cfg.slack.parsed_min_severity()))
    } else {
        None
    };

    NotificationThresholds {
        webhook_min_rank,
        telegram_min_rank,
        slack_min_rank,
    }
}

pub(crate) async fn dispatch_incident_notifications(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    thresholds: &NotificationThresholds,
) {
    // Notification cooldown - suppress duplicate alerts for the same entity
    // within a 10-minute window. Prevents alert spam during sustained attacks.
    let notify_cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(crate::NOTIFICATION_COOLDOWN_SECS);
    let notify_keys = crate::notification_cooldown_keys(incident);
    let notify_suppressed = notify_keys.iter().any(|k| {
        state
            .store
            .get_cooldown(state_store::CooldownTable::Notification, k)
            .is_some_and(|ts| ts > notify_cutoff)
    });

    if notify_suppressed {
        info!(
            incident_id = %incident.incident_id,
            "notification cooldown: suppressing duplicate alert"
        );
        return;
    }

    let incident_rank = webhook::severity_rank(&incident.severity);

    // Webhook - fires for ALL incidents above configured threshold.
    if let Some(min_rank) = thresholds.webhook_min_rank {
        if incident_rank >= min_rank {
            if let Err(e) = webhook::send_incident(
                &cfg.webhook.url,
                cfg.webhook.timeout_secs,
                incident,
                &cfg.webhook.format,
            )
            .await
            {
                state.telemetry.observe_error("webhook");
                warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
            }
        }
    }

    // Telegram T.1 - push notification for incidents above configured threshold.
    // Batching: first occurrence of a detector goes immediately.
    if let Some(min_rank) = thresholds.telegram_min_rank {
        if incident_rank >= min_rank {
            let tg = state.telegram_client.clone();
            if let Some(tg) = tg {
                if state.telegram_batcher.should_send_immediately(incident) {
                    let mode = guardian_mode(cfg);
                    let is_simple = cfg.telegram.is_simple_profile();
                    if let Err(e) = tg.send_incident_alert(incident, mode, is_simple).await {
                        warn!(incident_id = %incident.incident_id, "Telegram alert failed: {e:#}");
                    }
                }
                state.telegram_batcher.record(incident);
            }
        }
    }

    // Slack - push notification via Incoming Webhook.
    if let Some(min_rank) = thresholds.slack_min_rank {
        if incident_rank >= min_rank {
            if let Some(ref sc) = state.slack_client {
                let dashboard_url = if cfg.slack.dashboard_url.is_empty() {
                    None
                } else {
                    Some(cfg.slack.dashboard_url.as_str())
                };
                if let Err(e) = sc.send_incident_alert(incident, dashboard_url).await {
                    warn!(incident_id = %incident.incident_id, "Slack alert failed: {e:#}");
                }
            }
        }
    }

    // Web Push - browser notification.
    web_push::notify_incident(incident, data_dir, &cfg.web_push).await;

    // Mark notification cooldown for all entities in this incident.
    let now = chrono::Utc::now();
    for k in &notify_keys {
        state
            .store
            .set_cooldown(state_store::CooldownTable::Notification, k, now);
    }
}
