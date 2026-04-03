use std::collections::HashMap;
use std::path::Path;

use chrono::Timelike as _;
use tracing::{info, warn};

use crate::{bot_helpers, config, narrative, telegram, AgentState};

/// Regenerate daily markdown summary and send Telegram digest when due.
pub(crate) async fn maybe_write_daily_summary_and_digest(
    data_dir: &Path,
    today: &str,
    events_count: usize,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            // Generate synthetic events from accumulated counters (no file I/O)
            let all_events_synthetic = state.narrative_acc.synthetic_events();
            let all_incidents_ref = &state.narrative_acc.incidents;

            let host = all_incidents_ref
                .first()
                .map(|i| i.host.as_str())
                .unwrap_or("unknown");

            let responder_hint = narrative::ResponderHint {
                enabled: cfg.responder.enabled,
                dry_run: cfg.responder.dry_run,
                has_block_ip: cfg
                    .responder
                    .allowed_skills
                    .iter()
                    .any(|s| s.starts_with("block-ip")),
            };
            let md = narrative::generate_with_responder(
                today,
                host,
                &all_events_synthetic,
                all_incidents_ref,
                cfg.correlation.window_seconds,
                responder_hint,
            );
            if let Err(e) = narrative::write(data_dir, today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");

                // Daily Telegram digest
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        if let Some(tg) = &state.telegram_client {
                            let is_simple = cfg.telegram.is_simple_profile();
                            // Count incidents by severity and top detector
                            let mut incidents_today: u32 = 0;
                            let mut critical_count: u32 = 0;
                            let mut high_count: u32 = 0;
                            let mut detector_counts: HashMap<String, u32> = HashMap::new();
                            for inc in &state.narrative_acc.incidents {
                                incidents_today += 1;
                                match inc.severity {
                                    innerwarden_core::event::Severity::Critical => {
                                        critical_count += 1;
                                    }
                                    innerwarden_core::event::Severity::High => {
                                        high_count += 1;
                                    }
                                    _ => {}
                                }
                                let det = telegram::extract_detector_pub(&inc.incident_id);
                                *detector_counts.entry(det.to_string()).or_insert(0) += 1;
                            }
                            let blocks_today = bot_helpers::count_jsonl_lines(
                                data_dir,
                                &format!("decisions-{today}.jsonl"),
                            ) as u32;
                            let (top_detector, top_count) = detector_counts
                                .iter()
                                .max_by_key(|(_, c)| *c)
                                .map(|(d, c)| (d.as_str(), *c))
                                .unwrap_or(("none", 0));
                            let text = telegram::format_daily_digest(
                                incidents_today,
                                blocks_today,
                                critical_count,
                                high_count,
                                top_detector,
                                top_count,
                                is_simple,
                            );
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    state.last_daily_summary_telegram = Some(today_naive);
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }
                    }
                }
            }
        }
    }
}
