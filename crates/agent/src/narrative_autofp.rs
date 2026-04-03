use std::path::Path;

use tracing::{info, warn};

use crate::{neural_lifecycle, state_store, telegram, AgentState};

/// Suggest permanent allowlist entries via Telegram based on repeated FP reports.
pub(crate) async fn maybe_suggest_allowlist_from_fp_reports(
    data_dir: &Path,
    state: &mut AgentState,
) {
    if state.telegram_client.is_none() {
        return;
    }

    // If any (detector, entity) pair has 3+ FP reports in last 7 days,
    // suggest permanent allowlist addition via Telegram.
    let fp_counts = neural_lifecycle::read_fp_report_counts(data_dir, 7);
    for (detector, entity, count) in &fp_counts {
        if *count >= 3 && !entity.is_empty() {
            // Cooldown: only suggest once per day per entity.
            let cooldown_key = format!("autofp_suggest:{entity}");
            if state
                .store
                .has_cooldown(state_store::CooldownTable::Notification, &cooldown_key)
            {
                continue;
            }

            let text = format!(
                "\u{1f4ca} <b>Auto-learn suggestion</b>\n\n\
                 <code>{entity}</code> has been reported as false positive \
                 {count} times for <code>{detector}</code>.\n\n\
                 Add to allowlist permanently?",
                entity = telegram::escape_html_pub(entity),
                detector = telegram::escape_html_pub(detector),
            );
            let is_ip = entity.parse::<std::net::IpAddr>().is_ok();
            let section = if is_ip { "ip" } else { "proc" };
            let yes_cb = format!("autofp:yes:{section}:{entity}");
            let no_cb = format!("autofp:no:{entity}");
            // Truncate callback data to 64 bytes.
            let yes_cb = telegram::truncate_callback_pub(&yes_cb);
            let no_cb = telegram::truncate_callback_pub(&no_cb);
            let keyboard = serde_json::json!([
                [
                    { "text": "\u{2705} Yes, allowlist", "callback_data": yes_cb },
                    { "text": "\u{274c} No, keep monitoring", "callback_data": no_cb }
                ]
            ]);

            if let Some(ref tg) = state.telegram_client {
                if let Err(e) = tg.send_text_with_keyboard(&text, keyboard).await {
                    warn!("failed to send auto-FP suggestion: {e:#}");
                } else {
                    state.store.set_cooldown(
                        state_store::CooldownTable::Notification,
                        &cooldown_key,
                        chrono::Utc::now(),
                    );
                    info!(
                        entity = %entity,
                        detector = %detector,
                        count = count,
                        "auto-FP suggestion sent to Telegram"
                    );
                }
            }
        }
    }
}
