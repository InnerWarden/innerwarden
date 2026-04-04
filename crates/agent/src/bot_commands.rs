use std::path::Path;

use crate::agent_context::{build_agent_context, guardian_mode};
use crate::{bot_helpers, config, telegram, two_factor, AgentState};
use tracing::info;

/// Run an `innerwarden` CLI subcommand and return its stdout+stderr as a String.
/// Times out after 30 seconds. Used by /enable, /disable, /doctor bot commands.
pub(crate) async fn run_innerwarden_cli(args: &[&str]) -> String {
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("innerwarden")))
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/bin/innerwarden"));

    match tokio::process::Command::new(&bin).args(args).output().await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = format!("{stdout}{stderr}");
            // Strip ANSI color codes for Telegram
            strip_ansi(&combined)
        }
        Err(e) => format!("Failed to run innerwarden CLI: {e}"),
    }
}

/// Handle Telegram bot-only commands that do not depend on pending confirmations.
/// Returns true when a command/callback was matched and handled.
pub(crate) async fn handle_telegram_bot_command(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // /status callback
    if result.incident_id == "__status__" {
        info!(operator = %result.operator_name, "Telegram /status command received");
        if cfg.telegram.bot.enabled {
            if cfg.telegram.is_simple_profile() {
                // Simple profile: semaphore status
                let today = chrono::Local::now()
                    .date_naive()
                    .format("%Y-%m-%d")
                    .to_string();
                let decision_count =
                    bot_helpers::count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"))
                        as u64;

                // Check for recent critical/high incidents from narrative accumulator
                let now_utc = chrono::Utc::now();
                let one_hour_ago = now_utc - chrono::Duration::hours(1);
                let twenty_four_h_ago = now_utc - chrono::Duration::hours(24);
                let mut has_critical_last_hour = false;
                let mut has_high_last_hour = false;
                let mut has_critical_last_24h = false;
                let mut last_threat_ts: Option<chrono::DateTime<chrono::Utc>> = None;

                for inc in state.narrative_acc.incidents.iter().rev() {
                    if inc.ts > twenty_four_h_ago
                        && matches!(inc.severity, innerwarden_core::event::Severity::Critical)
                    {
                        has_critical_last_24h = true;
                    }
                    if inc.ts > one_hour_ago {
                        if matches!(inc.severity, innerwarden_core::event::Severity::Critical) {
                            has_critical_last_hour = true;
                        }
                        if matches!(inc.severity, innerwarden_core::event::Severity::High) {
                            has_high_last_hour = true;
                        }
                    }
                    if last_threat_ts.is_none() {
                        last_threat_ts = Some(inc.ts);
                    }
                }

                // Estimate uptime from the data directory's creation time
                let uptime_days = std::fs::metadata(data_dir)
                    .and_then(|m| m.created())
                    .map(|t| t.elapsed().map(|e| e.as_secs() / 86400).unwrap_or(0))
                    .unwrap_or(0);

                let last_threat_ago = match last_threat_ts {
                    Some(ts) => {
                        let diff = now_utc - ts;
                        if diff.num_hours() >= 24 {
                            format!("{} days ago", diff.num_days())
                        } else if diff.num_hours() >= 1 {
                            format!("{} hours ago", diff.num_hours())
                        } else {
                            format!("{} minutes ago", diff.num_minutes().max(1))
                        }
                    }
                    None => "no threats recorded".to_string(),
                };

                let text = telegram::format_simple_status(
                    has_critical_last_24h,
                    has_high_last_hour,
                    has_critical_last_hour,
                    uptime_days,
                    decision_count,
                    &last_threat_ago,
                );
                tg_reply(state, text);
            } else {
                // Technical profile: full status
                let today = chrono::Local::now()
                    .date_naive()
                    .format("%Y-%m-%d")
                    .to_string();
                let incident_count =
                    bot_helpers::count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
                let decision_count =
                    bot_helpers::count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
                let mode = guardian_mode(cfg);
                let mode_label = mode.label();
                let mode_desc = mode.description();
                let ai_label = if cfg.ai.enabled {
                    format!("{} / {}", cfg.ai.provider, cfg.ai.model)
                } else {
                    "not configured".to_string()
                };
                let host = std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string());
                let today_line = if incident_count == 0 {
                    "All quiet. No threat actors in the logs today.".to_string()
                } else if decision_count == 0 {
                    format!(
                        "{incident_count} intrusion attempt{} detected - none acted on yet.",
                        if incident_count == 1 { "" } else { "s" }
                    )
                } else {
                    format!(
                        "{incident_count} intrusion attempt{}, {decision_count} neutralized.",
                        if incident_count == 1 { "" } else { "s" }
                    )
                };
                let text = format!(
                    "\u{1f47e} <b>InnerWarden</b> - <b>{host}</b>\n\
                     \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
                     Mode: <b>{mode_label}</b>\n\
                     <i>{mode_desc}</i>\n\
                     \n\
                     AI: {ai_label}\n\
                     Today: {today_line}\n\
                     \n\
                     /threats \u{00b7} /decisions \u{00b7} /blocked",
                );
                tg_reply(state, text);
            }
        }
        return true;
    }

    // Sensitivity buttons from onboarding menu
    if let Some(level) = result.incident_id.strip_prefix("__sensitivity__:") {
        info!(operator = %result.operator_name, level, "Telegram sensitivity change");
        if let Some(ref tg) = state.telegram_client {
            let (emoji, desc) = match level {
                "quiet" => ("🔇", "Only Critical alerts (server compromised, privesc)"),
                "verbose" => ("🔊", "Medium, High, and Critical alerts"),
                _ => ("🔔", "High and Critical alerts (recommended)"),
            };
            let msg = format!(
                "{emoji} <b>Notification sensitivity: {level}</b>\n\n\
                 <i>{desc}</i>\n\n\
                 To apply permanently, run on server:\n\
                 <code>innerwarden configure sensitivity {level}</code>"
            );
            let tg = tg.clone();
            tokio::spawn(async move {
                let _ = tg.send_raw_html(&msg).await;
            });
        }
        return true;
    }

    // Profile toggle: "profile:simple" or "profile:technical"
    if let Some(profile) = result.incident_id.strip_prefix("__profile__:") {
        info!(operator = %result.operator_name, profile, "Telegram profile change");
        if let Some(ref tg) = state.telegram_client {
            let (emoji, desc) = match profile {
                "simple" => (
                    "✨",
                    "Simple mode. Plain language alerts, no technical details.",
                ),
                _ => (
                    "🔧",
                    "Technical mode. Full details, IPs, detectors, evidence.",
                ),
            };
            let msg = format!(
                "{emoji} <b>Profile: {profile}</b>\n\n\
                 <i>{desc}</i>\n\n\
                 To apply permanently, run on server:\n\
                 <code>innerwarden configure profile {profile}</code>"
            );
            let tg = tg.clone();
            tokio::spawn(async move {
                let _ = tg.send_raw_html(&msg).await;
            });
        }
        return true;
    }

    if result.incident_id == "__help__" {
        info!(operator = %result.operator_name, "Telegram /help command received");
        if cfg.telegram.bot.enabled {
            let text = "👾 <b>InnerWarden - Operator Playbook</b>\n\n\
                <b>Intel</b>\n\
                /status - mode, AI, today's threat intel\n\
                /threats - recent intrusion attempts\n\
                /decisions - actions I've taken\n\
                /blocked - threat actors contained\n\
                \n\
                <b>Configuration</b>\n\
                /capabilities - list all capabilities + status\n\
                /enable &lt;id&gt; - activate a capability\n\
                /disable &lt;id&gt; - deactivate a capability\n\
                /doctor - full health check with fix hints\n\
                \n\
                <b>Mode</b>\n\
                /guard - auto-defend (I act autonomously)\n\
                /watch - passive (I alert, you decide)\n\
                \n\
                <b>AI</b>\n\
                /ask &lt;question&gt; - ask anything, I know my config\n\
                <i>or just type - I'll understand</i>\n\
                \n\
                <b>On threat alerts:</b>\n\
                🛡 <b>Block</b> - drop this actor now\n\
                🙈 <b>Ignore</b> - false positive, stand down";
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__threats__" {
        info!(operator = %result.operator_name, "Telegram /threats command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let text = bot_helpers::read_last_incidents(data_dir, &today, 5);
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__decisions__" {
        info!(operator = %result.operator_name, "Telegram /decisions command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let text = bot_helpers::read_last_decisions(data_dir, &today, 5);
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__menu__" {
        info!(operator = %result.operator_name, "Telegram /menu command received");
        if cfg.telegram.bot.enabled {
            if let Some(ref tg) = state.telegram_client {
                let tg = tg.clone();
                let is_simple = cfg.telegram.is_simple_profile();
                tokio::spawn(async move {
                    let _ = tg.send_menu(is_simple).await;
                });
            }
        }
        return true;
    }

    // /undo command: show recent allowlist additions with remove buttons
    if result.incident_id == "__undo__" {
        info!(operator = %result.operator_name, "Telegram /undo command received");
        if cfg.telegram.bot.enabled {
            let entries = telegram::read_undoable_allowlist_entries(data_dir, 10);
            if entries.is_empty() {
                tg_reply(state, "\u{1f4cb} No recent allowlist additions to undo.");
            } else if let Some(ref tg) = state.telegram_client {
                let mut text = String::from(
                    "\u{1f5d1}\u{fe0f} <b>Recent allowlist additions</b>\nTap to remove:\n",
                );
                let mut keyboard_rows: Vec<serde_json::Value> = Vec::new();
                for (key, section, operator, ts) in &entries {
                    let ago = bot_helpers::format_time_ago(ts);
                    let sec_short = if section == "processes" { "proc" } else { "ip" };
                    text.push_str(&format!(
                        "\n\u{2022} <code>{}</code> ({}, {} by {})",
                        telegram::escape_html_pub(key),
                        sec_short,
                        ago,
                        telegram::escape_html_pub(operator),
                    ));
                    let cb = format!("undo:{sec_short}:{key}");
                    let cb = telegram::truncate_callback_pub(&cb);
                    keyboard_rows.push(serde_json::json!([{
                        "text": format!("\u{274c} Remove {}", &key[..key.len().min(20)]),
                        "callback_data": cb
                    }]));
                }
                let keyboard = serde_json::Value::Array(keyboard_rows);
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_text_with_keyboard(&text, keyboard).await;
                });
            }
        }
        return true;
    }

    // Undo execution: "undo:proc:<key>" or "undo:ip:<key>"
    if let Some(rest) = result.incident_id.strip_prefix("__undo__:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() == 2 {
            let sec_short = parts[0];
            let key = parts[1].trim();
            let section = if sec_short == "ip" {
                "ips"
            } else {
                "processes"
            };
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if bot_helpers::check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::UndoAllowlist {
                    section: section.to_string(),
                    key: key.to_string(),
                },
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");

            match telegram::remove_from_allowlist(allowlist_path, section, key) {
                Ok(()) => {
                    telegram::log_allowlist_change(
                        data_dir,
                        key,
                        section,
                        &result.operator_name,
                        "remove",
                    );
                    bot_helpers::write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_remove",
                        if sec_short == "ip" {
                            Some(key.to_string())
                        } else {
                            None
                        },
                        if sec_short == "proc" {
                            Some(format!("process:{key}"))
                        } else {
                            None
                        },
                        format!(
                            "Operator {} removed '{}' from {} allowlist via Telegram",
                            result.operator_name, key, section
                        ),
                        format!("allowlist_removed:{key}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        key = %key,
                        section = %section,
                        "Telegram undo: removed from allowlist"
                    );
                    tg_reply(
                        state,
                        format!(
                            "\u{2705} Removed <code>{}</code> from allowlist.",
                            telegram::escape_html_pub(key)
                        ),
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        operator = %result.operator_name,
                        key = %key,
                        error = %e,
                        "failed to remove from allowlist via Telegram undo"
                    );
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to remove <code>{}</code>: {}",
                            telegram::escape_html_pub(key),
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        return true;
    }

    // Auto-FP suggestion callback: "autofp:yes:proc:name" or "autofp:no:name"
    if let Some(rest) = result.incident_id.strip_prefix("__autofp__:") {
        if let Some(rest) = rest.strip_prefix("yes:") {
            // Format: "proc:name" or "ip:name"
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() == 2 {
                let sec_short = parts[0];
                let entity = parts[1].trim();
                let section = if sec_short == "ip" {
                    "ips"
                } else {
                    "processes"
                };
                // 2FA gate: if enabled, store pending and ask for TOTP code
                if bot_helpers::check_2fa_gate(
                    state,
                    cfg,
                    &result.operator_name,
                    two_factor::PendingActionType::AutoFpAllowlist {
                        section: section.to_string(),
                        entity: entity.to_string(),
                    },
                ) {
                    return true;
                }

                let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
                let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                let reason = format!("Auto-FP allowlist via Telegram ({ts})");

                match telegram::append_to_allowlist(allowlist_path, section, entity, &reason) {
                    Ok(()) => {
                        telegram::log_allowlist_change(
                            data_dir,
                            entity,
                            section,
                            &result.operator_name,
                            "add",
                        );
                        info!(
                            operator = %result.operator_name,
                            entity = %entity,
                            section = %section,
                            "auto-FP: added to allowlist"
                        );
                        tg_reply(
                            state,
                            format!(
                                "\u{2705} Added <code>{}</code> to {} allowlist permanently.",
                                telegram::escape_html_pub(entity),
                                section
                            ),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "auto-FP: failed to add to allowlist");
                        tg_reply(
                            state,
                            format!(
                                "\u{274c} Failed to add to allowlist: {}",
                                e.to_string().chars().take(180).collect::<String>()
                            ),
                        );
                    }
                }
            }
        } else {
            // "no:entity" - just acknowledge
            info!(operator = %result.operator_name, "auto-FP suggestion dismissed");
            tg_reply(state, "\u{1f440} OK, will keep monitoring.");
        }
        return true;
    }

    // Enable 2FA instructions
    if result.incident_id == "__enable2fa__" {
        info!(operator = %result.operator_name, "Telegram enable 2FA requested");
        tg_reply(
            state,
            "\u{1f510} <b>Enable 2FA</b>\n\n\
             Run this command on your server:\n\n\
             <code>innerwarden configure 2fa</code>\n\n\
             This will generate a QR code for Google Authenticator or any TOTP app.\n\
             After setup, all sensitive actions (allowlist, mode changes) will \
             require a 6-digit code.",
        );
        return true;
    }

    if result.incident_id == "__start__" {
        info!(operator = %result.operator_name, "Telegram /start command received");
        if cfg.telegram.bot.enabled {
            if let Some(ref tg) = state.telegram_client {
                let today = chrono::Local::now()
                    .date_naive()
                    .format("%Y-%m-%d")
                    .to_string();
                let incident_count =
                    bot_helpers::count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
                let decision_count =
                    bot_helpers::count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
                let mode = guardian_mode(cfg);
                let host = std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string());
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg
                        .send_onboarding(&host, incident_count, decision_count, mode)
                        .await;
                });
            }
        }
        return true;
    }

    if result.incident_id == "__guard__" {
        info!(operator = %result.operator_name, "Telegram /guard command received");
        if cfg.telegram.bot.enabled {
            let mode = guardian_mode(cfg);
            let text = match mode {
                telegram::GuardianMode::Guard => "🟢 <b>Already in GUARD mode.</b>\n\
                     I see a threat, I drop it. You get the action report after.\n\
                     High-confidence targets get neutralized - no questions asked.\n\n\
                     Switch to passive: <code>innerwarden configure responder</code> → option 1"
                    .to_string(),
                _ => {
                    format!(
                        "🟢 <b>GUARD mode</b> - full autonomous defense.\n\
                         When I'm confident, I act. You sleep, I don't.\n\n\
                         Activate on your server:\n\
                         <code>innerwarden configure responder</code>\n\
                         Pick option 3 (Live mode).\n\n\
                         Current: {} - <i>{}</i>",
                        mode.label(),
                        mode.description()
                    )
                }
            };
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__watch__" {
        info!(operator = %result.operator_name, "Telegram /watch command received");
        if cfg.telegram.bot.enabled {
            let mode = guardian_mode(cfg);
            let text = match mode {
                telegram::GuardianMode::Watch => "🔵 <b>Already in WATCH mode.</b>\n\
                     Eyes on everything, hands off. I detect and log - you call the shots.\n\
                     Good for baselining before going live.\n\n\
                     Go autonomous: <code>innerwarden configure responder</code> → option 3"
                    .to_string(),
                _ => {
                    format!(
                        "🔵 <b>WATCH mode</b> - passive recon, active alerts.\n\
                         Every IOC flagged, every anomaly logged. Your call on what gets dropped.\n\n\
                         Activate on your server:\n\
                         <code>innerwarden configure responder</code>\n\
                         Pick option 1 (Observe only).\n\n\
                         Current: {} - <i>{}</i>",
                        mode.label(),
                        mode.description()
                    )
                }
            };
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__blocked__" {
        info!(operator = %result.operator_name, "Telegram /blocked command received");
        if cfg.telegram.bot.enabled {
            let blocked: Vec<String> = state.blocklist.as_vec();
            let text = if blocked.is_empty() {
                "🛡 No kills this session - perimeter's been clean.\n\
                 <i>Previous firewall rules still active.</i>"
                    .to_string()
            } else {
                let mut sorted = blocked;
                sorted.sort();
                let list = sorted
                    .iter()
                    .map(|ip| format!("  <code>{ip}</code>"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "🛡 <b>Kill list</b> - {} contained this session\n\n{list}",
                    sorted.len()
                )
            };
            tg_reply(state, text);
        }
        return true;
    }

    if result.incident_id == "__unknown_cmd__" {
        info!(operator = %result.operator_name, "Telegram unknown command received");
        if cfg.telegram.bot.enabled {
            tg_reply(
                state,
                "Didn't catch that. /help for the full playbook - or just type what you need, I'll figure it out.",
            );
        }
        return true;
    }

    if let Some(question) = result.incident_id.strip_prefix("__ask__:") {
        let question = question.to_string();
        info!(operator = %result.operator_name, question = %question, "Telegram /ask command received");
        if cfg.telegram.bot.enabled {
            let today = chrono::Local::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            // Inject full system context so the AI knows exactly what's configured
            let agent_ctx = build_agent_context(cfg, data_dir);
            let recent_incidents = bot_helpers::read_last_incidents_raw(data_dir, &today, 3);
            let system_prompt = if recent_incidents.is_empty() {
                format!("{}\n\n{agent_ctx}", cfg.telegram.bot.personality)
            } else {
                format!(
                    "{}\n\n{agent_ctx}\n\nRECENT INCIDENTS (last 3):\n{recent_incidents}",
                    cfg.telegram.bot.personality
                )
            };

            if let Some(ref ai) = state.ai_provider {
                let ai = ai.clone();
                let tg = state.telegram_client.clone();
                tokio::spawn(async move {
                    if let Some(ref tg) = tg {
                        tg.send_typing().await;
                    }
                    match ai.chat(&system_prompt, &question).await {
                        Ok(reply) => {
                            if let Some(ref tg) = tg {
                                let _ = tg.send_text_message(&reply).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("AI chat error for Telegram /ask: {e:#}");
                            if let Some(ref tg) = tg {
                                let _ = tg
                                    .send_text_message(&format!(
                                        "Brain glitch: {}",
                                        e.to_string().chars().take(200).collect::<String>()
                                    ))
                                    .await;
                            }
                        }
                    }
                });
            } else {
                tg_reply(
                    state,
                    "No AI brain connected yet - I need one to answer questions.\n\nActivate:\n<code>innerwarden enable ai</code>\nor via /enable ai",
                );
            }
        }
        return true;
    }

    // /enable <capability> - run innerwarden enable <cap> as subprocess
    if let Some(cap_args) = result.incident_id.strip_prefix("__enable__:") {
        let cap_args = cap_args.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_args, "Telegram /enable command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                // Warn before executing destructive command
                if let Some(ref tg) = tg {
                    let _ = tg
                        .send_text_message(&format!(
                            "\u{26a0}\u{fe0f} Executing: <b>innerwarden enable {cap_args}</b>. Use the CLI for undo."
                        ))
                        .await;
                    tg.send_typing().await;
                }
                // Parse "block-ip --param backend=ufw" → ["enable", "block-ip", "--param", "backend=ufw"]
                let parts: Vec<&str> = cap_args.split_whitespace().collect();
                let mut args = vec!["enable"];
                args.extend(parts.iter().copied());
                let output = run_innerwarden_cli(&args).await;
                let text = format!(
                    "\u{1f527} <b>innerwarden enable {cap_args}</b>\n\n<pre>{output}</pre>",
                    cap_args = cap_args,
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return true;
    }

    // /disable <capability> - run innerwarden disable <cap> as subprocess
    if let Some(cap_args) = result.incident_id.strip_prefix("__disable__:") {
        let cap_args = cap_args.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_args, "Telegram /disable command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                // Warn before executing destructive command
                if let Some(ref tg) = tg {
                    let _ = tg
                        .send_text_message(&format!(
                            "\u{26a0}\u{fe0f} Executing: <b>innerwarden disable {cap_args}</b>. Use the CLI for undo."
                        ))
                        .await;
                    tg.send_typing().await;
                }
                let parts: Vec<&str> = cap_args.split_whitespace().collect();
                let mut args = vec!["disable"];
                args.extend(parts.iter().copied());
                let output = run_innerwarden_cli(&args).await;
                let text = format!(
                    "\u{1f527} <b>innerwarden disable {cap_args}</b>\n\n<pre>{output}</pre>",
                    cap_args = cap_args,
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return true;
    }

    // /doctor - run innerwarden doctor and show output
    if result.incident_id == "__doctor__" {
        info!(operator = %result.operator_name, "Telegram /doctor command received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                let output = run_innerwarden_cli(&["doctor"]).await;
                let text = format!(
                    "🩺 <b>System health check</b>\n\n<pre>{}</pre>",
                    output.chars().take(3000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return true;
    }

    // /capabilities - list capabilities and integrations with inline enable buttons
    if result.incident_id == "__capabilities__" {
        info!(operator = %result.operator_name, "Telegram /capabilities command received");
        if cfg.telegram.bot.enabled {
            let text = format_capabilities(cfg);
            let keyboard = capabilities_keyboard(cfg);
            if let Some(ref tg) = state.telegram_client {
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_text_with_keyboard(&text, keyboard).await;
                });
            }
        }
        return true;
    }

    // enable:<id> callback - from capabilities inline keyboard buttons
    if let Some(cap_id) = result.incident_id.strip_prefix("enable:") {
        let cap_id = cap_id.trim().to_string();
        info!(operator = %result.operator_name, cap = %cap_id, "Telegram enable callback received");
        if cfg.telegram.bot.enabled {
            let tg = state.telegram_client.clone();
            tokio::spawn(async move {
                if let Some(ref tg) = tg {
                    tg.send_typing().await;
                }
                // fail2ban uses `innerwarden integrate fail2ban` instead of `enable`
                // honeypot uses `innerwarden enable honeypot` (standard path)
                let output = if cap_id == "fail2ban" {
                    run_innerwarden_cli(&["integrate", "fail2ban"]).await
                } else {
                    run_innerwarden_cli(&["enable", &cap_id]).await
                };
                let cmd_label = if cap_id == "fail2ban" {
                    format!("innerwarden integrate {cap_id}")
                } else {
                    format!("innerwarden enable {cap_id}")
                };
                let text = format!(
                    "🔧 <b>{cmd_label}</b>\n\n<pre>{output}</pre>",
                    output = output.chars().take(2000).collect::<String>()
                );
                if let Some(ref tg) = tg {
                    let _ = tg.send_text_message(&text).await;
                }
            });
        }
        return true;
    }

    false
}

/// Build a Telegram-formatted capabilities list from the live agent config.
/// Avoids running the CTL CLI subprocess (which may be stale) and produces
/// clean HTML output suited for Telegram's parse_mode=HTML.
pub(crate) fn format_capabilities(cfg: &config::AgentConfig) -> String {
    let on = "🟢";
    let off = "🔴";

    // Core capabilities
    let ai_line = if cfg.ai.enabled {
        format!(
            "{on} <b>AI Analysis</b>  <code>{} / {}</code>",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        format!("{off} <b>AI Analysis</b>  disabled\n    <i>/enable ai --param provider=openai</i>")
    };

    let block_line = if cfg.responder.enabled {
        let mode = if cfg.responder.dry_run {
            "dry-run"
        } else {
            "live"
        };
        format!(
            "{on} <b>Block IP</b>  {} backend - {mode}",
            cfg.responder.block_backend
        )
    } else {
        format!("{off} <b>Block IP</b>  disabled\n    <i>/enable block-ip</i>")
    };

    let sudo_line = if cfg
        .responder
        .allowed_skills
        .iter()
        .any(|s| s.contains("suspend-user"))
    {
        format!("{on} <b>Sudo Protection</b>  active")
    } else {
        format!("{off} <b>Sudo Protection</b>  disabled\n    <i>/enable sudo-protection</i>")
    };

    // Integrations
    let abuseipdb_line = if cfg.abuseipdb.enabled {
        format!("{on} <b>AbuseIPDB</b>  IP reputation enrichment")
    } else {
        format!("{off} <b>AbuseIPDB</b>  disabled - <i>/enable abuseipdb</i>")
    };

    let geoip_line = if cfg.geoip.enabled {
        format!("{on} <b>GeoIP</b>  ip-api.com (free)")
    } else {
        format!("{off} <b>GeoIP</b>  disabled - <i>/enable geoip</i>")
    };

    let fail2ban_line = if cfg.fail2ban.enabled {
        format!("{on} <b>Fail2ban</b>  ban sync active")
    } else {
        format!("{off} <b>Fail2ban</b>  disabled - <i>/enable fail2ban</i>")
    };

    let slack_line = if cfg.slack.enabled {
        format!("{on} <b>Slack</b>  notifications enabled")
    } else {
        format!("{off} <b>Slack</b>  disabled - <i>/enable slack</i>")
    };

    let cloudflare_line = if cfg.cloudflare.enabled {
        format!("{on} <b>Cloudflare</b>  edge block push active")
    } else {
        format!("{off} <b>Cloudflare</b>  disabled - <i>/enable cloudflare</i>")
    };

    format!(
        "⚙️ <b>Capabilities</b>\n\
         \n\
         <b>Core</b>\n\
         {ai_line}\n\
         {block_line}\n\
         {sudo_line}\n\
         \n\
         <b>Integrations</b>\n\
         {abuseipdb_line}\n\
         {geoip_line}\n\
         {fail2ban_line}\n\
         {slack_line}\n\
         {cloudflare_line}\n\
         \n\
         <code>/enable &lt;id&gt;</code>  ·  <code>/disable &lt;id&gt;</code>"
    )
}

/// Build an inline keyboard with [Enable ->] buttons for each disabled capability.
/// Returns a JSON array of rows (each row is an array of buttons).
pub(crate) fn capabilities_keyboard(cfg: &config::AgentConfig) -> serde_json::Value {
    let mut buttons: Vec<serde_json::Value> = Vec::new();

    // Core capabilities
    if !cfg.ai.enabled {
        buttons.push(serde_json::json!({
            "text": "⚡ Enable AI",
            "callback_data": "enable:ai"
        }));
    }
    if !cfg.responder.enabled {
        buttons.push(serde_json::json!({
            "text": "🛡 Enable Block-IP",
            "callback_data": "enable:block-ip"
        }));
    }
    let has_sudo = cfg
        .responder
        .allowed_skills
        .iter()
        .any(|s| s.contains("suspend-user"));
    if !has_sudo {
        buttons.push(serde_json::json!({
            "text": "🔒 Enable Sudo Guard",
            "callback_data": "enable:sudo-protection"
        }));
    }

    // Integrations (only show a few to avoid keyboard overload)
    if !cfg.abuseipdb.enabled {
        buttons.push(serde_json::json!({
            "text": "🔍 Enable AbuseIPDB",
            "callback_data": "enable:abuseipdb"
        }));
    }
    if !cfg.geoip.enabled {
        buttons.push(serde_json::json!({
            "text": "🌍 Enable GeoIP",
            "callback_data": "enable:geoip"
        }));
    }
    if !cfg.fail2ban.enabled {
        buttons.push(serde_json::json!({
            "text": "🔍 Enable Fail2ban",
            "callback_data": "enable:fail2ban"
        }));
    }
    if cfg.honeypot.mode != "listener" {
        buttons.push(serde_json::json!({
            "text": "🪤 Enable Honeypot",
            "callback_data": "enable:honeypot"
        }));
    }

    if buttons.is_empty() {
        // All enabled - show a status button only
        return serde_json::json!([[{
            "text": "✅ All capabilities active",
            "callback_data": "menu:status"
        }]]);
    }

    // Group buttons into rows of 2
    let rows: Vec<Vec<serde_json::Value>> = buttons.chunks(2).map(|chunk| chunk.to_vec()).collect();
    serde_json::json!(rows)
}

/// Probe the system at startup and send proactive Telegram suggestions
/// for tools that are installed but not yet integrated with InnerWarden.
/// Runs once before the main loop. Fail-silent.
pub(crate) async fn probe_and_suggest(
    cfg: &config::AgentConfig,
    tg: Option<&telegram::TelegramClient>,
) {
    // Only if Telegram is configured
    let Some(tg) = tg else {
        return;
    };

    // Check for fail2ban: installed + running but not enabled in config
    if !cfg.fail2ban.enabled {
        let is_available = tokio::task::spawn_blocking(|| {
            std::process::Command::new("fail2ban-client")
                .arg("ping")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);

        if is_available {
            let text = "🔍 <b>Fail2ban detected!</b>\n\nFail2ban is running on this server but not integrated with InnerWarden.\n\nIntegrating it means InnerWarden will automatically sync all fail2ban bans - no duplicate work, full audit trail.\n\n<i>Want me to enable the integration?</i>";
            let keyboard = serde_json::json!([[
                {"text": "✅ Enable Fail2ban sync", "callback_data": "enable:fail2ban"},
                {"text": "❌ Not now", "callback_data": "menu:dismiss"}
            ]]);
            let _ = tg.send_text_with_keyboard(text, keyboard).await;
        }
    }
}

/// Strip ANSI escape codes from a string (for clean Telegram display).
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip escape sequence
            if chars.peek() == Some(&'[') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch.is_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}
