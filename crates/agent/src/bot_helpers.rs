use std::path::Path;

use tracing::{info, warn};

use crate::{config, decisions, telegram, two_factor, AgentState};

/// Count the number of lines in a JSONL file in data_dir (fail-silent -> 0).
pub(crate) fn count_jsonl_lines(data_dir: &Path, filename: &str) -> usize {
    let path = data_dir.join(filename);
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

/// Read the last N incidents from today's incidents file, formatted for display.
pub(crate) fn read_last_incidents(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "🔇 Clean slate - no intrusion attempts today.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "🔇 Clean slate - no intrusion attempts today.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();
    let now = chrono::Utc::now();

    let sev_icon = |s: &str| match s {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        _ => "⚪",
    };

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let severity = v["severity"].as_str().unwrap_or("?");
            let icon = sev_icon(severity);
            let title = v["title"].as_str().unwrap_or("unknown").to_string();
            let entity = v["entities"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|e| e["value"].as_str())
                .unwrap_or("?")
                .to_string();
            let ts_str = v["ts"].as_str().unwrap_or("");
            let age = chrono::DateTime::parse_from_rfc3339(ts_str)
                .ok()
                .map(|t| {
                    let mins = now
                        .signed_duration_since(t.with_timezone(&chrono::Utc))
                        .num_minutes();
                    if mins < 1 {
                        "just now".to_string()
                    } else if mins < 60 {
                        format!("{mins}m ago")
                    } else {
                        format!("{}h ago", mins / 60)
                    }
                })
                .unwrap_or_default();
            Some(format!("{icon} {title}\n   <code>{entity}</code> · {age}"))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable incidents today.".to_string()
    } else {
        format!(
            "🚨 <b>Recent threats</b> (last {})\n\n{}",
            formatted.len(),
            formatted.join("\n\n")
        )
    }
}

/// Read the last N decisions from today's decisions file, formatted for display.
pub(crate) fn read_last_decisions(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "⚖️ No decisions yet today - standing by.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "⚖️ No decisions yet today - standing by.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();

    let action_icon = |a: &str| {
        if a.contains("block") || a.contains("Block") {
            "🚫"
        } else if a.contains("suspend") || a.contains("Suspend") {
            "👑"
        } else if a.contains("honeypot") || a.contains("Honeypot") {
            "🍯"
        } else if a.contains("monitor") || a.contains("Monitor") {
            "👁"
        } else if a.contains("kill") || a.contains("Kill") {
            "💀"
        } else if a.contains("kill_chain") || a.contains("Kill chain") {
            "🔗"
        } else if a.contains("Ignore") || a.contains("ignore") {
            "🙈"
        } else {
            "⚡"
        }
    };

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let action = v["action_type"].as_str().unwrap_or("?").to_string();
            let icon = action_icon(&action);
            let target = v["target_ip"]
                .as_str()
                .or_else(|| v["target_user"].as_str())
                .unwrap_or("?")
                .to_string();
            let confidence = v["confidence"].as_f64().unwrap_or(0.0);
            let pct = (confidence * 100.0) as u32;
            let dry_run = v["dry_run"].as_bool().unwrap_or(true);
            let mode = if dry_run { "sim" } else { "live" };
            Some(format!(
                "{icon} {action} <code>{target}</code>\n   {pct}% confidence · {mode}"
            ))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable decisions today.".to_string()
    } else {
        format!(
            "⚖️ <b>Recent decisions</b> (last {})\n\n{}",
            formatted.len(),
            formatted.join("\n\n")
        )
    }
}

/// Read the last N incidents as compact JSON strings (for AI context).
pub(crate) fn read_last_incidents_raw(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return String::new();
    }

    lines
        .iter()
        .rev()
        .take(n)
        .map(|l| {
            // Summarise to avoid sending huge JSON blobs to the AI
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .map(|v| {
                    format!(
                        "[{}] {} - {}",
                        v["severity"].as_str().unwrap_or("?"),
                        v["title"].as_str().unwrap_or("?"),
                        v["summary"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(120)
                            .collect::<String>()
                    )
                })
                .unwrap_or_default()
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelegramTriageAction<'a> {
    AllowProc(&'a str),
    AllowIp(&'a str),
    ReportFp(&'a str),
}

pub(crate) fn parse_telegram_triage_action(incident_id: &str) -> Option<TelegramTriageAction<'_>> {
    if let Some(rest) = incident_id.strip_prefix("__allow_proc__:") {
        Some(TelegramTriageAction::AllowProc(rest))
    } else if let Some(rest) = incident_id.strip_prefix("__allow_ip__:") {
        Some(TelegramTriageAction::AllowIp(rest))
    } else {
        incident_id
            .strip_prefix("__fp__:")
            .map(TelegramTriageAction::ReportFp)
    }
}

pub(crate) fn sanitize_allowlist_process_name(raw: &str) -> Option<String> {
    let cleaned = raw.replace('"', "").replace('\n', " ").trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Handle triage sentinels from Telegram callbacks:
/// "__allow_proc__", "__allow_ip__", "__fp__".
/// Returns true when a triage callback was matched and handled.
pub(crate) fn handle_telegram_triage_action(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some(action) = parse_telegram_triage_action(&result.incident_id) else {
        return false;
    };

    match action {
        TelegramTriageAction::AllowProc(comm_raw) => {
            let Some(comm) = sanitize_allowlist_process_name(comm_raw) else {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    None,
                    Some("process:(empty)".to_string()),
                    format!(
                        "Operator {} attempted to add empty process allowlist via Telegram",
                        result.operator_name
                    ),
                    "skipped:empty_process_name".to_string(),
                );
                tg_reply(state, "⚠️ Could not add empty process name to allowlist.");
                return true;
            };
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistProcess(comm.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", &comm, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &comm,
                        "processes",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} added process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!("allowlist_process_added:{comm}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        comm = %comm,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (process) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{comm}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} failed to add process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        comm = %comm,
                        error = %e,
                        "failed to append process allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::AllowIp(ip_raw) => {
            let ip = ip_raw.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_err() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    Some(ip.clone()),
                    None,
                    format!(
                        "Operator {} attempted to add invalid IP '{}' to allowlist via Telegram",
                        result.operator_name, ip
                    ),
                    "skipped:invalid_ip".to_string(),
                );
                warn!(
                    operator = %result.operator_name,
                    ip = %ip,
                    "invalid ip in Telegram allowlist callback"
                );
                tg_reply(
                    state,
                    format!("⚠️ Invalid IP for allowlist: <code>{ip}</code>"),
                );
                return true;
            }
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistIp(ip.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", &ip, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &ip,
                        "ips",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} added IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        ip = %ip,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (ip) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{ip}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} failed to add IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        ip = %ip,
                        error = %e,
                        "failed to append ip allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::ReportFp(raw_incident_id) => {
            let incident_id = raw_incident_id.trim();
            if incident_id.is_empty() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "fp_report",
                    None,
                    None,
                    format!(
                        "Operator {} attempted to report FP with empty incident id",
                        result.operator_name
                    ),
                    "skipped:empty_incident_id".to_string(),
                );
                tg_reply(
                    state,
                    "⚠️ Could not report false positive: missing incident id.",
                );
                return true;
            }
            let detector = incident_id.split(':').next().unwrap_or("unknown");
            telegram::log_false_positive(data_dir, incident_id, detector, &result.operator_name);
            write_telegram_triage_audit(
                state,
                incident_id,
                &result.operator_name,
                "fp_report",
                None,
                None,
                format!(
                    "Operator {} reported incident '{}' as false positive via Telegram",
                    result.operator_name, incident_id
                ),
                format!("reported_fp:{detector}"),
            );
            info!(
                operator = %result.operator_name,
                incident_id = %incident_id,
                detector = %detector,
                "Telegram triage false-positive reported"
            );
            tg_reply(state, "📝 Reported. Thanks for the feedback.");
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 2FA gate — intercepts sensitive actions when TOTP is enabled
// ---------------------------------------------------------------------------

/// Check if 2FA is enabled in config.
pub(crate) fn is_2fa_enabled(cfg: &config::AgentConfig) -> bool {
    cfg.security
        .as_ref()
        .map(|s| s.two_factor_method == "totp")
        .unwrap_or(false)
}

/// Get the TOTP secret from config (resolved from env var or toml).
fn totp_secret(cfg: &config::AgentConfig) -> Option<String> {
    // Check env var first (preferred), then config field
    std::env::var("INNERWARDEN_TOTP_SECRET")
        .ok()
        .or_else(|| cfg.security.as_ref().map(|s| s.totp_secret.clone()))
        .filter(|s| !s.is_empty())
}

/// If 2FA is enabled, intercept the action: store as pending and ask for TOTP code.
/// Returns `true` if the action was intercepted (caller should return without executing).
/// Returns `false` if 2FA is disabled (caller should proceed normally).
pub(crate) fn check_2fa_gate(
    state: &mut AgentState,
    cfg: &config::AgentConfig,
    operator: &str,
    action: two_factor::PendingActionType,
) -> bool {
    if !is_2fa_enabled(cfg) {
        return false;
    }

    // Check lockout before accepting a new action
    if state.two_factor_state.is_locked_out(operator) {
        tg_reply(
            state,
            "\u{1f6ab} Too many failed 2FA attempts. Try again later.",
        );
        return true;
    }

    let now = chrono::Utc::now();
    let pending = two_factor::PendingAction {
        action_type: action,
        operator: operator.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        method: two_factor::TwoFactorMethod::Totp,
    };
    state.two_factor_state.set_pending(operator, pending);

    tg_reply(
        state,
        "\u{1f510} Enter your 6-digit TOTP code (expires in 5 min):",
    );
    info!(operator = %operator, "2FA: pending action stored, waiting for TOTP code");
    true
}

/// Try to handle a Telegram message as a TOTP code response.
/// Returns `true` if it was recognized as a TOTP attempt (code or cancel).
pub(crate) fn handle_totp_response(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let text = result.incident_id.trim();

    // Cancel pending 2FA
    if text == "/cancel" {
        if state
            .two_factor_state
            .take_pending(&result.operator_name)
            .is_some()
        {
            tg_reply(state, "\u{274c} 2FA verification cancelled.");
            return true;
        }
        return false;
    }

    // Only intercept 6-digit numeric strings when there's a pending action
    let is_6_digits = text.len() == 6 && text.chars().all(|c| c.is_ascii_digit());
    if !is_6_digits {
        return false;
    }

    let pending = match state.two_factor_state.take_pending(&result.operator_name) {
        Some(p) => p,
        None => return false, // No pending action — not a TOTP attempt
    };

    // Check if expired
    if pending.expires_at < chrono::Utc::now() {
        tg_reply(state, "\u{23f0} 2FA code expired. Please retry the action.");
        return true;
    }

    // Verify TOTP code
    let secret = match totp_secret(cfg) {
        Some(s) => s,
        None => {
            warn!("2FA enabled but no TOTP secret configured");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} 2FA is enabled but no TOTP secret is configured. Run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    let provider = match two_factor::TotpProvider::new(&secret) {
        Some(p) => p,
        None => {
            warn!("2FA: invalid TOTP secret in config");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} Invalid TOTP secret. Re-run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    if !provider.verify(text) {
        state.two_factor_state.record_failure(&result.operator_name);
        if state.two_factor_state.is_locked_out(&result.operator_name) {
            tg_reply(
                state,
                "\u{274c} Wrong code. You are now locked out for 1 hour.",
            );
        } else {
            // Re-store the pending action so operator can retry
            state
                .two_factor_state
                .set_pending(&result.operator_name, pending);
            tg_reply(state, "\u{274c} Wrong code. Try again or /cancel.");
        }
        return true;
    }

    // Code verified — execute the pending action
    info!(
        operator = %result.operator_name,
        action = ?pending.action_type,
        "2FA: TOTP verified, executing pending action"
    );
    execute_verified_action(pending.action_type, &result.operator_name, data_dir, state);
    true
}

/// Execute a 2FA-verified action.
fn execute_verified_action(
    action: two_factor::PendingActionType,
    operator: &str,
    data_dir: &Path,
    state: &mut AgentState,
) {
    let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    match action {
        two_factor::PendingActionType::AllowlistProcess(ref comm) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", comm, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, comm, "processes", operator, "add");
                    write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_add",
                        None, Some(format!("process:{comm}")),
                        format!("Operator {operator} added process '{comm}' to allowlist (2FA verified)"),
                        format!("allowlist_process_added:{comm}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{comm}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::AllowlistIp(ref ip) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", ip, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, ip, "ips", operator, "add");
                    write_telegram_triage_audit(
                        state,
                        "__2fa_verified__",
                        operator,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!("Operator {operator} added IP '{ip}' to allowlist (2FA verified)"),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{ip}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::UndoAllowlist {
            ref section,
            ref key,
        } => match telegram::remove_from_allowlist(allowlist_path, section, key) {
            Ok(()) => {
                telegram::log_allowlist_change(data_dir, key, section, operator, "remove");
                write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_remove",
                        None, None,
                        format!("Operator {operator} removed '{key}' from {section} allowlist (2FA verified)"),
                        format!("allowlist_removed:{key}"),
                    );
                tg_reply(
                    state,
                    format!(
                        "\u{2705} Removed <code>{}</code> from allowlist (verified by TOTP).",
                        telegram::escape_html_pub(key)
                    ),
                );
            }
            Err(e) => {
                tg_reply(
                    state,
                    format!(
                        "\u{274c} Failed to remove <code>{}</code>: {}",
                        telegram::escape_html_pub(key),
                        e.to_string().chars().take(180).collect::<String>()
                    ),
                );
            }
        },
        two_factor::PendingActionType::AutoFpAllowlist {
            ref section,
            ref entity,
        } => {
            let reason = format!("Auto-FP allowlist via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, section, entity, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, entity, section, operator, "add");
                    tg_reply(state, format!(
                        "\u{2705} Added <code>{}</code> to {} allowlist permanently (verified by TOTP).",
                        telegram::escape_html_pub(entity), section
                    ));
                }
                Err(e) => {
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
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an RFC3339 timestamp as a human-readable "X ago" string.
pub(crate) fn format_time_ago(ts_str: &str) -> String {
    let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(_) => return "recently".to_string(),
    };
    let diff = chrono::Utc::now() - ts;
    if diff.num_days() > 0 {
        format!("{}d ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{}h ago", diff.num_hours())
    } else {
        format!("{}m ago", diff.num_minutes().max(1))
    }
}

pub(crate) fn local_hostname_for_audit() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_telegram_triage_audit(
    state: &mut AgentState,
    incident_id: &str,
    operator: &str,
    action_type: &str,
    target_ip: Option<String>,
    target_user: Option<String>,
    reason: String,
    execution_result: String,
) {
    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: local_hostname_for_audit(),
            ai_provider: format!("operator:telegram:{operator}"),
            action_type: action_type.to_string(),
            target_ip,
            target_user,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason,
            estimated_threat: "manual".to_string(),
            execution_result,
            prev_hash: None,
        };
        if let Err(e) = writer.write(&entry) {
            warn!(
                error = %e,
                action_type,
                incident_id,
                operator,
                "failed to write Telegram triage audit entry"
            );
        }
    }
}
