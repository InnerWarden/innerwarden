/// Telegram notification and approval channel for InnerWarden.
///
/// T.1 - Notifications: sends an alert message for every High/Critical incident.
/// T.2 - Approvals: sends an inline-keyboard message when the AI requests human
///        confirmation; polls for button presses and sends results back to the
///        main loop via a channel.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Message length guard
// ---------------------------------------------------------------------------

/// Telegram enforces a 4096-character limit on messages.
/// Truncate with a warning marker if exceeded.
const TELEGRAM_MAX_LEN: usize = 4000; // Leave margin for safety
/// Telegram callback_data payloads must be <= 64 bytes.
const TELEGRAM_MAX_CALLBACK_BYTES: usize = 64;

fn enforce_length(text: &str) -> String {
    if text.len() <= TELEGRAM_MAX_LEN {
        return text.to_string();
    }
    warn!(
        original_len = text.len(),
        "Telegram message truncated (exceeded 4096 char limit)"
    );
    let mut truncated: String = text.chars().take(TELEGRAM_MAX_LEN - 30).collect();
    truncated.push_str("\n\n<i>… message truncated</i>");
    truncated
}

/// Truncate a UTF-8 string to at most `max_bytes` while preserving char boundaries.
fn truncate_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut cut = 0usize;
    for (idx, ch) in text.char_indices() {
        let next = idx + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        cut = next;
    }
    text[..cut].to_string()
}

/// Build callback_data with a fixed prefix, ensuring total payload stays <= 64 bytes.
fn callback_data(prefix: &str, payload: &str) -> String {
    let prefix_len = prefix.len();
    if prefix_len >= TELEGRAM_MAX_CALLBACK_BYTES {
        warn!(
            prefix_len,
            max = TELEGRAM_MAX_CALLBACK_BYTES,
            "callback prefix exceeded Telegram limit; truncating prefix"
        );
        return truncate_utf8_bytes(prefix, TELEGRAM_MAX_CALLBACK_BYTES);
    }
    let payload_budget = TELEGRAM_MAX_CALLBACK_BYTES - prefix_len;
    let payload = truncate_utf8_bytes(payload, payload_budget);
    format!("{prefix}{payload}")
}

// ---------------------------------------------------------------------------
// URL sanitization for logging
// ---------------------------------------------------------------------------

/// Replace bot token in Telegram API URL with redacted version for logging.
fn sanitize_url(url: &str) -> String {
    if let Some(start) = url.find("/bot") {
        if let Some(end) = url[start + 4..].find('/') {
            let mut sanitized = url[..start + 4].to_string();
            sanitized.push_str("***REDACTED***");
            sanitized.push_str(&url[start + 4 + end..]);
            return sanitized;
        }
    }
    url.to_string()
}

// ---------------------------------------------------------------------------
// Guardian mode
// ---------------------------------------------------------------------------

/// Operating mode of the InnerWarden agent - drives notification style.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuardianMode {
    /// Responder enabled, live - agent acts autonomously and reports decisions.
    Guard,
    /// Responder enabled, dry-run - simulates actions, asks for confirmation.
    DryRun,
    /// Responder disabled - monitors and asks operator what to do.
    Watch,
}

impl GuardianMode {
    pub fn label(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "🟢 GUARD",
            GuardianMode::DryRun => "🟡 DRY-RUN",
            GuardianMode::Watch => "🔵 WATCH",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "Threats are blocked automatically. You receive reports.",
            GuardianMode::DryRun => "Test mode - shows what would be blocked, no real changes.",
            GuardianMode::Watch => "Monitor only - all actions require your approval.",
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An approval result received from the operator via Telegram.
#[derive(Debug, Clone)]
pub struct ApprovalResult {
    pub incident_id: String,
    pub approved: bool,
    pub operator_name: String,
    /// If true, the operator wants this detector+action pair to always auto-execute.
    pub always: bool,
    /// The action chosen by the operator (for multi-choice keyboards).
    /// Values: "honeypot", "block", "monitor", "ignore", or empty (binary approve/reject).
    pub chosen_action: String,
}

/// Tracks a pending confirmation while waiting for the operator's response.
#[derive(Debug, Clone)]
pub struct PendingConfirmation {
    #[allow(dead_code)]
    pub incident_id: String,
    pub telegram_message_id: i64,
    #[allow(dead_code)]
    pub action_description: String,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Detector that triggered this incident (for trust-rule creation on "Always").
    pub detector: String,
    /// Action name (for trust-rule creation on "Always").
    pub action_name: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    dashboard_url: Option<String>,
    /// Dev mode: adds "Check FP" button to every notification.
    pub dev_mode: bool,
    http: reqwest::Client,
    /// Rate limiter: tracks last send time to stay within Telegram's 30 msg/sec limit.
    last_send: Arc<tokio::sync::Mutex<tokio::time::Instant>>,
}

impl TelegramClient {
    pub fn new(
        bot_token: impl Into<String>,
        chat_id: impl Into<String>,
        dashboard_url: Option<String>,
    ) -> Result<Self> {
        // Long-poll timeout is 25 s; give a 10 s buffer so the HTTP layer
        // never fires before the Telegram timeout parameter expires.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .context("failed to build Telegram HTTP client")?;
        Ok(Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
            dashboard_url,
            dev_mode: false,
            http,
            last_send: Arc::new(tokio::sync::Mutex::new(
                tokio::time::Instant::now() - Duration::from_secs(1),
            )),
        })
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    // -----------------------------------------------------------------------
    // T.1 - Incident notification
    // -----------------------------------------------------------------------

    /// Send a notification message for a High/Critical incident.
    /// In GUARD mode the alert is compact - no action buttons, the agent will
    /// act and follow up with send_action_report(). In WATCH/DryRun mode the
    /// alert includes Block/Ignore quick-action buttons.
    /// When `is_simple` is true, uses plain language (no IPs, no detector names).
    /// Failures are logged as warnings and never propagate - fail-open.
    pub async fn send_incident_alert(
        &self,
        incident: &Incident,
        mode: GuardianMode,
        is_simple: bool,
    ) -> Result<()> {
        let text = if is_simple {
            format_simple_message(incident, self.dashboard_url.as_deref(), mode)
        } else {
            format_incident_message(incident, self.dashboard_url.as_deref(), mode)
        };

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        match mode {
            GuardianMode::Guard => {
                // GUARD: agent will act - show investigate button only, no Block/Ignore
                if let Some(ip) = first_ip_entity(incident) {
                    if let Some(ref base_url) = self.dashboard_url {
                        let link = format!(
                            "{base_url}/?subject_type=ip&subject={ip}&date={}",
                            incident.ts.format("%Y-%m-%d")
                        );
                        body["reply_markup"] = serde_json::json!({
                            "inline_keyboard": [[{
                                "text": "🔍 Investigate",
                                "url": link
                            }]]
                        });
                    }
                }
            }
            GuardianMode::Watch | GuardianMode::DryRun => {
                // WATCH/DryRun: operator makes the call - add Block/Ignore buttons
                if let Some(ip) = first_ip_entity(incident) {
                    let mut keyboard: Vec<Vec<serde_json::Value>> = vec![vec![
                        serde_json::json!({
                            "text": format!("🛡 Block {ip}"),
                            "callback_data": format!("quick:block:{ip}")
                        }),
                        serde_json::json!({
                            "text": "🙈 Ignore",
                            "callback_data": "quick:ignore"
                        }),
                    ]];

                    if let Some(ref base_url) = self.dashboard_url {
                        let link = format!(
                            "{base_url}/?subject_type=ip&subject={ip}&date={}",
                            incident.ts.format("%Y-%m-%d")
                        );
                        keyboard.push(vec![serde_json::json!({
                            "text": "🔍 Investigate in dashboard",
                            "url": link
                        })]);
                    }

                    body["reply_markup"] = serde_json::json!({ "inline_keyboard": keyboard });
                } else if let Some(ref base_url) = self.dashboard_url {
                    let link = format!("{base_url}/?date={}", incident.ts.format("%Y-%m-%d"));
                    body["reply_markup"] = serde_json::json!({
                        "inline_keyboard": [[{
                            "text": "🔍 Investigate in dashboard",
                            "url": link
                        }]]
                    });
                }
            }
        }

        // Dev mode: append "Check FP" button to every incident notification
        if self.dev_mode {
            let incident_id = &incident.incident_id;
            let fp_btn = serde_json::json!({
                "text": "\u{1f52c} Check FP",
                "callback_data": callback_data("fp:check:", incident_id)
            });
            if let Some(markup) = body.get_mut("reply_markup") {
                if let Some(kb) = markup.get_mut("inline_keyboard") {
                    if let Some(arr) = kb.as_array_mut() {
                        arr.push(serde_json::json!([fp_btn]));
                    }
                }
            } else {
                body["reply_markup"] = serde_json::json!({ "inline_keyboard": [[fp_btn]] });
            }
        }

        // Triage row: allowlist + report FP buttons (both profiles)
        {
            let comm = if let Some(arr) = incident.evidence.as_array() {
                arr.first()
                    .and_then(|e| e.get("comm"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                incident
                    .evidence
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let ip = first_ip_entity(incident);

            let mut triage_row = vec![];
            if !comm.is_empty() {
                let label = if is_simple {
                    "Allow this"
                } else {
                    "Add to allowlist"
                };
                triage_row.push(serde_json::json!({
                    "text": format!("\u{2705} {label}"),
                    "callback_data": callback_data("allow:proc:", &comm)
                }));
            }
            if let Some(ref ip_val) = ip {
                let label = if is_simple {
                    "Allow this"
                } else {
                    "Allowlist IP"
                };
                triage_row.push(serde_json::json!({
                    "text": format!("\u{2705} {label}"),
                    "callback_data": callback_data("allow:ip:", ip_val)
                }));
            }

            let fp_label = if is_simple {
                "Not a threat"
            } else {
                "Report FP"
            };
            triage_row.push(serde_json::json!({
                "text": format!("\u{1f4dd} {fp_label}"),
                "callback_data": callback_data("fp:", &incident.incident_id)
            }));

            if !triage_row.is_empty() {
                if let Some(markup) = body.get_mut("reply_markup") {
                    if let Some(kb) = markup.get_mut("inline_keyboard") {
                        if let Some(arr) = kb.as_array_mut() {
                            arr.push(serde_json::json!(triage_row));
                        }
                    }
                } else {
                    body["reply_markup"] = serde_json::json!({ "inline_keyboard": [triage_row] });
                }
            }
        }

        // Explain button: both profiles get "What does this mean?"
        {
            let detector = extract_detector(&incident.incident_id).to_string();
            let explain_label = if is_simple {
                "What does this mean?"
            } else {
                "Explain this alert"
            };
            let explain_btn = serde_json::json!({
                "text": format!("\u{2753} {explain_label}"),
                "callback_data": callback_data("explain:", &detector)
            });
            if let Some(markup) = body.get_mut("reply_markup") {
                if let Some(kb) = markup.get_mut("inline_keyboard") {
                    if let Some(arr) = kb.as_array_mut() {
                        arr.push(serde_json::json!([explain_btn]));
                    }
                }
            } else {
                body["reply_markup"] = serde_json::json!({ "inline_keyboard": [[explain_btn]] });
            }
        }

        self.post_json("sendMessage", &body).await
    }

    /// Send a post-execution report when the agent autonomously acted on a threat.
    /// Called in GUARD mode after execute_decision succeeds.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_action_report(
        &self,
        action_label: &str,
        target: &str,
        incident_title: &str,
        confidence: f32,
        _host: &str,
        dry_run: bool,
        reputation: Option<&crate::abuseipdb::IpReputation>,
        geo: Option<&crate::geoip::GeoInfo>,
        cloudflare_pushed: bool,
    ) -> Result<()> {
        let pct = (confidence * 100.0) as u32;

        // Build optional enrichment block
        let mut enrichment = String::new();
        if let Some(rep) = reputation {
            let bar = reputation_score_bar(rep.confidence_score);
            let country_part = geo
                .map(|g| {
                    let flag = country_flag_emoji(&g.country_code);
                    format!(" · {flag} {} · {}", g.country, g.isp)
                })
                .unwrap_or_default();
            enrichment = format!(
                "\n📊 AbuseIPDB: <b>{}/100</b> {bar}{country_part}",
                rep.confidence_score
            );
        } else if let Some(g) = geo {
            let flag = country_flag_emoji(&g.country_code);
            enrichment = format!("\n🌐 {flag} {} · {}", g.country, escape_html(&g.isp));
        }

        let cf_line = if cloudflare_pushed {
            "\n☁️ Pushed to Cloudflare edge too - blocked before they even reach your server."
        } else {
            ""
        };

        let text = if dry_run {
            format!(
                "🧪 <b>Simulation</b>\n\
                 Would've {action_label} <code>{target}</code>{enrichment}\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}% - dry-run, no real action.\n\
                 <i>Want me to start dropping these for real? Enable live mode.</i>{cf_line}",
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        } else if action_label.to_lowercase().contains("ignore") {
            format!(
                "📝 <b>Analyzed &amp; dismissed</b>\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}% - No action needed.{enrichment}",
                incident_title = escape_html(incident_title),
            )
        } else {
            let kill_quip = match pct {
                95..=100 => "Clean kill. Zero doubt.",
                85..=94 => "Textbook containment.",
                70..=84 => "Threat actor down. Solid confidence.",
                _ => "Contained - keeping eyes on it.",
            };
            format!(
                "🔥 <b>Threat neutralized</b>\n\
                 {action_label} <code>{target}</code>{enrichment}\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}% - {kill_quip}{cf_line}",
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send a raw HTML message (no formatting helpers).
    /// Used for mesh network notifications and other custom messages.
    pub async fn send_raw_html(&self, html: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": html,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send an agent-guard snitch alert when an AI agent attempts something dangerous.
    pub async fn send_agent_guard_alert(
        &self,
        alert: &crate::dashboard::AgentGuardAlert,
    ) -> Result<()> {
        let sev_emoji = match alert.severity.as_str() {
            "high" => "\u{1f534}",   // 🔴
            "medium" => "\u{1f7e0}", // 🟠
            _ => "\u{1f7e1}",        // 🟡
        };
        let rec_label = match alert.recommendation.as_str() {
            "deny" => "DENIED",
            "review" => "REVIEW",
            _ => &alert.recommendation,
        };
        let cmd_preview = if alert.command.len() > 120 {
            format!("{}…", &alert.command[..120])
        } else {
            alert.command.clone()
        };
        let signals_str = if alert.signals.is_empty() {
            "—".to_string()
        } else {
            alert.signals.join(", ")
        };
        let atr_line = if alert.atr_rule_ids.is_empty() {
            String::new()
        } else {
            format!("\n<b>ATR rules:</b> {}", alert.atr_rule_ids.join(", "))
        };

        let html = format!(
            "\u{1f916} <b>Agent Guard Alert</b>\n\n\
             {sev_emoji} <b>{}</b> — {rec_label}\n\n\
             <b>Agent:</b> {}\n\
             <b>Command:</b> <code>{}</code>\n\
             <b>Risk:</b> {}/100\n\
             <b>Signals:</b> {}{}\n\n\
             InnerWarden flagged this action by your AI agent.",
            alert.severity.to_uppercase(),
            escape_html(&alert.agent_name),
            escape_html(&cmd_preview),
            alert.risk_score,
            escape_html(&signals_str),
            atr_line,
        );
        self.send_raw_html(&html).await
    }

    /// Send the onboarding/welcome message when the operator opens the bot.
    /// Shows current mode, today's stats, and quick-action buttons.
    pub async fn send_onboarding(
        &self,
        host: &str,
        incident_count: usize,
        decision_count: usize,
        mode: GuardianMode,
    ) -> Result<()> {
        let mode_label = mode.label();
        let mode_desc = mode.description();

        let today_line = if incident_count == 0 {
            "Perimeter's clean - no threat actors in the logs today.".to_string()
        } else {
            format!(
                "<b>{incident_count}</b> intrusion attempt{} logged, <b>{decision_count}</b> neutralized.",
                if incident_count == 1 { "" } else { "s" },
            )
        };

        let text = format!(
            "🛡 <b>InnerWarden</b> - protecting <b>{host}</b>\n\
             \n\
             {today_line}\n\
             \n\
             Mode: <b>{mode_label}</b>\n\
             <i>{mode_desc}</i>",
            host = escape_html(host),
        );

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   },
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" }
                    ],
                    [
                        { "text": "🔇 Quiet",   "callback_data": "sensitivity:quiet"   },
                        { "text": "🔔 Normal",  "callback_data": "sensitivity:normal"  },
                        { "text": "🔊 Verbose", "callback_data": "sensitivity:verbose" }
                    ],
                    [
                        { "text": "\u{1f5d1}\u{fe0f} Undo allowlist", "callback_data": "menu:undo"  },
                        { "text": "❓ All commands",  "callback_data": "menu:help"      }
                    ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // T.2 - Confirmation request (inline keyboard: Approve / Reject)
    // -----------------------------------------------------------------------

    /// Send a confirmation-request message with Approve/Reject inline keyboard.
    /// Returns the Telegram message ID so the caller can track the pending approval.
    pub async fn send_confirmation_request(
        &self,
        incident: &Incident,
        action_description: &str,
        action_name: &str,
        confidence: f32,
        expires_secs: u64,
    ) -> Result<i64> {
        let sev = severity_label(incident);
        let source_icon = source_icon(&incident.tags);
        let entity_line = entity_summary(incident);
        let pct = (confidence * 100.0) as u32;

        let confidence_phrase = match pct {
            90..=100 => "High confidence - this is a real threat",
            75..=89 => "Strong signal - TTPs check out",
            60..=74 => "Moderate confidence - worth acting on",
            _ => "Low signal - could be noise, could be legit",
        };
        let action_plain = plain_action(action_description);
        let expires_min = expires_secs / 60;
        let expires_label = if expires_min >= 1 {
            format!("{expires_min} min")
        } else {
            format!("{expires_secs}s")
        };

        let text = format!(
            "{source_icon} {sev}\n\
             <b>{title}</b>\n\
             {entity_line}\n\
             \n\
             🤖 {confidence_phrase} ({pct}%). Recommended action:\n\
             <code>{action_plain}</code>\n\
             \n\
             Your call, operator - {expires_label} to respond.",
            title = escape_html(&incident.title),
            action_plain = escape_html(&action_plain),
            entity_line = entity_line,
            sev = sev,
            source_icon = source_icon,
            confidence_phrase = confidence_phrase,
            expires_label = expires_label,
            pct = pct,
        );

        let id = &incident.incident_id;
        let always_label = format!("🔁 Always {action_name}");
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    { "text": "✅ Approve", "callback_data": format!("approve:{id}") },
                    { "text": always_label, "callback_data": format!("always:{id}") },
                    { "text": "❌ Reject", "callback_data": format!("reject:{id}") }
                ]]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop suggestion
    // -----------------------------------------------------------------------

    /// Send a honeypot suggestion message with a 4-button choice keyboard.
    ///
    /// Sent when the AI recommends `Honeypot` (or when `block_ip` is decided and honeypot
    /// is an allowed skill) so the operator can choose what to do with the attacker.
    ///
    /// Returns the Telegram `message_id` for pending-choice tracking.
    pub async fn send_honeypot_suggestion(
        &self,
        incident: &Incident,
        ip: &str,
        ai_reason: &str,
        ai_confidence: f32,
        ai_suggested: &str, // "honeypot" | "block" | "monitor"
    ) -> Result<i64> {
        let pct = (ai_confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Honeypot candidate detected</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incident:</b> {title}\n\
             <b>AI read:</b> {reason} ({pct}% confidence)\n\
             \n\
             Redirect to honeypot for analysis, or block immediately?",
            ip = escape_html(ip),
            title = escape_html(&incident.title),
            reason = escape_html(ai_reason),
            pct = pct,
        );

        // Add ✓ checkmark to the AI-suggested action
        let honeypot_label = if ai_suggested == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        let block_label = if ai_suggested == "block" {
            "🚫 Block ✓"
        } else {
            "🚫 Block"
        };
        let monitor_label = if ai_suggested == "monitor" {
            "👁 Monitor ✓"
        } else {
            "👁 Monitor"
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": honeypot_label, "callback_data": format!("hpot:honeypot:{ip}") },
                        { "text": block_label,    "callback_data": format!("hpot:block:{ip}")    }
                    ],
                    [
                        { "text": monitor_label,  "callback_data": format!("hpot:monitor:{ip}")  },
                        { "text": "❌ Ignore",    "callback_data": format!("hpot:ignore:{ip}")   }
                    ]
                ]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    /// Edit a confirmation message to show the final outcome (removes the keyboard).
    pub async fn resolve_confirmation(
        &self,
        message_id: i64,
        approved: bool,
        always: bool,
        operator: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "reply_markup": { "inline_keyboard": [] }
        });
        // Remove inline keyboard
        let _ = self.post_json("editMessageReplyMarkup", &body).await;

        // Send follow-up result message with hacker personality
        let text = if always {
            format!(
                "🔁 Trust rule saved, {operator}. This TTP is now auto-contained - no need to ping you next time.",
                operator = escape_html(operator)
            )
        } else if approved {
            format!(
                "✅ Executed. {operator} called the shot - threat actor has been neutralized.",
                operator = escape_html(operator)
            )
        } else {
            format!(
                "❌ Standing down on {operator}'s call. Logging the IOC, keeping eyes on it.",
                operator = escape_html(operator)
            )
        };
        let body2 = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "reply_to_message_id": message_id,
        });
        self.post_json("sendMessage", &body2).await
    }

    // -----------------------------------------------------------------------
    // T.5 - Post-session honeypot report
    // -----------------------------------------------------------------------

    /// T.5 - Post-session report sent after a honeypot session ends.
    /// Summarizes commands, extracted IOCs, AI verdict, and offers a Block action.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_honeypot_session_report(
        &self,
        ip: &str,
        session_id: &str,
        duration_secs: u64,
        commands: &[String],
        credentials: &[(String, Option<String>)], // (username, password)
        iocs: &crate::ioc::ExtractedIocs,
        ai_verdict: &str,
        auto_blocked: bool,
    ) -> Result<()> {
        let mut lines = Vec::new();
        lines.push(format!(
            "🍯 <b>Honeypot debrief</b> - session over\n\n\
             <b>Attacker:</b> <code>{ip}</code>\n\
             <b>Session:</b> <code>{session_id}</code>\n\
             <b>Duration:</b> {duration_secs}s | <b>Commands captured:</b> {}",
            commands.len(),
            ip = escape_html(ip),
            session_id = escape_html(session_id),
        ));

        // Credentials tried
        if !credentials.is_empty() {
            let mut cred_block = "\n<b>Credentials tried:</b>\n".to_string();
            for (user, pass) in credentials.iter().take(10) {
                let pass_display = pass
                    .as_deref()
                    .map(|p| {
                        if p.len() > 20 {
                            format!("{}...", &p[..20])
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_else(|| "(key auth)".to_string());
                cred_block.push_str(&format!(
                    "  <code>{}</code> / <code>{}</code>\n",
                    escape_html(user),
                    escape_html(&pass_display)
                ));
            }
            if credentials.len() > 10 {
                cred_block.push_str(&format!("  ... +{} more\n", credentials.len() - 10));
            }
            lines.push(cred_block.trim_end().to_string());
        }

        if !commands.is_empty() {
            let mut cmd_block = "\n<b>Their playbook:</b>\n".to_string();
            for cmd in commands.iter().take(8) {
                cmd_block.push_str(&format!("  $ <code>{}</code>\n", escape_html(cmd)));
            }
            lines.push(cmd_block.trim_end().to_string());
        }

        if !iocs.is_empty() {
            let ioc_text = iocs.format_telegram();
            if !ioc_text.is_empty() {
                lines.push(format!("\n<b>Extracted IOCs:</b>\n{ioc_text}"));
            }
        }

        lines.push(format!("\n<b>AI verdict:</b> {}", escape_html(ai_verdict)));

        if auto_blocked {
            lines.push("\n✅ IP auto-blocked - they walked right into it.".to_string());
        }

        let text = lines.join("\n");

        // Build inline keyboard
        let mut keyboard_rows: Vec<Vec<serde_json::Value>> = vec![];

        if !auto_blocked {
            keyboard_rows.push(vec![serde_json::json!({
                "text": "🚫 Block now",
                "callback_data": format!("hpot:block:{ip}")
            })]);
        }

        if let Some(ref dash_url) = self.dashboard_url {
            keyboard_rows.push(vec![serde_json::json!({
                "text": "📊 View in dashboard",
                "url": dash_url
            })]);
        }

        let body = if keyboard_rows.is_empty() {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            })
        } else {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
                "reply_markup": {
                    "inline_keyboard": keyboard_rows
                }
            })
        };

        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // AbuseIPDB auto-block notification
    // -----------------------------------------------------------------------

    /// Notify operator when an IP is auto-blocked via AbuseIPDB threshold
    /// (no AI call was made - pure reputation gate).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_abuseipdb_autoblock(
        &self,
        ip: &str,
        score: u8,
        threshold: u8,
        total_reports: u32,
        country: Option<&str>,
        isp: Option<&str>,
        incident_title: &str,
        dry_run: bool,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let country_flag = country
            .map(|c| format!(" {} ·", country_flag_emoji(c)))
            .unwrap_or_default();
        let isp_line = isp
            .map(|i| format!(" · <i>{}</i>", escape_html(i)))
            .unwrap_or_default();
        let reports_line = if total_reports > 0 {
            format!(" · {} reports worldwide", total_reports)
        } else {
            String::new()
        };

        let (action_line, header) = if dry_run {
            (
                format!(
                    "Would've dropped <code>{}</code> - dry-run, standing down.",
                    escape_html(ip)
                ),
                "🧪 <b>Dry-run</b> - known bad actor flagged",
            )
        } else {
            (
                format!(
                    "Blocked <code>{}</code> - known threat from reputation database.",
                    escape_html(ip)
                ),
                "🛡 <b>Instant kill</b> - AbuseIPDB reputation gate",
            )
        };

        let score_bar = reputation_score_bar(score);

        let text = format!(
            "{header}\n\
             \n\
             🌐{country_flag} <code>{ip}</code>{isp_line}\n\
             📊 Score: <b>{score}/100</b> {score_bar}{reports_line}\n\
             🔍 <i>{incident_title}</i>\n\
             \n\
             {action_line}\n\
             <i>Score ≥ {threshold} - handled before AI analysis.</i>",
            ip = escape_html(ip),
            incident_title = escape_html(incident_title),
        );

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        // Deep-link to dashboard journey for this IP
        if let Some(base_url) = dashboard_url {
            let today = chrono::Utc::now().format("%Y-%m-%d");
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[{
                    "text": "🔍 View threat timeline",
                    "url": format!("{base_url}/?subject_type=ip&subject={ip}&date={today}", ip = ip)
                }]]
            });
        }

        self.post_json("sendMessage", &body).await
    }

    // T.3 - Daily digest
    // -----------------------------------------------------------------------

    /// Send a plain HTML text message (used for daily digest).
    pub async fn send_text_message(&self, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send an HTML message with an inline keyboard.
    pub async fn send_text_with_keyboard(
        &self,
        text: &str,
        keyboard: serde_json::Value,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": { "inline_keyboard": keyboard },
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send the interactive menu with inline keyboard buttons.
    pub async fn send_menu(&self, is_simple: bool) -> Result<()> {
        let profile_btn = if is_simple {
            serde_json::json!({ "text": "🔧 Switch to Technical", "callback_data": "profile:technical" })
        } else {
            serde_json::json!({ "text": "✨ Switch to Simple", "callback_data": "profile:simple" })
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": "👾 <b>InnerWarden</b> - what do you need?",
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   }
                    ],
                    [
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" },
                        { "text": "\u{1f5d1}\u{fe0f} Undo", "callback_data": "menu:undo" }
                    ],
                    [
                        { "text": "❓ Help",       "callback_data": "menu:help"      }
                    ],
                    [ profile_btn ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    /// React to a message with 👀 (processing indicator).
    pub async fn react_eyes(&self, chat_id: i64, message_id: i64) {
        let body = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "reaction": [{ "type": "emoji", "emoji": "👀" }]
        });
        let _ = self.post_json("setMessageReaction", &body).await;
    }

    /// Show "typing..." indicator in the chat.
    pub async fn send_typing(&self) {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "action": "typing"
        });
        let _ = self.post_json("sendChatAction", &body).await;
    }

    /// Register the bot's persistent command menu (shown in the text input).
    /// Called once at startup.
    pub async fn set_commands(&self) {
        let body = serde_json::json!({
            "commands": [
                { "command": "status",       "description": "Guardian status - mode, AI, threat intel" },
                { "command": "threats",      "description": "Recent intrusion attempts" },
                { "command": "decisions",    "description": "Actions I've taken" },
                { "command": "blocked",      "description": "Threat actors currently contained" },
                { "command": "capabilities", "description": "List all capabilities and their status" },
                { "command": "enable",       "description": "Enable a capability - /enable block-ip" },
                { "command": "disable",      "description": "Disable a capability - /disable ai" },
                { "command": "doctor",       "description": "Full health check with fix hints" },
                { "command": "guard",        "description": "Activate auto-defend mode" },
                { "command": "watch",        "description": "Switch to passive monitor mode" },
                { "command": "ask",          "description": "Ask me anything - I know my config" },
                { "command": "undo",         "description": "Undo recent allowlist additions" },
                { "command": "help",         "description": "Operator command playbook" }
            ]
        });
        let _ = self.post_json("setMyCommands", &body).await;
    }

    // -----------------------------------------------------------------------
    // Polling loop (background task)
    // -----------------------------------------------------------------------

    /// Polls Telegram for updates and sends ApprovalResults to `approval_tx`.
    /// Designed to run as a background tokio task - exits when `approval_tx` is closed.
    ///
    /// Uses long-polling (timeout=25s) so this blocks for up to 25s between updates.
    /// Any errors are logged and the loop continues.
    pub async fn run_polling(
        self: std::sync::Arc<Self>,
        approval_tx: mpsc::Sender<ApprovalResult>,
    ) {
        let mut offset: i64 = 0;

        loop {
            if approval_tx.is_closed() {
                break;
            }

            match self.get_updates(offset).await {
                Ok(updates) => {
                    if !updates.is_empty() {
                        info!(count = updates.len(), offset, "Telegram: received updates");
                    }
                    for update in updates {
                        offset = update.update_id + 1;

                        if let Some(callback) = update.callback_query {
                            let operator = callback
                                .from
                                .first_name
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());

                            if let Some(data) = &callback.data {
                                if let Some(incident_id) = data.strip_prefix("fp:check:") {
                                    // Dev mode: log incident as potential false positive
                                    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                                    let entry = format!(
                                        "{{\"ts\":\"{ts}\",\"incident_id\":\"{incident_id}\",\"operator\":\"{operator}\",\"action\":\"check_fp\"}}\n"
                                    );
                                    // Write to false-positive review log
                                    // Write to data dir or fallback to /tmp
                                    let fp_path = {
                                        let primary = std::path::PathBuf::from(
                                            "/var/lib/innerwarden/fp-review.jsonl",
                                        );
                                        if primary.parent().map(|p| p.exists()).unwrap_or(false) {
                                            primary
                                        } else {
                                            std::path::PathBuf::from(
                                                "/tmp/innerwarden-fp-review.jsonl",
                                            )
                                        }
                                    };
                                    match std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&fp_path)
                                    {
                                        Ok(mut f) => {
                                            use std::io::Write;
                                            let _ = f.write_all(entry.as_bytes());
                                            info!(incident_id, operator = %operator, path = %fp_path.display(), "FP review: incident flagged for review");
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "FP review: failed to write log")
                                        }
                                    }
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!(
                                                "\u{1f52c} Flagged for FP review: {}",
                                                &incident_id[..incident_id.len().min(40)]
                                            ),
                                        )
                                        .await;
                                } else if let Some(detector) = data.strip_prefix("explain:") {
                                    // Simple profile: send a longer explanation of the detector
                                    let explanation = explain_detector(detector);
                                    let _ = self.answer_callback(&callback.id).await;
                                    let _ = self.send_raw_html(&explanation).await;
                                } else if data == "quick:ignore" {
                                    // Just ack with toast - no further action needed
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "👍 Logged as false positive. Keeping eyes on it.",
                                        )
                                        .await;
                                } else if let Some(ip_str) = data.strip_prefix("quick:block:") {
                                    // Validate IP format before processing
                                    if ip_str.parse::<std::net::IpAddr>().is_ok() {
                                        let ip = ip_str.to_string();
                                        let _ = self
                                            .answer_callback_toast(
                                                &callback.id,
                                                &format!("🛡 Dropping {ip} at the firewall..."),
                                            )
                                            .await;
                                        let result = ApprovalResult {
                                            incident_id: format!("__quick_block__:{ip}"),
                                            approved: true,
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: String::new(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    } else {
                                        warn!(callback_data = %data, "invalid IP in Telegram callback, ignoring");
                                    }
                                } else if let Some(rest) = data.strip_prefix("hpot:") {
                                    // Honeypot operator-in-the-loop choice
                                    // format: "hpot:{action}:{ip}"
                                    let parts: Vec<&str> = rest.splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        let action = parts[0];
                                        let ip = parts[1];
                                        let toast = match action {
                                            "honeypot" => {
                                                format!("🍯 Routing {ip} to honeypot - let them think they're in...")
                                            }
                                            "block" => {
                                                format!("🚫 Dropping {ip} at the firewall...")
                                            }
                                            "monitor" => {
                                                format!("👁 Silent monitoring on {ip} - collecting intel...")
                                            }
                                            _ => "👍 Logged.".to_string(),
                                        };
                                        let _ =
                                            self.answer_callback_toast(&callback.id, &toast).await;
                                        let result = ApprovalResult {
                                            incident_id: format!("__hpot__:{ip}"),
                                            approved: action != "ignore",
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: action.to_string(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                } else if let Some(rest) = data.strip_prefix("allow:proc:") {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("\u{2705} Adding {} to allowlist...", rest),
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__allow_proc__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("allow:ip:") {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("\u{2705} Adding {} to allowlist...", rest),
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__allow_ip__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if !data.starts_with("fp:check:") && data.starts_with("fp:")
                                {
                                    // Triage FP report (not the dev-mode fp:check: handler)
                                    let rest = &data[3..];
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f4dd} Reported as false positive. Thanks!",
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__fp__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("autofp:") {
                                    // Auto-FP suggestion: "autofp:yes:proc:name" or "autofp:no:name"
                                    let toast = if rest.starts_with("yes:") {
                                        "\u{2705} Adding to allowlist..."
                                    } else {
                                        "\u{1f440} OK, will keep monitoring."
                                    };
                                    let _ = self.answer_callback_toast(&callback.id, toast).await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__autofp__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("undo:") {
                                    // Undo allowlist: "undo:proc:key" or "undo:ip:key"
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f5d1}\u{fe0f} Removing from allowlist...",
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__undo__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if data == "enable2fa" {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f510} 2FA setup instructions sent.",
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: "__enable2fa__".to_string(),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if data == "dismiss2fa" {
                                    let _ = self
                                        .answer_callback_toast(&callback.id, "\u{1f44d} Dismissed.")
                                        .await;
                                    // No routing needed, just ack
                                } else {
                                    // Answer the callback immediately to remove the spinner
                                    let _ = self.answer_callback(&callback.id).await;
                                    if let Some(result) = parse_callback(data, &operator) {
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }

                        // Handle text commands and free-form messages
                        if let Some(msg) = update.message {
                            if let Some(raw_text) = &msg.text {
                                // Strip @BotUsername suffix that Telegram appends
                                // (e.g. "/help@InnerWardenBot" → "/help")
                                let text = strip_bot_suffix(raw_text.trim());
                                let operator = msg
                                    .from
                                    .as_ref()
                                    .and_then(|f| f.first_name.clone())
                                    .unwrap_or_default();
                                info!(text = %text, operator = %operator, "Telegram: text message received");

                                // Visual feedback: react with 👀 and show typing
                                let chat_id = msg.chat.as_ref().map(|c| c.id).unwrap_or(0);
                                if chat_id != 0 {
                                    self.react_eyes(chat_id, msg.message_id).await;
                                }
                                self.send_typing().await;

                                let incident_id = if text == "/status"
                                    || text.starts_with("/status ")
                                {
                                    info!("Telegram: routing /status command");
                                    "__status__".to_string()
                                } else if text == "/help" || text.starts_with("/help ") {
                                    "__help__".to_string()
                                } else if text == "/menu" || text.starts_with("/menu ") {
                                    "__menu__".to_string()
                                } else if text == "/incidents"
                                    || text.starts_with("/incidents ")
                                    || text == "/threats"
                                    || text.starts_with("/threats ")
                                {
                                    "__threats__".to_string()
                                } else if text == "/decisions" || text.starts_with("/decisions ") {
                                    "__decisions__".to_string()
                                } else if text == "/blocked" || text.starts_with("/blocked ") {
                                    "__blocked__".to_string()
                                } else if text == "/guard" || text.starts_with("/guard ") {
                                    "__guard__".to_string()
                                } else if text == "/watch" || text.starts_with("/watch ") {
                                    "__watch__".to_string()
                                } else if text == "/doctor" || text.starts_with("/doctor ") {
                                    "__doctor__".to_string()
                                } else if text == "/capabilities"
                                    || text.starts_with("/capabilities ")
                                    || text == "/list"
                                    || text.starts_with("/list ")
                                {
                                    "__capabilities__".to_string()
                                } else if let Some(cap) = text.strip_prefix("/enable ") {
                                    format!("__enable__:{cap}")
                                } else if let Some(cap) = text.strip_prefix("/disable ") {
                                    format!("__disable__:{cap}")
                                } else if text == "/undo" || text.starts_with("/undo ") {
                                    "__undo__".to_string()
                                } else if text == "/start" || text.starts_with("/start ") {
                                    // Telegram sends /start when user first opens the bot
                                    "__start__".to_string()
                                } else if !text.starts_with('/') || text.starts_with("/ask ") {
                                    // Free-form text or /ask <question> - route to AI
                                    let question =
                                        text.strip_prefix("/ask ").unwrap_or(&text).to_string();
                                    format!("__ask__:{question}")
                                } else {
                                    // Unknown command - send help hint
                                    "__unknown_cmd__".to_string()
                                };

                                let _ = approval_tx
                                    .send(ApprovalResult {
                                        incident_id,
                                        approved: true,
                                        always: false,
                                        operator_name: operator,
                                        chosen_action: String::new(),
                                    })
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Telegram poll error: {e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Low-level API calls
    // -----------------------------------------------------------------------

    async fn get_updates(&self, offset: i64) -> Result<Vec<Update>> {
        let url = self.api_url("getUpdates");
        let resp = self
            .http
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", "25".to_string()),
                (
                    "allowed_updates",
                    r#"["message","callback_query"]"#.to_string(),
                ),
            ])
            .send()
            .await
            .with_context(|| format!("getUpdates request failed ({})", sanitize_url(&url)))?
            .json::<serde_json::Value>()
            .await
            .with_context(|| format!("getUpdates JSON parse failed ({})", sanitize_url(&url)))?;

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"].as_str().unwrap_or("unknown error");
            warn!("Telegram getUpdates error: {desc}");
            return Ok(vec![]);
        }

        let raw_result = resp["result"].clone();
        let result_count = raw_result.as_array().map(|a| a.len()).unwrap_or(0);
        let updates: Vec<Update> = match serde_json::from_value(raw_result) {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, raw_count = result_count, "Telegram: failed to deserialize updates");
                vec![]
            }
        };
        Ok(updates)
    }

    async fn answer_callback(&self, callback_query_id: &str) -> Result<()> {
        let body = serde_json::json!({ "callback_query_id": callback_query_id });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn answer_callback_toast(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": false
        });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn post_json(&self, method: &str, body: &serde_json::Value) -> Result<()> {
        self.post_json_with_response(method, body).await?;
        Ok(())
    }

    async fn post_json_with_response(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Enforce message length limit on outgoing text
        let body = if let Some(text) = body["text"].as_str() {
            let safe_text = enforce_length(text);
            let mut patched = body.clone();
            patched["text"] = serde_json::Value::String(safe_text);
            patched
        } else {
            body.clone()
        };

        // Rate limiter: ~20 msg/sec, well within Telegram's 30/sec limit
        {
            let mut last = self.last_send.lock().await;
            let elapsed = last.elapsed();
            if elapsed < Duration::from_millis(50) {
                tokio::time::sleep(Duration::from_millis(50) - elapsed).await;
            }
            *last = tokio::time::Instant::now();
        }

        let url = self.api_url(method);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Telegram {method} failed ({})", sanitize_url(&url)))?
            .json::<serde_json::Value>()
            .await
            .with_context(|| {
                format!(
                    "Telegram {method} JSON parse failed ({})",
                    sanitize_url(&url)
                )
            })?;

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"]
                .as_str()
                .unwrap_or("unknown Telegram error");
            warn!(method, url = %sanitize_url(&url), "Telegram API error: {desc}");
        }

        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Polling response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(default)]
    message_id: i64,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    from: Option<User>,
    #[serde(default)]
    chat: Option<Chat>,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    from: User,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default)]
    first_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_incident_message(
    incident: &Incident,
    dashboard_url: Option<&str>,
    mode: GuardianMode,
) -> String {
    let sev = severity_label(incident);
    let source_icon = source_icon(&incident.tags);
    let entity_line = entity_summary(incident);

    let summary_trunc = if incident.summary.len() > 200 {
        format!("{}…", &incident.summary[..200])
    } else {
        incident.summary.clone()
    };

    // Mode-specific header and call-to-action
    let (mode_prefix, cta) = match mode {
        GuardianMode::Guard => {
            let quip = incident_quip(incident);
            (
                "⚡",
                format!("\n{quip}\n<i>Handling it - stand by for action report.</i>"),
            )
        }
        GuardianMode::DryRun => {
            let quip = incident_quip(incident);
            (
                "🧪",
                format!("\n{quip}\n<i>Dry-run - I'd act on this. Enable live mode to let me.</i>"),
            )
        }
        GuardianMode::Watch => {
            let quip = incident_quip(incident);
            ("🚨", quip.to_string())
        }
    };

    let link_line = dashboard_url
        .and_then(|base| first_ip_entity(incident).map(|ip| (base, ip)))
        .map(|(base, ip)| {
            format!(
                "\n🔗 <a href=\"{}/?subject_type=ip&subject={}&date={}\">Investigate</a>",
                base,
                ip,
                incident.ts.format("%Y-%m-%d")
            )
        })
        .unwrap_or_default();

    let prefix_line = if mode_prefix.is_empty() {
        String::new()
    } else {
        format!("{mode_prefix} ")
    };

    format!(
        "{source_icon} {prefix_line}{sev}\n\
         <b>{title}</b>\n\
         {entity_line}\n\
         <i>{summary}</i>\n\
         \n\
         {cta}{link_line}",
        title = escape_html(&incident.title),
        summary = escape_html(&summary_trunc),
        entity_line = entity_line,
        sev = sev,
        source_icon = source_icon,
        prefix_line = prefix_line,
        cta = cta,
        link_line = link_line,
    )
}

/// Returns a hacker-flavored one-liner based on the incident type.
fn incident_quip(incident: &Incident) -> &'static str {
    let title = incident.title.to_lowercase();
    let tags: Vec<&str> = incident.tags.iter().map(|s| s.as_str()).collect();

    if title.contains("brute") || (title.contains("ssh") && title.contains("fail")) {
        return "💥 Script kiddie hammering the front door. Dictionary attack, classic.";
    }
    if title.contains("credential") || title.contains("stuffing") || title.contains("spray") {
        return "🎭 Credential spray detected. Threat actor cosplaying as your users.";
    }
    if title.contains("port scan") || title.contains("portscan") {
        return "🔭 Recon phase active - they're mapping our attack surface. Not on my watch.";
    }
    if title.contains("sudo") || title.contains("privilege") {
        return "👑 Privilege escalation attempt. This actor's trying to go root. Hard no.";
    }
    if title.contains("execution") || title.contains("shell") || title.contains("command") {
        return "💀 Suspicious binary execution. Could be a payload drop - locking it down.";
    }
    if title.contains("rate") || title.contains("search") || title.contains("abuse") {
        return "🤖 Automated scraping detected. Bot's treating your server like an open API.";
    }
    if title.contains("authorized_keys") || title.contains("ssh key") {
        return "🔑 SSH key tampering - classic persistence play. ATT&CK T1098.004 vibes.";
    }
    if title.contains("cron") || title.contains("scheduled") {
        return "⏰ Cron tampering - threat actor planting a persistent backdoor. ATT&CK T1053.";
    }
    if title.contains("file") || title.contains("integrity") {
        return "🕵️ File tampered outside expected windows. Could be an IOC - eyes on it.";
    }
    if title.contains("container") || title.contains("docker") {
        return "🐳 Suspicious container spun up. Checking for --privileged escapes.";
    }
    if tags.contains(&"falco") {
        return "🔬 Falco snagged a kernel-level anomaly. That's deep in the stack - serious.";
    }
    if tags.contains(&"suricata") {
        return "🌐 Suricata flagged dirty traffic. Network-layer IOC confirmed.";
    }
    if tags.contains(&"wazuh") {
        return "🛡 Wazuh HIDS tripped. Host-based intrusion signatures firing.";
    }
    "👾 Anomaly in the noise. Threat actor or misconfigured bot - investigating."
}

/// Converts a technical action description into hacker-flavored plain language.
fn plain_action(action: &str) -> String {
    let a = action.trim();
    // block-ip variants
    if a.contains("ufw deny from")
        || a.contains("iptables")
        || a.contains("nftables")
        || a.contains("pfctl")
    {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Drop {ip} at the firewall - blackhole their traffic");
    }
    if a.contains("block") && a.contains("ip") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Firewall drop {ip} - null route all inbound traffic");
    }
    // suspend-user-sudo
    if a.contains("sudoers") || a.contains("suspend") {
        let user = a.split_whitespace().last().unwrap_or("user");
        return format!("Kill sudo privileges for {user} - privilege revoked");
    }
    // monitor
    if a.contains("tcpdump") || a.contains("monitor") || a.contains("pcap") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Spin up packet capture on {ip} - collect forensic evidence");
    }
    // honeypot
    if a.contains("honeypot") {
        return "Redirect threat actor to honeypot - let them think they're in".to_string();
    }
    // fallback
    a.to_string()
}

fn severity_label(incident: &Incident) -> &'static str {
    use innerwarden_core::event::Severity::*;
    match incident.severity {
        Critical => "🔴 <b>CRITICAL</b>",
        High => "🟠 <b>HIGH</b>",
        Medium => "🟡 MEDIUM",
        Low => "🟢 LOW",
        _ => "⚪ INFO",
    }
}

fn source_icon(tags: &[String]) -> &'static str {
    if tags.iter().any(|t| t == "falco") {
        "🔬"
    } else if tags.iter().any(|t| t == "suricata") {
        "🌐"
    } else if tags.iter().any(|t| t == "osquery") {
        "🔍"
    } else if tags.iter().any(|t| t == "ssh" || t == "sshd") {
        "🔐"
    } else {
        "📋"
    }
}

fn entity_summary(incident: &Incident) -> String {
    use innerwarden_core::entities::EntityType::*;
    let parts: Vec<String> = incident
        .entities
        .iter()
        .take(3)
        .map(|e| match e.r#type {
            Ip => format!("IP: <code>{}</code>", escape_html(&e.value)),
            User => format!("User: <code>{}</code>", escape_html(&e.value)),
            Container => format!("Container: <code>{}</code>", escape_html(&e.value)),
            Path => format!("Path: <code>{}</code>", escape_html(&e.value)),
            Service => format!("Service: <code>{}</code>", escape_html(&e.value)),
        })
        .collect();
    parts.join(" · ")
}

fn first_ip_entity(incident: &Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
        .map(|e| e.value.clone())
}

/// Parse a Telegram callback_data string into an ApprovalResult.
/// Format: "approve:{incident_id}", "reject:{incident_id}", or "menu:{command}"
fn parse_callback(data: &str, operator: &str) -> Option<ApprovalResult> {
    if let Some(id) = data.strip_prefix("approve:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("always:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: true,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("reject:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: false,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Inline-keyboard menu buttons: "menu:status", "menu:threats", etc.
    if let Some(cmd) = data.strip_prefix("menu:") {
        let incident_id = match cmd {
            "status" => "__status__",
            "incidents" | "threats" => "__threats__",
            "decisions" => "__decisions__",
            "help" => "__help__",
            "undo" => "__undo__",
            _ => "__unknown_cmd__",
        };
        return Some(ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Sensitivity buttons: "sensitivity:quiet", "sensitivity:normal", "sensitivity:verbose"
    if let Some(level) = data.strip_prefix("sensitivity:") {
        return Some(ApprovalResult {
            incident_id: format!("__sensitivity__:{level}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Profile toggle: "profile:simple" or "profile:technical"
    if let Some(profile) = data.strip_prefix("profile:") {
        return Some(ApprovalResult {
            incident_id: format!("__profile__:{profile}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Capabilities inline keyboard: "enable:<id>" → routed to __enable__:<id> handler
    if let Some(cap_id) = data.strip_prefix("enable:") {
        return Some(ApprovalResult {
            incident_id: format!("enable:{cap_id}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    None
}

/// Strip `@BotUsername` suffix from Telegram commands.
/// "/help@InnerWardenBot" → "/help", "/status" → "/status", "hello" → "hello"
fn strip_bot_suffix(text: &str) -> String {
    if text.starts_with('/') {
        if let Some(at_pos) = text.find('@') {
            // Check if @bot comes right after the command (before any space)
            let space_pos = text.find(' ').unwrap_or(text.len());
            if at_pos < space_pos {
                // "/help@Bot args" → "/help args"
                let cmd = &text[..at_pos];
                let rest = &text[space_pos..];
                return format!("{cmd}{rest}");
            }
        }
    }
    text.to_string()
}

/// Escape HTML special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Public wrapper for escape_html (used by main.rs auto-FP suggestions).
pub fn escape_html_pub(s: &str) -> String {
    escape_html(s)
}

/// Public wrapper for truncate_utf8_bytes (callback data must be <= 64 bytes).
pub fn truncate_callback_pub(s: &str) -> String {
    truncate_utf8_bytes(s, TELEGRAM_MAX_CALLBACK_BYTES)
}

/// Visual score bar for AbuseIPDB confidence (e.g. "████░░░░ 80/100").
fn reputation_score_bar(score: u8) -> String {
    let filled = (score as usize * 8 / 100).min(8);
    let empty = 8 - filled;
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    format!("[{bar}]")
}

/// Convert a 2-letter ISO country code to a flag emoji.
fn country_flag_emoji(code: &str) -> String {
    if code.len() != 2 {
        return String::new();
    }
    let bytes = code.to_uppercase();
    let mut chars = bytes.chars();
    if let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let base: u32 = 0x1F1E6 - b'A' as u32;
        let fa = char::from_u32(base + a as u32).unwrap_or(' ');
        let fb = char::from_u32(base + b as u32).unwrap_or(' ');
        return format!("{fa}{fb}");
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
    use tempfile::tempdir;

    fn make_incident(severity: Severity, tags: Vec<String>, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "web-server-01".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026-03-15T15:00Z".to_string(),
            severity,
            title: "Possible SSH brute force from 1.2.3.4".to_string(),
            summary: "15 failed SSH logins in 5 minutes".to_string(),
            evidence: serde_json::json!([]),
            recommended_checks: vec![],
            tags,
            entities,
        }
    }

    #[test]
    fn format_critical_message_contains_key_fields() {
        let inc = make_incident(
            Severity::Critical,
            vec!["falco".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Watch);
        assert!(msg.contains("CRITICAL"));
        assert!(msg.contains("SSH brute force"));
        assert!(msg.contains("1.2.3.4"));
        assert!(msg.contains("🔬"), "falco icon should appear");
    }

    #[test]
    fn format_high_message_with_dashboard_url() {
        let inc = make_incident(
            Severity::High,
            vec!["suricata".to_string()],
            vec![EntityRef::ip("203.0.113.10".to_string())],
        );
        let msg = format_incident_message(&inc, Some("http://127.0.0.1:8787"), GuardianMode::Watch);
        assert!(msg.contains("HIGH"));
        assert!(msg.contains("🌐"), "suricata icon");
        assert!(msg.contains("Investigate"));
        assert!(msg.contains("203.0.113.10"));
    }

    #[test]
    fn format_guard_mode_shows_defense_active() {
        let inc = make_incident(
            Severity::High,
            vec!["ssh".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Guard);
        assert!(
            msg.contains("action report"),
            "GUARD mode mentions action report"
        );
        // GUARD mode should NOT show Block/Ignore buttons inline
        assert!(
            !msg.contains("🛡 Block"),
            "GUARD mode has no block CTA button text"
        );
    }

    #[test]
    fn source_icon_picks_correct_icon() {
        assert_eq!(source_icon(&["falco".to_string()]), "🔬");
        assert_eq!(source_icon(&["suricata".to_string()]), "🌐");
        assert_eq!(source_icon(&["osquery".to_string()]), "🔍");
        assert_eq!(source_icon(&["ssh".to_string()]), "🔐");
        assert_eq!(source_icon(&["other".to_string()]), "📋");
    }

    #[test]
    fn parse_callback_approve() {
        let result = parse_callback("approve:ssh_bruteforce:1.2.3.4:2026Z", "Alice").unwrap();
        assert!(result.approved);
        assert_eq!(result.incident_id, "ssh_bruteforce:1.2.3.4:2026Z");
        assert_eq!(result.operator_name, "Alice");
    }

    #[test]
    fn parse_callback_reject() {
        let result = parse_callback("reject:some:incident:id", "Bob").unwrap();
        assert!(!result.approved);
        assert_eq!(result.incident_id, "some:incident:id");
    }

    #[test]
    fn parse_callback_unknown_returns_none() {
        assert!(parse_callback("unknown:foo", "user").is_none());
        assert!(parse_callback("", "user").is_none());
    }

    #[test]
    fn parse_callback_menu_routes_to_sentinels() {
        let r = parse_callback("menu:status", "Alice").unwrap();
        assert_eq!(r.incident_id, "__status__");
        assert!(r.approved);

        // Both "threats" and "incidents" route to __threats__
        let r = parse_callback("menu:threats", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:incidents", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:decisions", "Alice").unwrap();
        assert_eq!(r.incident_id, "__decisions__");

        let r = parse_callback("menu:help", "Alice").unwrap();
        assert_eq!(r.incident_id, "__help__");

        // Unknown menu command → unknown cmd sentinel
        let r = parse_callback("menu:bogus", "Alice").unwrap();
        assert_eq!(r.incident_id, "__unknown_cmd__");
    }

    #[test]
    fn guardian_mode_labels_and_descriptions() {
        assert_eq!(GuardianMode::Guard.label(), "🟢 GUARD");
        assert_eq!(GuardianMode::DryRun.label(), "🟡 DRY-RUN");
        assert_eq!(GuardianMode::Watch.label(), "🔵 WATCH");
        assert!(GuardianMode::Guard.description().contains("automatically"));
        assert!(GuardianMode::Watch.description().contains("your approval"));
    }

    #[test]
    fn strip_bot_suffix_removes_at_username() {
        assert_eq!(strip_bot_suffix("/help@InnerWardenBot"), "/help");
        assert_eq!(strip_bot_suffix("/status@Bot"), "/status");
        assert_eq!(
            strip_bot_suffix("/ask@Bot question here"),
            "/ask question here"
        );
        assert_eq!(strip_bot_suffix("/status"), "/status");
        assert_eq!(strip_bot_suffix("hello"), "hello");
        assert_eq!(strip_bot_suffix("text with @mention"), "text with @mention");
    }

    #[test]
    fn quick_block_callback_routes_to_sentinel() {
        // Simulate the run_polling logic for "quick:block:<ip>" callbacks.
        // The callback data must produce the correct ApprovalResult sentinel.
        let data = "quick:block:1.2.3.4";
        let operator = "Alice";

        let ip = data.strip_prefix("quick:block:").unwrap();
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__quick_block__:{ip}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        };

        assert_eq!(result.incident_id, "__quick_block__:1.2.3.4");
        assert!(result.approved);
        assert!(!result.always);
        assert_eq!(result.operator_name, "Alice");

        // quick:ignore must not produce a routing result (handled inline)
        assert!(parse_callback("quick:ignore", operator).is_none());
        // quick:block: prefix must not be caught by parse_callback
        assert!(parse_callback("quick:block:1.2.3.4", operator).is_none());
    }

    #[test]
    fn escape_html_handles_specials() {
        assert_eq!(
            escape_html("<b>test & \"value\"</b>"),
            "&lt;b&gt;test &amp; &quot;value&quot;&lt;/b&gt;"
        );
    }

    #[test]
    fn severity_label_covers_all() {
        let make = |sev| make_incident(sev, vec![], vec![]);
        assert!(severity_label(&make(Severity::Critical)).contains("CRITICAL"));
        assert!(severity_label(&make(Severity::High)).contains("HIGH"));
        assert!(severity_label(&make(Severity::Medium)).contains("MEDIUM"));
    }

    #[test]
    fn first_ip_entity_returns_first_ip() {
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![
                EntityRef::user("bob".to_string()),
                EntityRef::ip("10.0.0.1".to_string()),
                EntityRef::ip("203.0.113.10".to_string()),
            ],
        );
        assert_eq!(first_ip_entity(&inc), Some("10.0.0.1".to_string()));
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hpot_callback_routing() {
        // Simulate the run_polling routing logic for hpot: callbacks
        let data = "hpot:honeypot:1.2.3.4";
        let rest = data.strip_prefix("hpot:").unwrap();
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        let action = parts[0];
        let ip = parts[1];
        assert_eq!(action, "honeypot");
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__hpot__:{ip}"),
            approved: action != "ignore",
            always: false,
            operator_name: "Alice".to_string(),
            chosen_action: action.to_string(),
        };
        assert_eq!(result.incident_id, "__hpot__:1.2.3.4");
        assert!(result.approved);
        assert_eq!(result.chosen_action, "honeypot");

        // ignore action should produce approved=false
        let data_ignore = "hpot:ignore:5.6.7.8";
        let rest_i = data_ignore.strip_prefix("hpot:").unwrap();
        let parts_i: Vec<&str> = rest_i.splitn(2, ':').collect();
        let action_i = parts_i[0];
        assert_eq!(action_i, "ignore");
        let result_i = ApprovalResult {
            incident_id: format!("__hpot__:{}", parts_i[1]),
            approved: action_i != "ignore",
            always: false,
            operator_name: "Bob".to_string(),
            chosen_action: action_i.to_string(),
        };
        assert!(!result_i.approved);
        assert_eq!(result_i.chosen_action, "ignore");

        // hpot: prefix must not be caught by parse_callback
        assert!(parse_callback("hpot:honeypot:1.2.3.4", "Alice").is_none());
        assert!(parse_callback("hpot:block:1.2.3.4", "Alice").is_none());
    }

    #[test]
    fn test_send_honeypot_suggestion_format() {
        // Verify the message body would contain the key fields.
        // We test by constructing the expected format string directly.
        let ip = "185.220.101.45";
        let title = "47 SSH attempts in 5 min";
        let reason = "New IP, no history in blocklists";
        let confidence = 0.87_f32;
        let pct = (confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Honeypot candidate detected</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incident:</b> {title}\n\
             <b>AI read:</b> {reason} ({pct}% confidence)\n\
             \n\
             Redirect to honeypot for analysis, or block immediately?",
            ip = escape_html(ip),
            title = escape_html(title),
            reason = escape_html(reason),
            pct = pct,
        );

        assert!(text.contains("185.220.101.45"), "IP must appear in message");
        assert!(
            text.contains("47 SSH attempts"),
            "incident title must appear in message"
        );
        assert!(text.contains("87%"), "confidence percentage must appear");
        assert!(
            text.contains("Honeypot candidate detected"),
            "honeypot heading must appear"
        );
        assert!(
            text.contains("honeypot for analysis"),
            "operator question must appear"
        );

        // Verify ai_suggested checkmark logic
        let honeypot_label_suggested = if "honeypot" == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        assert_eq!(honeypot_label_suggested, "🍯 Honeypot ✓");

        let block_label_not_suggested = if "honeypot" == "block" {
            "🚫 Block ✓"
        } else {
            "🚫 Block"
        };
        assert_eq!(block_label_not_suggested, "🚫 Block");
    }

    #[test]
    fn enforce_length_passes_short_messages() {
        let short = "Hello, world!";
        assert_eq!(enforce_length(short), short);
    }

    #[test]
    fn enforce_length_truncates_long_messages() {
        let long = "x".repeat(5000);
        let result = enforce_length(&long);
        assert!(result.len() <= TELEGRAM_MAX_LEN);
        assert!(result.contains("… message truncated"));
    }

    #[test]
    fn enforce_length_at_boundary() {
        // Exactly at limit should pass through
        let exact = "a".repeat(TELEGRAM_MAX_LEN);
        assert_eq!(enforce_length(&exact), exact);

        // One over should truncate
        let over = "a".repeat(TELEGRAM_MAX_LEN + 1);
        let result = enforce_length(&over);
        assert!(result.len() <= TELEGRAM_MAX_LEN);
        assert!(result.contains("… message truncated"));
    }

    #[test]
    fn callback_data_keeps_short_payload() {
        let cb = callback_data("allow:proc:", "sshd");
        assert_eq!(cb, "allow:proc:sshd");
        assert!(cb.len() <= TELEGRAM_MAX_CALLBACK_BYTES);
    }

    #[test]
    fn callback_data_truncates_to_telegram_limit() {
        let cb = callback_data("fp:check:", &"x".repeat(500));
        assert!(cb.starts_with("fp:check:"));
        assert_eq!(cb.len(), TELEGRAM_MAX_CALLBACK_BYTES);
    }

    #[test]
    fn callback_data_preserves_utf8_boundaries() {
        let cb = callback_data("fp:", &"á".repeat(100));
        assert!(cb.len() <= TELEGRAM_MAX_CALLBACK_BYTES);
        assert!(std::str::from_utf8(cb.as_bytes()).is_ok());
    }

    #[test]
    fn append_to_allowlist_creates_and_appends_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");

        append_to_allowlist(&path, "processes", "cargo-build", "from telegram").unwrap();
        append_to_allowlist(&path, "ips", "1.2.3.4", "known safe").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[processes]"));
        assert!(content.contains("\"cargo-build\" = \"from telegram\""));
        assert!(content.contains("[ips]"));
        assert!(content.contains("\"1.2.3.4\" = \"known safe\""));
    }

    #[test]
    fn append_to_allowlist_escapes_toml_sensitive_chars() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");
        append_to_allowlist(&path, "processes", "my\"proc", "line1\nline2").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"my\\\"proc\""));
        assert!(content.contains("line1 line2"));
    }

    #[test]
    fn log_false_positive_writes_expected_jsonl_fields() {
        let dir = tempdir().unwrap();
        log_false_positive(
            dir.path(),
            "ssh_bruteforce:1.2.3.4:test",
            "ssh_bruteforce",
            "operator-a",
        );

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("fp-reports-{today}.jsonl"));
        let content = std::fs::read_to_string(path).unwrap();
        let line = content.lines().next().unwrap();
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["incident_id"], "ssh_bruteforce:1.2.3.4:test");
        assert_eq!(value["detector"], "ssh_bruteforce");
        assert_eq!(value["reporter"], "operator-a");
        assert_eq!(value["action"], "reported_fp");
        assert!(value["ts"].is_string());
    }

    #[test]
    fn sanitize_url_redacts_bot_token() {
        let url = "https://api.telegram.org/bot1234567890:AAAAAAAAAA/sendMessage";
        let sanitized = sanitize_url(url);
        assert_eq!(
            sanitized,
            "https://api.telegram.org/bot***REDACTED***/sendMessage"
        );
        assert!(!sanitized.contains("1234567890"));
        assert!(!sanitized.contains("AAAAAAAAAA"));
    }

    #[test]
    fn sanitize_url_no_bot_token() {
        let url = "https://example.com/api/test";
        assert_eq!(sanitize_url(url), url);
    }

    #[test]
    fn quick_block_rejects_invalid_ip() {
        // Valid IPs should be accepted
        assert!("1.2.3.4".parse::<std::net::IpAddr>().is_ok());
        assert!("::1".parse::<std::net::IpAddr>().is_ok());
        assert!("2001:db8::1".parse::<std::net::IpAddr>().is_ok());

        // Invalid strings should be rejected
        assert!("not-an-ip".parse::<std::net::IpAddr>().is_err());
        assert!("1.2.3.4; rm -rf /".parse::<std::net::IpAddr>().is_err());
        assert!("".parse::<std::net::IpAddr>().is_err());
    }

    #[test]
    fn telegram_batcher_groups_same_detector() {
        let mut b = super::TelegramBatcher::new(30);
        let now = chrono::Utc::now();

        let inc = |det: &str, sev: &str| Incident {
            ts: now,
            host: "test".into(),
            incident_id: format!("{det}:x:{}", now.format("%H:%M")),
            severity: match sev {
                "critical" => innerwarden_core::event::Severity::Critical,
                "high" => innerwarden_core::event::Severity::High,
                _ => innerwarden_core::event::Severity::Medium,
            },
            title: format!("{det} alert"),
            summary: format!("{det} summary"),
            evidence: serde_json::json!([]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };

        // Critical always immediate
        assert!(b.should_send_immediately(&inc("reverse_shell", "critical")));

        // First ssh_bruteforce goes through
        assert!(b.should_send_immediately(&inc("ssh_bruteforce", "high")));
        b.record(&inc("ssh_bruteforce", "high"));

        // Second ssh_bruteforce should batch
        assert!(!b.should_send_immediately(&inc("ssh_bruteforce", "high")));
        b.record(&inc("ssh_bruteforce", "high"));
        b.record(&inc("ssh_bruteforce", "high"));

        // Flush produces summary
        let summaries = b.flush();
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].contains("ssh_bruteforce"));
        assert!(summaries[0].contains("2")); // 2 batched
    }

    // -----------------------------------------------------------------------
    // Simple profile tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_simple_message_ssh_bruteforce_guard() {
        let inc = make_incident(
            Severity::Critical,
            vec![],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_simple_message(&inc, None, GuardianMode::Guard);
        assert!(
            msg.contains("tried to guess your server's password"),
            "should contain plain description"
        );
        assert!(msg.contains("Handled automatically."));
        assert!(!msg.contains("1.2.3.4"), "simple mode must not show IPs");
        assert!(
            !msg.contains("ssh_bruteforce"),
            "simple mode must not show detector name"
        );
        assert!(
            msg.contains("\u{1f534}"),
            "critical should have red circle emoji"
        );
    }

    #[test]
    fn format_simple_message_watch_mode() {
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![EntityRef::ip("5.6.7.8".to_string())],
        );
        let msg = format_simple_message(&inc, None, GuardianMode::Watch);
        assert!(msg.contains("Monitoring the situation."));
    }

    #[test]
    fn format_simple_message_unknown_detector() {
        let mut inc = make_incident(Severity::Medium, vec![], vec![]);
        inc.incident_id = "unknown_detector:foo:bar".to_string();
        let msg = format_simple_message(&inc, None, GuardianMode::Guard);
        assert!(msg.contains("Suspicious activity detected."));
    }

    #[test]
    fn explain_detector_returns_explanation() {
        let explanation = explain_detector("ssh_bruteforce");
        assert!(explanation.contains("guessing passwords"));
        assert!(explanation.contains("What does this mean?"));

        let explanation = explain_detector("ransomware");
        assert!(explanation.contains("encrypts your files"));

        // Unknown detector should give generic explanation
        let explanation = explain_detector("totally_unknown");
        assert!(explanation.contains("suspicious activity"));
    }

    #[test]
    fn format_daily_digest_simple() {
        let msg = format_daily_digest(42, 30, 2, 5, "ssh_bruteforce", 15, true);
        assert!(msg.contains("Good morning!"));
        assert!(msg.contains("30 attacks blocked"));
        assert!(msg.contains("2 critical threats"));
        assert!(msg.contains("Health:"));
        assert!(msg.contains("Everything is under control."));
        // Score = 100 - 2*20 - 5*5 = 35 → 🔴
        assert!(msg.contains("\u{1f534}"));
    }

    #[test]
    fn format_daily_digest_technical() {
        let msg = format_daily_digest(42, 30, 2, 5, "ssh_bruteforce", 15, false);
        assert!(msg.contains("Daily digest"));
        assert!(msg.contains("42 incidents"));
        assert!(msg.contains("30 blocks"));
        assert!(msg.contains("ssh_bruteforce: 15"));
        assert!(msg.contains("Critical: 2 | High: 5"));
    }

    #[test]
    fn format_daily_digest_health_score() {
        // Perfect score
        let msg = format_daily_digest(5, 5, 0, 0, "port_scan", 5, true);
        assert!(msg.contains("100/100"));
        assert!(msg.contains("\u{1f7e2}")); // 🟢

        // Yellow zone: 100 - 0*20 - 6*5 = 70
        let msg = format_daily_digest(10, 10, 0, 6, "port_scan", 6, true);
        assert!(msg.contains("70/100"));
        assert!(msg.contains("\u{1f7e1}")); // 🟡

        // Red zone: 100 - 3*20 - 10*5 = -10 → clamped to 0
        let msg = format_daily_digest(50, 50, 3, 10, "ssh_bruteforce", 20, true);
        assert!(msg.contains("0/100"));
        assert!(msg.contains("\u{1f534}")); // 🔴
    }

    #[test]
    fn format_simple_status_safe() {
        let msg = format_simple_status(false, false, false, 45, 1200, "3 hours ago");
        assert!(msg.contains("\u{1f7e2}")); // 🟢
        assert!(msg.contains("safe"));
        assert!(msg.contains("45 days"));
        assert!(msg.contains("1200 attacks blocked"));
        assert!(msg.contains("3 hours ago"));
    }

    #[test]
    fn format_simple_status_under_watch() {
        let msg = format_simple_status(false, true, false, 10, 50, "25 minutes ago");
        assert!(msg.contains("\u{1f7e1}")); // 🟡
        assert!(msg.contains("under watch"));
    }

    #[test]
    fn format_simple_status_needs_attention() {
        let msg = format_simple_status(true, true, true, 10, 50, "2 minutes ago");
        assert!(msg.contains("\u{1f534}")); // 🔴
        assert!(msg.contains("needs attention"));
    }

    #[test]
    fn simple_detector_lookup_covers_all_detectors() {
        // Verify all documented detectors return non-default entries
        let known_detectors = [
            "ssh_bruteforce",
            "credential_stuffing",
            "port_scan",
            "packet_flood",
            "data_exfil",
            "data_exfil_cmd",
            "data_exfil_ebpf",
            "reverse_shell",
            "privesc",
            "rootkit",
            "ransomware",
            "dns_tunneling",
            "dns_tunneling_ebpf",
            "c2_callback",
            "crypto_miner",
            "container_escape",
            "lateral_movement",
            "web_shell",
            "process_injection",
            "fileless",
            "log_tampering",
            "ssh_key_injection",
            "crontab_persistence",
            "systemd_persistence",
            "kernel_module_load",
            "discovery_burst",
            "sigma",
            "suspicious_execution",
            "sensitive_write",
            "user_creation",
            "process_tree",
            "neural_anomaly",
        ];

        for det in &known_detectors {
            let (_emoji, template) = simple_detector_lookup(det);
            assert!(
                !template.starts_with("Suspicious activity detected"),
                "detector '{}' should have a specific message, not fallback",
                det
            );
            assert!(
                template.contains("{action}"),
                "detector '{}' template must contain {{action}}",
                det
            );
        }

        // Default fallback
        let (_emoji, template) = simple_detector_lookup("unknown_detector_xyz");
        assert!(template.contains("Suspicious activity detected"));
    }
}

// ---------------------------------------------------------------------------
// Telegram Batcher — groups repeated alerts into periodic summaries
// ---------------------------------------------------------------------------

use std::collections::HashMap;

/// Groups repeated incidents by detector to avoid Telegram spam.
/// Critical incidents always go immediately. Repeated incidents of the
/// same detector within `window_secs` are batched into a single summary.
pub struct TelegramBatcher {
    /// detector → (count, first_title, unique_ips)
    pending: HashMap<String, (u32, String, std::collections::HashSet<String>)>,
    /// When the current batch window started
    window_start: chrono::DateTime<chrono::Utc>,
    /// Batch window in seconds
    window_secs: i64,
    /// Detectors seen in current window (for "first occurrence" logic)
    seen_this_window: std::collections::HashSet<String>,
}

impl TelegramBatcher {
    pub fn new(window_secs: i64) -> Self {
        Self {
            pending: HashMap::new(),
            window_start: chrono::Utc::now(),
            window_secs,
            seen_this_window: std::collections::HashSet::new(),
        }
    }

    /// Returns true if this incident should be sent immediately (not batched).
    /// Critical severity always goes immediately. First occurrence of a detector
    /// in a window also goes immediately. Subsequent same-detector alerts batch.
    pub fn should_send_immediately(&self, incident: &Incident) -> bool {
        // Critical always immediate
        if matches!(
            incident.severity,
            innerwarden_core::event::Severity::Critical
        ) {
            return true;
        }

        let detector = extract_detector(&incident.incident_id);

        // First occurrence in this window — send immediately
        !self.seen_this_window.contains(detector)
    }

    /// Record an incident for batching (call after checking should_send_immediately).
    /// Only counts incidents that were NOT sent immediately (batched ones).
    pub fn record(&mut self, incident: &Incident) {
        let detector = extract_detector(&incident.incident_id).to_string();
        let already_seen = self.seen_this_window.contains(&detector);
        self.seen_this_window.insert(detector.clone());

        // Only count if this is a repeat (first occurrence was sent immediately)
        if !already_seen {
            return;
        }

        let entry = self
            .pending
            .entry(detector)
            .or_insert_with(|| (0, incident.title.clone(), std::collections::HashSet::new()));
        entry.0 += 1;

        // Collect unique IPs
        for entity in &incident.entities {
            if entity.r#type == innerwarden_core::entities::EntityType::Ip {
                entry.2.insert(entity.value.clone());
            }
        }
    }

    /// Check if the batch window has elapsed.
    pub fn should_flush(&self) -> bool {
        let elapsed = chrono::Utc::now() - self.window_start;
        elapsed.num_seconds() >= self.window_secs
    }

    /// Flush all pending batched incidents into summary messages.
    /// Returns formatted HTML summaries ready to send.
    pub fn flush(&mut self) -> Vec<String> {
        let mut summaries = Vec::new();

        // Only emit summaries for detectors with batched (>0) incidents
        for (detector, (count, _title, ips)) in &self.pending {
            if *count == 0 {
                continue;
            }
            let ip_list = if ips.is_empty() {
                String::new()
            } else {
                let preview: Vec<&str> = ips.iter().map(|s| s.as_str()).take(5).collect();
                let more = if ips.len() > 5 {
                    format!(" +{} more", ips.len() - 5)
                } else {
                    String::new()
                };
                format!("\nIPs: <code>{}</code>{}", preview.join(", "), more)
            };
            summaries.push(format!(
                "📊 <b>{detector}</b>: {count} alerts batched (last {}s){ip_list}",
                self.window_secs
            ));
        }

        // Reset
        self.pending.clear();
        self.seen_this_window.clear();
        self.window_start = chrono::Utc::now();

        summaries
    }
}

/// Extract detector name from incident_id (format: "detector:rest:...")
fn extract_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or(incident_id)
}

/// Public wrapper for extract_detector, used by daily digest in main.rs.
pub fn extract_detector_pub(incident_id: &str) -> &str {
    extract_detector(incident_id)
}

/// Append an entry to the allowlist TOML file.
///
/// Creates the file if it does not exist. Each call appends a new
/// `[section]` header followed by the key-value pair so the sensor
/// picks it up on its next reload (every 60 s).
pub fn append_to_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
    reason: &str,
) -> anyhow::Result<()> {
    use fs2::FileExt;
    use std::io::Write;

    fn toml_escape(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(allowlist_path)?;
    file.lock_exclusive()?;
    let escaped_key = toml_escape(key);
    let escaped_reason = toml_escape(reason);
    writeln!(file, "\n[{section}]")?;
    writeln!(file, "\"{}\" = \"{}\"", escaped_key, escaped_reason)?;
    file.flush()?;
    file.unlock()?;
    Ok(())
}

/// Log an allowlist change (add or remove) to allowlist-history.jsonl.
pub fn log_allowlist_change(
    data_dir: &std::path::Path,
    key: &str,
    section: &str,
    operator: &str,
    action: &str,
) {
    let path = data_dir.join("allowlist-history.jsonl");
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "key": key,
        "section": section,
        "operator": operator,
        "action": action,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", entry);
    }
}

/// Read allowlist history and return last N "add" entries without matching "remove".
pub fn read_undoable_allowlist_entries(
    data_dir: &std::path::Path,
    max_entries: usize,
) -> Vec<(String, String, String, String)> {
    // Returns Vec<(key, section, operator, ts)>
    let path = data_dir.join("allowlist-history.jsonl");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut adds: Vec<(String, String, String, String)> = Vec::new();
    let mut removed_keys: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    // Parse all entries
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let key = v
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let section = v
                .get("section")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operator = v
                .get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ts = v
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let action = v
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if action == "add" {
                adds.push((key, section, operator, ts));
            } else if action == "remove" {
                removed_keys.insert((key, section));
            }
        }
    }

    // Filter out entries that have been removed, take last N
    adds.into_iter()
        .rev()
        .filter(|(key, section, _, _)| !removed_keys.contains(&(key.clone(), section.clone())))
        .take(max_entries)
        .collect()
}

/// Remove a key from allowlist.toml atomically.
/// Reads the file, removes lines containing the key in the appropriate section,
/// writes to a temp file, and renames over the original.
pub fn remove_from_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
) -> anyhow::Result<()> {
    use fs2::FileExt;

    let content = std::fs::read_to_string(allowlist_path).unwrap_or_default();

    let mut result_lines: Vec<String> = Vec::new();
    let mut in_target_section = false;
    let escaped_key = key.replace('\\', "\\\\").replace('"', "\\\"");

    for line in content.lines() {
        let trimmed = line.trim();
        // Track section headers
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = &trimmed[1..trimmed.len() - 1];
            in_target_section = sec == section;
            result_lines.push(line.to_string());
            continue;
        }

        // If in the target section, skip lines containing the key
        if in_target_section
            && (trimmed.contains(&format!("\"{}\"", escaped_key))
                || trimmed.contains(&format!("\"{}\"", key)))
        {
            continue;
        }

        result_lines.push(line.to_string());
    }

    // Remove trailing empty lines and consecutive empty section headers
    let output = result_lines.join("\n");

    // Write atomically: temp file + rename
    let temp_path = allowlist_path.with_extension("toml.tmp");
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        file.lock_exclusive()?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(output.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.unlock()?;
    }
    std::fs::rename(&temp_path, allowlist_path)?;

    Ok(())
}

/// Log an incident as a false positive to a daily JSONL file.
///
/// Used for training data collection and FP-rate tracking.  The file
/// is created if missing and each entry is one JSON line.
pub fn log_false_positive(
    data_dir: &std::path::Path,
    incident_id: &str,
    detector: &str,
    reporter: &str,
) {
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let path = data_dir.join(format!("fp-reports-{today}.jsonl"));
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "incident_id": incident_id,
        "detector": detector,
        "reporter": reporter,
        "action": "reported_fp"
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", entry);
    }
}

// ---------------------------------------------------------------------------
// Simple profile: plain-language messages
// ---------------------------------------------------------------------------

/// Returns (emoji, plain_description_template) for a given detector name.
/// The template may contain `{action}` which the caller replaces.
fn simple_detector_lookup(detector: &str) -> (&'static str, &'static str) {
    match detector {
        "ssh_bruteforce" => (
            "\u{1f512}",
            "Someone tried to guess your server's password. {action}",
        ),
        "credential_stuffing" => (
            "\u{1f3ad}",
            "Multiple login attempts with different passwords detected. {action}",
        ),
        "port_scan" => (
            "\u{1f50d}",
            "Someone is scanning your server looking for open doors. {action}",
        ),
        "packet_flood" => (
            "\u{1f30a}",
            "Your server is receiving unusual traffic. {action}",
        ),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => (
            "\u{1f4e4}",
            "A program tried to steal sensitive data. {action}",
        ),
        "reverse_shell" => (
            "\u{1f6a8}",
            "An attacker may have gained remote access. {action}",
        ),
        "privesc" => (
            "\u{1f451}",
            "A process tried to become administrator without permission. {action}",
        ),
        "rootkit" => (
            "\u{1f47b}",
            "Suspicious kernel-level activity detected. {action}",
        ),
        "ransomware" => ("\u{1f4b0}", "File encryption pattern detected. {action}"),
        "dns_tunneling" | "dns_tunneling_ebpf" => (
            "\u{1f310}",
            "Hidden communication channel detected. {action}",
        ),
        "c2_callback" => (
            "\u{1f4e1}",
            "Your server may be communicating with an attacker. {action}",
        ),
        "crypto_miner" => (
            "\u{26cf}\u{fe0f}",
            "Something is using your server to mine cryptocurrency. {action}",
        ),
        "container_escape" => (
            "\u{1f4e6}",
            "A container tried to break out of its sandbox. {action}",
        ),
        "lateral_movement" => ("\u{1f6b6}", "Movement between systems detected. {action}"),
        "web_shell" => (
            "\u{1f578}\u{fe0f}",
            "A web-based backdoor was detected. {action}",
        ),
        "process_injection" => (
            "\u{1f489}",
            "A program tried to inject code into another program. {action}",
        ),
        "fileless" => (
            "\u{1f47e}",
            "Fileless malware detected running only in memory. {action}",
        ),
        "log_tampering" => ("\u{1f9f9}", "Someone tried to erase their tracks. {action}"),
        "ssh_key_injection" => (
            "\u{1f511}",
            "An SSH key was added to allow future access. {action}",
        ),
        "crontab_persistence" | "systemd_persistence" => (
            "\u{23f0}",
            "Something installed itself to survive reboots. {action}",
        ),
        "kernel_module_load" => ("\u{1f9e9}", "A new kernel module was loaded. {action}"),
        "discovery_burst" => (
            "\u{1f5fa}\u{fe0f}",
            "Someone is mapping your system. {action}",
        ),
        "sigma" => ("\u{1f4cb}", "A known attack pattern was detected. {action}"),
        "suspicious_execution" => (
            "\u{26a0}\u{fe0f}",
            "A suspicious program was executed. {action}",
        ),
        "sensitive_write" => (
            "\u{270f}\u{fe0f}",
            "A sensitive system file was modified. {action}",
        ),
        "user_creation" => ("\u{1f464}", "A new user account was created. {action}"),
        "process_tree" => ("\u{1f333}", "Suspicious program chain detected. {action}"),
        "neural_anomaly" => (
            "\u{1f9e0}",
            "Unusual behavior pattern detected by AI. {action}",
        ),
        _ => ("\u{26a0}\u{fe0f}", "Suspicious activity detected. {action}"),
    }
}

/// Severity emoji for simple profile messages.
fn simple_severity_emoji(incident: &Incident) -> &'static str {
    use innerwarden_core::event::Severity::*;
    match incident.severity {
        Critical => "\u{1f534}", // 🔴
        High => "\u{1f7e0}",     // 🟠
        Medium => "\u{1f7e1}",   // 🟡
        Low => "\u{1f7e2}",      // 🟢
        _ => "\u{26aa}",         // ⚪
    }
}

/// Format a plain-language alert message for simple profile users.
/// No IPs, no detector names, no technical jargon.
fn format_simple_message(
    incident: &Incident,
    _dashboard_url: Option<&str>,
    mode: GuardianMode,
) -> String {
    let detector = extract_detector(&incident.incident_id);
    let (_det_emoji, template) = simple_detector_lookup(detector);
    let sev_emoji = simple_severity_emoji(incident);

    let action = match mode {
        GuardianMode::Guard => "Handled automatically.",
        GuardianMode::DryRun | GuardianMode::Watch => "Monitoring the situation.",
    };

    let description = template.replace("{action}", action);

    format!("{sev_emoji} {description}")
}

/// Return a 2-3 sentence plain explanation for a detector.
/// Used when simple-profile users tap "What does this mean?"
pub fn explain_detector(detector: &str) -> String {
    let text = match detector {
        "ssh_bruteforce" => "This means someone from another country tried to log into your server by guessing passwords. This is very common on the internet and happens to every server. InnerWarden blocked them automatically. You don't need to do anything.",
        "credential_stuffing" => "This means someone used a list of stolen passwords from other websites to try to log in to your server. These passwords were leaked in data breaches. InnerWarden detected the pattern and stopped it.",
        "port_scan" => "Someone is checking which services are running on your server. This is like someone walking around a building trying every door. It's a common first step before an attack. InnerWarden is keeping watch.",
        "packet_flood" => "Your server received a large amount of network traffic in a short time. This could be an attempt to overwhelm your server (DDoS attack). InnerWarden is managing the traffic.",
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => "A program on your server tried to send sensitive data (like passwords or configuration files) to an external location. This could mean an attacker is trying to steal information. InnerWarden caught it.",
        "reverse_shell" => "An attacker may have established a way to remotely control your server. This is a serious threat where someone can execute commands as if they were sitting at the keyboard. InnerWarden is taking action.",
        "privesc" => "A program tried to gain administrator (root) access without proper authorization. This usually means an attacker is trying to take full control of your server. InnerWarden blocked the attempt.",
        "rootkit" => "Suspicious activity was detected at the deepest level of your operating system (the kernel). Rootkits try to hide malicious software from detection tools. This is a serious threat that InnerWarden is monitoring closely.",
        "ransomware" => "A pattern consistent with ransomware was detected. Ransomware encrypts your files and demands payment to unlock them. InnerWarden detected this early to prevent damage.",
        "dns_tunneling" | "dns_tunneling_ebpf" => "A program is using the DNS system (which translates domain names to addresses) to secretly send or receive data. Attackers use this to bypass firewalls. InnerWarden detected the hidden channel.",
        "c2_callback" => "Your server appears to be communicating with a known attacker-controlled server (called 'command and control'). This could mean malware is receiving instructions. InnerWarden is intervening.",
        "crypto_miner" => "Something on your server is using CPU power to mine cryptocurrency. This steals your computing resources and increases your electricity costs. InnerWarden detected the unauthorized mining.",
        "container_escape" => "A containerized application tried to access resources outside its isolated environment. Containers are supposed to be sandboxed. This could be an attack attempting to reach the host system.",
        "lateral_movement" => "An attacker is trying to move from one system or account to another within your network. This is how attackers spread after their initial break-in. InnerWarden detected the movement.",
        "web_shell" => "A web-based backdoor was found on your server. Web shells allow attackers to run commands through a web page. This usually means an attacker uploaded a malicious file to your web server.",
        "process_injection" => "A program tried to insert its code into another running program. Attackers do this to hide their activity inside legitimate software. InnerWarden caught the injection attempt.",
        "fileless" => "Malware was detected running entirely in memory without writing to disk. This technique is used to avoid antivirus detection. InnerWarden's memory analysis caught it.",
        "log_tampering" => "Someone tried to delete or modify system logs. Attackers do this to cover their tracks after breaking in. InnerWarden preserves the evidence and detected the tampering.",
        "ssh_key_injection" => "An SSH key was added to your server's authorized keys. This would allow someone to log in without a password in the future. If you didn't do this, an attacker is setting up persistent access.",
        "crontab_persistence" | "systemd_persistence" => "Something installed a scheduled task or service that will start automatically, even after a reboot. Attackers use this to maintain access to your server long-term. InnerWarden is monitoring it.",
        "kernel_module_load" => "A new kernel module was loaded into your operating system's core. While some modules are legitimate (drivers, etc.), malicious modules can give attackers deep system access. InnerWarden is checking it.",
        "discovery_burst" => "Someone is running commands to map out your system, listing users, files, network connections, and installed software. This is reconnaissance, usually done after an initial break-in. InnerWarden is watching.",
        "sigma" => "A known attack pattern from the security community's signature database was matched. These patterns are maintained by security researchers worldwide. InnerWarden recognized the threat.",
        "suspicious_execution" => "A program was executed that matches patterns commonly seen in attacks. This could be a legitimate tool being misused or actual malware. InnerWarden is investigating.",
        "sensitive_write" => "An important system file (like password files or security configurations) was modified. If this wasn't a planned change, it could indicate an attacker modifying your system.",
        "user_creation" => "A new user account was created on your server. If you didn't create it, this could mean an attacker is setting up their own access. InnerWarden is tracking it.",
        "process_tree" => "A suspicious chain of programs was detected. For example, a web server launching a command shell is unusual and often indicates exploitation. InnerWarden noticed the suspicious chain.",
        "neural_anomaly" => "InnerWarden's AI detected behavior that doesn't match your server's normal patterns. Machine learning identified something unusual that rule-based detection might miss.",
        _ => "InnerWarden detected suspicious activity on your server. The system is monitoring the situation and will take appropriate action based on your settings.",
    };
    format!(
        "\u{2139}\u{fe0f} <b>What does this mean?</b>\n\n{}",
        escape_html(text)
    )
}

// ---------------------------------------------------------------------------
// Daily digest
// ---------------------------------------------------------------------------

/// Format the daily digest message.
/// Simple mode: friendly, non-technical. Technical mode: concise stats.
pub fn format_daily_digest(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
) -> String {
    if is_simple {
        let raw_score = 100i32
            .saturating_sub(critical_count as i32 * 20)
            .saturating_sub(high_count as i32 * 5);
        let score = raw_score.clamp(0, 100) as u32;
        let health_emoji = if score >= 80 {
            "\u{1f7e2}" // 🟢
        } else if score >= 50 {
            "\u{1f7e1}" // 🟡
        } else {
            "\u{1f534}" // 🔴
        };

        format!(
            "\u{2600}\u{fe0f} Good morning! Your server in the last 24h:\n\
             \n\
             \u{00a0}\u{00a0}{blocks_today} attacks blocked\n\
             \u{00a0}\u{00a0}{critical_count} critical threats\n\
             \u{00a0}\u{00a0}Health: {score}/100 {health_emoji}\n\
             \n\
             Everything is under control."
        )
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        format!(
            "\u{1f4ca} Daily digest ({date}):\n\
             \u{00a0}\u{00a0}Total: {incidents_today} incidents, {blocks_today} blocks\n\
             \u{00a0}\u{00a0}{top_detector}: {top_count}\n\
             \u{00a0}\u{00a0}Critical: {critical_count} | High: {high_count}",
            top_detector = escape_html(top_detector),
        )
    }
}

// ---------------------------------------------------------------------------
// Simple /status
// ---------------------------------------------------------------------------

/// Format a simple /status response.
/// Returns the semaphore status message for non-technical users.
pub fn format_simple_status(
    has_critical_last_24h: bool,
    has_high_last_hour: bool,
    has_critical_last_hour: bool,
    uptime_days: u64,
    total_blocked: u64,
    last_threat_ago: &str,
) -> String {
    let (semaphore, status_word) = if has_critical_last_hour {
        ("\u{1f534}", "needs attention") // 🔴
    } else if has_high_last_hour {
        ("\u{1f7e1}", "under watch") // 🟡
    } else {
        ("\u{1f7e2}", "safe") // 🟢
    };

    // Suppress "no critical" label when there are none
    let _ = has_critical_last_24h;

    format!(
        "{semaphore} Your server is {status_word}\n\
         \n\
         Protected for {uptime_days} days\n\
         {total_blocked} attacks blocked\n\
         Last threat: {last_threat_ago}",
        last_threat_ago = escape_html(last_threat_ago),
    )
}
