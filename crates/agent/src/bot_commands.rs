use crate::config;

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
