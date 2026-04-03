use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{
    config_editor, hostname, load_env_file, prompt, prompt_with_hint, require_sudo, restart_agent,
    send_telegram_message_md, systemd, write_env_key, Cli,
};

pub(crate) fn cmd_configure_telegram(
    cli: &Cli,
    token_arg: Option<&str>,
    chat_id_arg: Option<&str>,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // ── Step 1: bot token ──────────────────────────────────────────────────
    let token = if let Some(t) = token_arg {
        t.to_string()
    } else {
        println!("InnerWarden - Telegram setup\n");
        println!("Step 1 - Create a bot");
        println!("  1. Open Telegram and message @BotFather");
        println!("  2. Send:  /newbot");
        println!("  3. Choose a name and username for your bot");
        println!("  4. Copy the token BotFather gives you (looks like 123456789:ABCdef...)\n");
        let t = prompt("Bot token")?;
        if t.is_empty() {
            anyhow::bail!("token cannot be empty");
        }
        t
    };

    // Basic format check: digits : alphanumeric
    if !token.contains(':') || token.split(':').next().is_none_or(|s| s.is_empty()) {
        anyhow::bail!(
            "token looks wrong - expected format: 123456789:ABCdef...\nGet one from @BotFather on Telegram."
        );
    }

    // ── Step 2: chat ID ────────────────────────────────────────────────────
    let chat_id = if let Some(c) = chat_id_arg {
        c.to_string()
    } else {
        // Try to discover chat_id from pending updates (works if user already messaged the bot)
        let discovered = discover_telegram_chat_id(&token);

        match discovered {
            Some(id) => {
                println!("\n  Found your chat ID automatically: {id}");
                print!("  Use this chat ID? [Y/n] ");
                std::io::stdout().flush()?;
                let mut ans = String::new();
                std::io::stdin().read_line(&mut ans)?;
                if ans.trim().to_lowercase() == "n" {
                    let manual = prompt_with_hint(
                        "Chat ID",
                        "send a message to your bot first, then re-run",
                    )?;
                    if manual.is_empty() {
                        anyhow::bail!("chat ID cannot be empty");
                    }
                    manual
                } else {
                    id
                }
            }
            None => {
                println!();
                println!("  Now open Telegram and send any message to your bot.");
                println!("  Waiting for your message...");
                std::io::stdout().flush()?;

                // Long-poll getUpdates (5s timeout per request, up to 2 minutes total)
                let mut found = None;
                for _ in 0..24 {
                    if let Some(id) = discover_telegram_chat_id(&token) {
                        found = Some(id);
                        break;
                    }
                    // discover_telegram_chat_id already waits 5s via long poll
                    print!(".");
                    std::io::stdout().flush()?;
                }
                println!();

                match found {
                    Some(id) => {
                        println!("  ✓ Got it! Chat ID: {id}");
                        id
                    }
                    None => {
                        println!("  Timed out. Enter your chat ID manually:");
                        println!("  (Message @userinfobot on Telegram to get it)");
                        let c = prompt("Chat ID")?;
                        if c.is_empty() {
                            anyhow::bail!("chat ID cannot be empty");
                        }
                        c
                    }
                }
            }
        }
    };

    // Validate chat_id is numeric (may be negative for groups)
    let chat_id_trimmed = chat_id.trim_start_matches('-');
    if !chat_id_trimmed.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "chat ID must be a number (e.g. 123456789 for a user, -100... for a group).\nGet yours by messaging @userinfobot on Telegram."
        );
    }

    // ── Save credentials ───────────────────────────────────────────────────
    if cli.dry_run {
        println!(
            "\n  [dry-run] would write TELEGRAM_BOT_TOKEN=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would write TELEGRAM_CHAT_ID={chat_id} to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [telegram] enabled=true in {}",
            cli.agent_config.display()
        );
    } else {
        write_env_key(&env_file, "TELEGRAM_BOT_TOKEN", &token)?;
        write_env_key(&env_file, "TELEGRAM_CHAT_ID", &chat_id)?;
        println!("\n  [ok] Credentials saved to {}", env_file.display());

        config_editor::write_bool(&cli.agent_config, "telegram", "enabled", true)?;
        println!("  [ok] agent.toml: telegram.enabled = true");
    }

    // ── Test notification ──────────────────────────────────────────────────
    if !no_test && !cli.dry_run {
        print!("  Sending test notification... ");
        std::io::stdout().flush()?;
        match send_telegram_test(&token, &chat_id) {
            Ok(()) => println!("sent!"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: could not send test message: {e:#}");
                println!("  Your credentials have been saved. Check token and chat_id with:");
                println!("  innerwarden doctor");
            }
        }
    }

    // ── Restart agent ──────────────────────────────────────────────────────
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {cmd}");
    } else if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("Telegram is ready.");
    println!();
    println!("  Your bot sends alerts and responds to commands:");
    println!("    /menu       - interactive button menu");
    println!("    /status     - system overview");
    println!("    /incidents  - last incidents");
    println!("    /decisions  - last decisions");
    println!("    /ask <q>    - ask the AI a question");
    println!();
    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "telegram".to_string(),
        parameters: serde_json::json!({}),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("Next steps:");
    println!("  innerwarden status       - check services and active capabilities");
    println!("  innerwarden doctor       - validate the full setup");
    println!("  innerwarden test-alert   - send a test alert right now");
    Ok(())
}

/// Try to get the chat_id by long-polling for new messages.
/// First clears any pending updates, then waits for a fresh message.
fn discover_telegram_chat_id(token: &str) -> Option<String> {
    // Step 1: Clear old updates by fetching with offset -1
    let clear_url =
        format!("https://api.telegram.org/bot{token}/getUpdates?offset=-1&limit=1&timeout=0");
    let mut next_offset = 0i64;
    if let Ok(resp) = ureq::get(&clear_url).call() {
        if let Ok(json) = resp.into_body().read_json::<serde_json::Value>() {
            if let Some(last) = json["result"].as_array().and_then(|a| a.last()) {
                if let Some(uid) = last["update_id"].as_i64() {
                    next_offset = uid + 1; // Skip past all old updates
                }
            }
        }
    }

    // Step 2: Long-poll for a NEW message (timeout=5s per request)
    let poll_url = format!(
        "https://api.telegram.org/bot{token}/getUpdates?offset={next_offset}&limit=1&timeout=5"
    );
    let resp = ureq::get(&poll_url).call().ok()?;
    let json: serde_json::Value = resp.into_body().read_json().ok()?;
    json["result"]
        .as_array()?
        .first()?
        .get("message")?
        .get("chat")?
        .get("id")?
        .as_i64()
        .map(|id| id.to_string())
}

/// Send a test Telegram message to confirm the configuration works.
fn send_telegram_test(token: &str, chat_id: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({
        "chat_id": chat_id,
        "text": "✅ <b>InnerWarden connected</b>\n\nYou'll receive alerts here when High or Critical threats are detected on your server.\n\n<b>Commands:</b>\n/menu - interactive button menu\n/status - system overview\n/incidents - last incidents\n/decisions - last decisions\n/ask &lt;question&gt; - ask the AI\n\nOr just type a question in plain text.",
        "parse_mode": "HTML"
    });
    let resp = ureq::post(&url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json: serde_json::Value = resp.into_body().read_json()?;
    if json["ok"].as_bool() != Some(true) {
        anyhow::bail!(
            "{}",
            json["description"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden configure slack
// ---------------------------------------------------------------------------

pub(crate) fn cmd_configure_slack(
    cli: &Cli,
    webhook_url_arg: Option<&str>,
    min_severity: &str,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // ── Webhook URL ────────────────────────────────────────────────────────
    let webhook_url = if let Some(u) = webhook_url_arg {
        u.to_string()
    } else {
        println!("InnerWarden - Slack setup\n");
        println!("Step 1 - Create an Incoming Webhook");
        println!("  1. Go to https://api.slack.com/apps and click 'Create New App'");
        println!("  2. Choose 'From scratch', name it 'InnerWarden', pick your workspace");
        println!("  3. Click 'Incoming Webhooks' → toggle On → 'Add New Webhook to Workspace'");
        println!("  4. Choose a channel (e.g. #security-alerts) → Allow");
        println!("  5. Copy the webhook URL (starts with https://hooks.slack.com/...)\n");
        let u = prompt("Webhook URL")?;
        if u.is_empty() {
            anyhow::bail!("webhook URL cannot be empty");
        }
        u
    };

    if !webhook_url.starts_with("https://hooks.slack.com/") {
        anyhow::bail!(
            "webhook URL should start with https://hooks.slack.com/\nGet one at https://api.slack.com/apps"
        );
    }

    // Validate severity
    if !matches!(min_severity, "low" | "medium" | "high" | "critical") {
        anyhow::bail!("min-severity must be one of: low, medium, high, critical");
    }

    // ── Save credentials ───────────────────────────────────────────────────
    if cli.dry_run {
        println!(
            "\n  [dry-run] would write SLACK_WEBHOOK_URL=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [slack] enabled=true min_severity={min_severity} in {}",
            cli.agent_config.display()
        );
    } else {
        write_env_key(&env_file, "SLACK_WEBHOOK_URL", &webhook_url)?;
        println!("\n  [ok] Webhook URL saved to {}", env_file.display());

        config_editor::write_bool(&cli.agent_config, "slack", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "slack", "min_severity", min_severity)?;
        println!("  [ok] agent.toml: slack.enabled = true, min_severity = {min_severity}");
    }

    // ── Test notification ──────────────────────────────────────────────────
    if !no_test && !cli.dry_run {
        print!("  Sending test notification... ");
        std::io::stdout().flush()?;
        match send_slack_test(&webhook_url) {
            Ok(()) => println!("sent!"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: could not send test message: {e:#}");
                println!("  Your URL has been saved. Verify it at https://api.slack.com/apps");
            }
        }
    }

    // ── Restart agent ──────────────────────────────────────────────────────
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {cmd}");
    } else if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "slack".to_string(),
        parameters: serde_json::json!({ "min_severity": min_severity }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Slack configured. You'll receive alerts for {min_severity}+ incidents.");
    println!("Run 'innerwarden doctor' to validate the full setup.");
    Ok(())
}

fn send_slack_test(webhook_url: &str) -> Result<()> {
    let body = serde_json::json!({
        "text": "✅ *InnerWarden* is connected. You'll receive security alerts here."
    });
    ureq::post(webhook_url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub(crate) fn cmd_configure_webhook(
    cli: &Cli,
    url_arg: Option<&str>,
    min_severity: &str,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    // Validate severity
    if !matches!(min_severity, "low" | "medium" | "high" | "critical") {
        anyhow::bail!("min-severity must be one of: low, medium, high, critical");
    }

    let url = if let Some(u) = url_arg {
        u.to_string()
    } else {
        println!("InnerWarden - Webhook setup\n");
        println!("Sends a JSON POST to your endpoint for every alert.\n");
        println!("Works with:");
        println!("  PagerDuty, Opsgenie, Discord, Microsoft Teams, Google Chat,");
        println!("  DingTalk, Feishu/Lark, WeCom, n8n, Zapier, Make, Home Assistant\n");
        println!("Tip: for PagerDuty, set format later with:");
        println!("  innerwarden configure webhook --format pagerduty\n");
        let u = prompt("Webhook URL")?;
        if u.is_empty() {
            anyhow::bail!("URL cannot be empty");
        }
        u
    };

    if !url.starts_with("http://") && !url.starts_with("https://") {
        anyhow::bail!("URL must start with http:// or https://");
    }

    if cli.dry_run {
        println!("\n  [dry-run] would set [webhook] enabled=true url=... min_severity={min_severity} in {}", cli.agent_config.display());
    } else {
        config_editor::write_bool(&cli.agent_config, "webhook", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "webhook", "url", &url)?;
        config_editor::write_str(&cli.agent_config, "webhook", "min_severity", min_severity)?;
        println!("\n  [ok] agent.toml: webhook.enabled = true, min_severity = {min_severity}");
    }

    if !no_test && !cli.dry_run {
        print!("  Sending test request... ");
        std::io::stdout().flush()?;
        match send_webhook_test(&url) {
            Ok(status) => println!("ok (HTTP {status})"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: {e:#}");
                println!("  Your URL has been saved. Check the endpoint is reachable.");
            }
        }
    }

    restart_agent(cli);

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "webhook".to_string(),
        parameters: serde_json::json!({ "min_severity": min_severity }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Webhook configured. Alerts ({min_severity}+) will be sent to your endpoint.");
    println!("Run 'innerwarden doctor' to validate.");
    Ok(())
}

fn send_webhook_test(url: &str) -> Result<u16> {
    let body = serde_json::json!({
        "source": "innerwarden",
        "kind": "test",
        "severity": "low",
        "summary": "InnerWarden webhook test - configuration successful",
        "host": hostname()
    });
    let resp = ureq::post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "innerwarden-ctl/1.0")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(resp.status().as_u16())
}

// ---------------------------------------------------------------------------
// innerwarden configure dashboard
// ---------------------------------------------------------------------------

pub(crate) fn cmd_configure_dashboard(
    cli: &Cli,
    user: &str,
    password_arg: Option<&str>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // When password is provided via --password flag, use it directly.
    // Otherwise let the agent binary handle prompting (hidden input + confirm = 2 prompts total).
    let hash = if let Some(password) = password_arg {
        // Non-interactive path: pipe password to agent subprocess.
        let agent_bin = cli
            .agent_config
            .parent()
            .and_then(|_| {
                for path in &[
                    "/usr/local/bin/innerwarden-agent",
                    "/usr/bin/innerwarden-agent",
                ] {
                    if Path::new(path).exists() {
                        return Some(PathBuf::from(path));
                    }
                }
                None
            })
            .or_else(|| which_bin("innerwarden-agent"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "innerwarden-agent not found - run ./install.sh first or generate hash manually:\
                    \n  innerwarden-agent --dashboard-generate-password-hash"
                )
            })?;

        let output = std::process::Command::new(&agent_bin)
            .arg("--dashboard-generate-password-hash")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = writeln!(stdin, "{password}");
                    let _ = writeln!(stdin, "{password}");
                }
                child.wait_with_output()
            })
            .map_err(|e| anyhow::anyhow!("failed to run agent binary: {e}"))?;

        if !output.status.success() {
            anyhow::bail!("agent binary failed to generate hash");
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        raw.lines()
            .find(|l| l.starts_with("$argon2"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("agent binary returned unexpected output"))?
    } else {
        // Interactive path: let the agent binary prompt for password (hidden, with confirm).
        // This avoids the duplicate-prompt issue - only 2 prompts instead of 3.
        println!("InnerWarden - Dashboard setup\n");
        println!("The dashboard requires a login to protect your security data.");
        println!("Choose a strong password (min 8 chars).\n");

        let agent_bin = cli
            .agent_config
            .parent()
            .and_then(|_| {
                for path in &[
                    "/usr/local/bin/innerwarden-agent",
                    "/usr/bin/innerwarden-agent",
                ] {
                    if Path::new(path).exists() {
                        return Some(PathBuf::from(path));
                    }
                }
                None
            })
            .or_else(|| which_bin("innerwarden-agent"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "innerwarden-agent not found - run ./install.sh first or generate hash manually:\
                    \n  innerwarden-agent --dashboard-generate-password-hash"
                )
            })?;

        // Inherit stdin/stderr so rpassword can read from the terminal directly.
        let output = std::process::Command::new(&agent_bin)
            .arg("--dashboard-generate-password-hash")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|e| anyhow::anyhow!("failed to run agent binary: {e}"))?;

        if !output.status.success() {
            anyhow::bail!("password setup failed");
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        raw.lines()
            .find(|l| l.starts_with("$argon2"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("agent binary returned unexpected output"))?
    };

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write INNERWARDEN_DASHBOARD_USER={user} to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would write INNERWARDEN_DASHBOARD_PASSWORD_HASH=<hash> to {}",
            env_file.display()
        );
        println!("  [dry-run] would add --dashboard to service ExecStart if missing");
    } else {
        write_env_key(&env_file, "INNERWARDEN_DASHBOARD_USER", user)?;
        write_env_key(&env_file, "INNERWARDEN_DASHBOARD_PASSWORD_HASH", &hash)?;
        println!("\n  [ok] Credentials saved to {}", env_file.display());
    }

    // Ensure --dashboard is in the service ExecStart
    ensure_dashboard_flag_in_service(cli);

    restart_agent(cli);
    println!();
    println!("Dashboard configured.");
    println!("  URL:      http://localhost:8787");
    println!("  Username: {user}");
    println!("  Password: (the one you entered)");
    println!();
    println!("To access from your browser via SSH tunnel:");
    println!("  ssh -L 8787:127.0.0.1:8787 user@YOUR_SERVER");
    println!("  Then open: http://localhost:8787");
    println!();
    println!("If you use nginx, add this to your server block:");
    println!("  location / {{");
    println!("      proxy_pass http://127.0.0.1:8787;");
    println!("      proxy_set_header Host $host;");
    println!("      proxy_set_header Authorization $http_authorization;");
    println!("      proxy_pass_header Authorization;");
    println!("      proxy_http_version 1.1;");
    println!("      proxy_buffering off;");
    println!("  }}");
    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "dashboard".to_string(),
        parameters: serde_json::json!({ "user": user }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Run 'innerwarden doctor' to validate.");
    Ok(())
}

/// Add `--dashboard` to the innerwarden-agent service ExecStart if not already present.
fn ensure_dashboard_flag_in_service(cli: &Cli) {
    // Only applies to Linux systemd
    if std::env::consts::OS == "macos" {
        return;
    }
    let service_path = "/etc/systemd/system/innerwarden-agent.service";
    let Ok(content) = std::fs::read_to_string(service_path) else {
        return;
    };
    if content.contains("--dashboard") {
        return;
    }
    // Patch ExecStart line to append --dashboard
    let patched = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("ExecStart=") && !line.contains("--dashboard") {
                format!("{line} --dashboard")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if cli.dry_run {
        println!("  [dry-run] would add --dashboard to {service_path}");
        return;
    }

    if std::fs::write(service_path, patched).is_ok() {
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
        println!("  [ok] --dashboard added to {service_path}");
    } else {
        println!(
            "  [warn] could not update {service_path} - add --dashboard to ExecStart manually"
        );
    }
}

fn which_bin(name: &str) -> Option<PathBuf> {
    std::env::var("PATH").ok()?.split(':').find_map(|dir| {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            Some(p)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------

pub(crate) fn cmd_test_alert(cli: &Cli, channel: Option<&str>) -> Result<()> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Detect permission-denied early - don't check exists() first because
    // the directory itself may be inaccessible, making exists() return false.
    if let Err(e) = std::fs::read_to_string(&env_file) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("Permission denied reading {}", env_file.display());
            eprintln!("Credentials are stored in a protected file.");
            eprintln!();
            let args: Vec<String> = std::env::args().collect();
            let cmd_args = args[1..].join(" ");
            eprintln!("Run with sudo:");
            eprintln!("  sudo innerwarden {cmd_args}");
            std::process::exit(1);
        }
        // File not found or other error - fine, load_env_file will return empty map
    }

    // Load agent.env for credentials
    let env_vars = load_env_file(&env_file);

    let test_only = channel;
    let mut any_tested = false;
    let mut any_failed = false;

    println!("InnerWarden - test alert\n");

    // ── Telegram ─────────────────────────────────────────────────────────
    let try_telegram = test_only.is_none_or(|c| c == "telegram");
    if try_telegram {
        let token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok());
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok());
        match (token, chat_id) {
            (Some(tok), Some(cid)) if !tok.is_empty() && !cid.is_empty() => {
                any_tested = true;
                print!("  Telegram ... ");
                std::io::stdout().flush().ok();
                let msg = "🔔 *Test alert from InnerWarden*\n\nYour Telegram notifications are working correctly\\.";
                match send_telegram_message_md(&tok, &cid, msg) {
                    Ok(()) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("telegram") {
                    println!("  Telegram ... not configured (run: innerwarden notify telegram)");
                    any_failed = true;
                } else {
                    println!("  Telegram ... skipped (not configured)");
                }
            }
        }
    }

    // ── Slack ─────────────────────────────────────────────────────────────
    let try_slack = test_only.is_none_or(|c| c == "slack");
    if try_slack {
        let webhook = env_vars
            .get("SLACK_WEBHOOK_URL")
            .cloned()
            .or_else(|| std::env::var("SLACK_WEBHOOK_URL").ok());
        match webhook {
            Some(url) if !url.is_empty() => {
                any_tested = true;
                print!("  Slack ...... ");
                std::io::stdout().flush().ok();
                let payload = serde_json::json!({
                    "text": "🔔 *Test alert from InnerWarden* - Slack notifications are working correctly."
                });
                match ureq::post(&url)
                    .header("Content-Type", "application/json")
                    .send(payload.to_string())
                {
                    Ok(_) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("slack") {
                    println!("  Slack ...... not configured (run: innerwarden configure slack)");
                    any_failed = true;
                } else {
                    println!("  Slack ...... skipped (not configured)");
                }
            }
        }
    }

    // ── Webhook ───────────────────────────────────────────────────────────
    let try_webhook = test_only.is_none_or(|c| c == "webhook");
    if try_webhook {
        // Read webhook URL and enabled flag from agent.toml
        let agent_doc: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let webhook_url: Option<String> = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|w| w.get("url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string());
        let webhook_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|w| w.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        match webhook_url {
            Some(url) if !url.is_empty() && webhook_enabled => {
                any_tested = true;
                print!("  Webhook .... ");
                std::io::stdout().flush().ok();
                let payload = serde_json::json!({
                    "type": "test",
                    "message": "Test alert from InnerWarden - webhook notifications are working correctly."
                });
                match ureq::post(&url)
                    .header("Content-Type", "application/json")
                    .config()
                    .timeout_global(Some(std::time::Duration::from_secs(10)))
                    .build()
                    .send(payload.to_string())
                {
                    Ok(_) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("webhook") {
                    println!("  Webhook .... not configured (run: innerwarden configure webhook)");
                    any_failed = true;
                } else {
                    println!("  Webhook .... skipped (not configured)");
                }
            }
        }
    }

    println!();
    if !any_tested {
        println!("No channels configured yet.");
        println!("Run 'innerwarden configure' to set up notifications.");
        return Ok(());
    }
    if any_failed {
        anyhow::bail!("One or more channels failed - run 'innerwarden doctor' for details");
    }
    println!("All channels ok.");
    Ok(())
}
