use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{
    epoch_secs_to_date, hostname, load_env_file, resolve_data_dir, send_telegram_message_md, Cli,
};

pub(crate) fn cmd_watchdog(
    cli: &Cli,
    threshold_secs: u64,
    notify: bool,
    data_dir: &std::path::Path,
) -> Result<()> {
    // Try to read data_dir from agent.toml if using default
    let effective_dir = if data_dir == std::path::Path::new("/var/lib/innerwarden") {
        cli.agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(std::path::PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Format today and yesterday as YYYY-MM-DD using chrono
    let today_str = chrono::Local::now().format("%Y-%m-%d").to_string();
    let yesterday_str = (chrono::Local::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // Find the most recent telemetry file
    let telemetry_path = {
        let today_p = effective_dir.join(format!("telemetry-{today_str}.jsonl"));
        let yest_p = effective_dir.join(format!("telemetry-{yesterday_str}.jsonl"));

        if today_p.exists() {
            today_p
        } else if yest_p.exists() {
            yest_p
        } else {
            println!("⚠️  No telemetry file found in {}", effective_dir.display());
            println!("   The agent may not be running: innerwarden status");
            if notify {
                maybe_send_watchdog_alert(
                    cli,
                    "InnerWarden agent appears offline - no telemetry files found.",
                );
            }
            return Ok(());
        }
    };

    // Use file mtime as the last-activity timestamp (most reliable)
    let last_ts_secs: Option<u64> = std::fs::metadata(&telemetry_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    match last_ts_secs {
        Some(ts) => {
            let age = now_secs.saturating_sub(ts);
            if age > threshold_secs {
                println!("⚠️  Agent appears unhealthy - last activity {}s ago (threshold: {threshold_secs}s)", age);
                println!("   Check status: innerwarden status");
                println!("   Check logs:   journalctl -u innerwarden-agent -n 50");
                if notify {
                    let msg = format!(
                        "⚠️ InnerWarden agent appears unhealthy on {}.\nLast activity: {}s ago (threshold: {}s).",
                        hostname(),
                        age,
                        threshold_secs
                    );
                    maybe_send_watchdog_alert(cli, &msg);
                }
                std::process::exit(1);
            } else {
                println!("✅ Agent is healthy - last activity {}s ago", age);
            }

            // Memory check - restart agent if RSS exceeds 512MB
            let max_rss_kb: u64 = 512 * 1024;
            if let Some(rss_kb) = get_agent_rss_kb() {
                let rss_mb = rss_kb / 1024;
                if rss_kb > max_rss_kb {
                    println!(
                        "⚠️  Agent memory too high: {}MB (limit: {}MB) - restarting",
                        rss_mb,
                        max_rss_kb / 1024
                    );
                    let _ = std::process::Command::new("sudo")
                        .args(["systemctl", "restart", "innerwarden-agent"])
                        .status();
                    if notify {
                        let msg = format!(
                            "⚠️ InnerWarden agent on {} was using {}MB RAM (limit: {}MB). Auto-restarted.",
                            hostname(),
                            rss_mb,
                            max_rss_kb / 1024
                        );
                        maybe_send_watchdog_alert(cli, &msg);
                    }
                } else {
                    println!("✅ Agent memory OK - {}MB", rss_mb);
                }
            }
        }
        None => {
            println!(
                "⚠️  Could not determine agent liveness from {}",
                telemetry_path.display()
            );
            if notify {
                maybe_send_watchdog_alert(
                    cli,
                    "InnerWarden watchdog could not verify agent health.",
                );
            }
        }
    }

    Ok(())
}

/// Read the RSS (resident set size) of the innerwarden-agent process in KB.
/// Returns None if the process is not found or /proc is not available.
fn get_agent_rss_kb() -> Option<u64> {
    let output = std::process::Command::new("pgrep")
        .args(["-f", "innerwarden-agent"])
        .output()
        .ok()?;
    let pids = String::from_utf8_lossy(&output.stdout);
    // Get the main agent PID (the actual binary, not sudo wrapper)
    for pid_str in pids.lines() {
        let pid = pid_str.trim();
        if pid.is_empty() {
            continue;
        }
        let status_path = format!("/proc/{pid}/status");
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if kb > 0 {
                        return Some(kb);
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// innerwarden watchdog --status
// ---------------------------------------------------------------------------

pub(crate) fn cmd_watchdog_status(cli: &Cli, data_dir: &Path) -> Result<()> {
    println!("Watchdog Status");
    println!("{}", "─".repeat(56));

    // ── Cron entry ────────────────────────────────────────
    println!("\nCron schedule");
    let crontab = std::process::Command::new("crontab").arg("-l").output();

    match crontab {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let entry = text
                .lines()
                .find(|l| l.contains("innerwarden watchdog") && !l.trim_start().starts_with('#'));
            match entry {
                Some(line) => {
                    println!("  ✅ Installed: {line}");
                    // Parse interval from */N prefix
                    if let Some(interval) = line
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.strip_prefix("*/"))
                        .and_then(|n| n.parse::<u64>().ok())
                    {
                        println!("     Runs every {interval} minute(s)");
                    }
                }
                None => {
                    println!("  ○ Not installed");
                    println!(
                        "    Run 'innerwarden configure watchdog' to set up automatic monitoring."
                    );
                }
            }
        }
        Ok(_) => {
            println!("  ○ No crontab for current user");
            println!("    Run 'innerwarden configure watchdog' to set up automatic monitoring.");
        }
        Err(_) => {
            println!("  ○ crontab command not available");
            println!("    On macOS you may need to configure launchd manually.");
            println!("    See: innerwarden configure watchdog");
        }
    }

    // ── Last agent activity ───────────────────────────────
    println!("\nAgent health");
    let effective_dir = resolve_data_dir(cli, data_dir);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);
    let yesterday = epoch_secs_to_date(now_secs.saturating_sub(86400));

    let telemetry_path = {
        let today_p = effective_dir.join(format!("telemetry-{today}.jsonl"));
        let yest_p = effective_dir.join(format!("telemetry-{yesterday}.jsonl"));
        if today_p.exists() {
            Some(today_p)
        } else if yest_p.exists() {
            Some(yest_p)
        } else {
            None
        }
    };

    match telemetry_path {
        None => {
            println!("  ⚠️  No telemetry file found - agent may not be running");
            println!("     Run 'innerwarden status' to check.");
        }
        Some(ref path) => {
            let mtime_secs = std::fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            match mtime_secs {
                None => println!("  ⚠️  Could not read telemetry file mtime"),
                Some(ts) => {
                    let age = now_secs.saturating_sub(ts);
                    if age < 120 {
                        println!("  ✅ Agent is healthy - last write {age}s ago");
                    } else if age < 300 {
                        println!("  ✅ Agent last wrote telemetry {age}s ago");
                    } else {
                        println!("  ⚠️  Agent last wrote telemetry {age}s ago - may be stuck");
                        println!("     Run 'innerwarden watchdog' to run a full health check.");
                    }
                }
            }
        }
    }

    // ── Quick tip ─────────────────────────────────────────
    println!("\nUseful commands");
    println!("  innerwarden watchdog            - run a health check now");
    println!("  innerwarden watchdog --notify   - check and alert via Telegram if unhealthy");
    println!("  innerwarden configure watchdog  - set up or change the cron schedule");

    Ok(())
}

fn maybe_send_watchdog_alert(cli: &Cli, message: &str) {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);

    let token = env_vars
        .get("TELEGRAM_BOT_TOKEN")
        .cloned()
        .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok());
    let chat_id = env_vars
        .get("TELEGRAM_CHAT_ID")
        .cloned()
        .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok());

    if let (Some(tok), Some(cid)) = (token, chat_id) {
        if !tok.is_empty() && !cid.is_empty() {
            let _ = send_telegram_message_md(&tok, &cid, message);
        }
    }
}
