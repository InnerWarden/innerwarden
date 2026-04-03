use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{config_editor, prompt, require_sudo, restart_agent, write_env_key, Cli};

pub(crate) fn cmd_configure_abuseipdb(
    cli: &Cli,
    api_key_arg: Option<&str>,
    auto_block_arg: Option<u8>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    let api_key = if let Some(k) = api_key_arg {
        k.to_string()
    } else {
        println!("InnerWarden - AbuseIPDB setup\n");
        println!("AbuseIPDB checks the reputation of every attacking IP before AI analysis.");
        println!("The reputation score (0–100) is injected into the AI prompt so decisions");
        println!("are more confident. IPs with known bad reputation can be blocked instantly");
        println!("without spending an AI token.\n");
        println!("Free tier: 1,000 lookups/day - enough for most servers.\n");
        println!("  1. Go to https://www.abuseipdb.com/register and create a free account");
        println!("  2. Once logged in, go to https://www.abuseipdb.com/account/api");
        println!("  3. Create a new API key and paste it below\n");
        let k = prompt("API key")?;
        if k.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }
        k
    };

    if api_key.len() < 10 {
        anyhow::bail!("API key looks too short - copy the full key from abuseipdb.com");
    }

    let threshold: u8 = if let Some(t) = auto_block_arg {
        t
    } else if api_key_arg.is_none() {
        println!("\nAuto-block threshold (0–100, 0 = disabled)");
        println!("  IPs with AbuseIPDB confidence score >= threshold are blocked immediately,");
        println!("  without calling AI. Useful during botnets and DDoS.\n");
        println!("  Recommended: 80  (blocks known botnet IPs, rarely a false positive)");
        println!("  Conservative: 0  (AbuseIPDB enriches AI context only, no auto-block)\n");
        let raw = prompt("Auto-block threshold [80]")?;
        if raw.is_empty() {
            80
        } else {
            raw.parse::<u8>().unwrap_or_else(|_| {
                println!("  Invalid value - using 80");
                80
            })
        }
    } else {
        80
    };

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write ABUSEIPDB_API_KEY=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [abuseipdb] enabled=true, auto_block_threshold={threshold} in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    write_env_key(&env_file, "ABUSEIPDB_API_KEY", &api_key)?;
    println!("\n  [ok] API key saved to {}", env_file.display());

    config_editor::write_bool(&cli.agent_config, "abuseipdb", "enabled", true)?;
    config_editor::write_int(
        &cli.agent_config,
        "abuseipdb",
        "auto_block_threshold",
        threshold as i64,
    )?;
    if threshold > 0 {
        println!("  [ok] agent.toml: abuseipdb.enabled = true, auto_block_threshold = {threshold}");
    } else {
        println!("  [ok] agent.toml: abuseipdb.enabled = true (auto-block disabled)");
    }

    restart_agent(cli);
    println!();
    if threshold > 0 {
        println!("AbuseIPDB enabled.");
        println!("  → IPs with score >= {threshold} are blocked instantly (no AI call needed).");
        println!("  → All other IPs get reputation context injected into AI analysis.");
    } else {
        println!("AbuseIPDB enabled. IP reputation will appear in AI analysis.");
        println!("  Tip: set auto_block_threshold = 80 to auto-block known botnet IPs.");
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "abuseipdb".to_string(),
        parameters: serde_json::json!({ "auto_block_threshold": threshold }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nRun 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn cmd_configure_geoip(cli: &Cli) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    if cli.dry_run {
        println!(
            "[dry-run] would set [geoip] enabled=true in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    println!("InnerWarden - GeoIP setup\n");
    println!("GeoIP adds country and ISP context to AI analysis. No API key needed.");
    println!("Uses ip-api.com (free, 45 lookups/min).\n");

    print!("  Checking ip-api.com connectivity... ");
    std::io::stdout().flush()?;
    match ureq::get("http://ip-api.com/json/8.8.8.8?fields=status")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .call()
    {
        Ok(_) => println!("ok"),
        Err(_) => println!("unreachable (will enable anyway - retried at runtime)"),
    }

    config_editor::write_bool(&cli.agent_config, "geoip", "enabled", true)?;
    println!("  [ok] agent.toml: geoip.enabled = true");

    restart_agent(cli);

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "geoip".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("GeoIP enabled. Country and ISP will appear in AI decisions.");
    Ok(())
}

pub(crate) fn cmd_configure_cloudflare(
    cli: &Cli,
    zone_id_arg: Option<&str>,
    api_token_arg: Option<&str>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    let (zone_id, api_token) = match (zone_id_arg, api_token_arg) {
        (Some(z), Some(t)) => (z.to_string(), t.to_string()),
        (zone_id_arg, api_token_arg) => {
            println!("InnerWarden - Cloudflare integration setup\n");
            println!("When InnerWarden blocks an IP, it will also push that block to Cloudflare's");
            println!(
                "edge via IP Access Rules - stopping the attacker before they reach your server.\n"
            );
            println!("You need:");
            println!("  1. Zone ID   - right panel of your domain at dash.cloudflare.com");
            println!("  2. API token - dash.cloudflare.com/profile/api-tokens");
            println!("     Use template 'Edit zone DNS' or custom with Zone > Firewall Services > Edit\n");

            let zid = if let Some(z) = zone_id_arg {
                z.to_string()
            } else {
                let z = prompt("Zone ID")?;
                if z.is_empty() {
                    anyhow::bail!("Zone ID cannot be empty");
                }
                z
            };

            let tok = if let Some(t) = api_token_arg {
                t.to_string()
            } else {
                let t = prompt("API token")?;
                if t.is_empty() {
                    anyhow::bail!("API token cannot be empty");
                }
                t
            };

            (zid, tok)
        }
    };

    if zone_id.len() < 10 {
        anyhow::bail!("Zone ID looks too short - copy it from the Cloudflare dashboard");
    }
    if api_token.len() < 10 {
        anyhow::bail!("API token looks too short - copy the full token from Cloudflare");
    }

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write CLOUDFLARE_API_TOKEN=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [cloudflare] enabled=true, zone_id={zone_id} in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    write_env_key(&env_file, "CLOUDFLARE_API_TOKEN", &api_token)?;
    println!("\n  [ok] API token saved to {}", env_file.display());

    config_editor::write_bool(&cli.agent_config, "cloudflare", "enabled", true)?;
    config_editor::write_str(&cli.agent_config, "cloudflare", "zone_id", &zone_id)?;
    config_editor::write_bool(&cli.agent_config, "cloudflare", "auto_push_blocks", true)?;
    println!("  [ok] agent.toml: cloudflare.enabled = true, zone_id set, auto_push_blocks = true");

    restart_agent(cli);

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "cloudflare".to_string(),
        parameters: serde_json::json!({ "zone_id": zone_id }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Cloudflare integration enabled.");
    println!("  → Every blocked IP will be pushed to Cloudflare edge IP Access Rules.");
    println!("  → Attackers are stopped at the CDN before reaching your server.");
    println!("\nRun 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn cmd_configure_watchdog(cli: &Cli, interval_mins: u64) -> Result<()> {
    if std::env::consts::OS == "macos" {
        println!("On macOS, use a launchd plist instead of cron.");
        println!(
            "Create /Library/LaunchDaemons/com.innerwarden.watchdog.plist with an interval of {}s.",
            interval_mins * 60
        );
        println!("Or run: innerwarden watchdog --notify (manually, or via a scheduled job).");
        return Ok(());
    }

    let bin = which_bin("innerwarden")
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/usr/local/bin/innerwarden".to_string());
    let cron_line = format!("*/{interval_mins} * * * * {bin} watchdog --notify");

    if cli.dry_run {
        println!("[dry-run] would add to crontab:");
        println!("  {cron_line}");
        return Ok(());
    }

    let current = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    if current.contains("innerwarden watchdog") {
        println!("Watchdog cron is already installed:");
        for line in current
            .lines()
            .filter(|l| l.contains("innerwarden watchdog"))
        {
            println!("  {line}");
        }
        println!();
        println!("To update the interval, remove it first with 'crontab -e' and re-run.");
        return Ok(());
    }

    let new_crontab = if current.trim().is_empty() {
        format!("{cron_line}\n")
    } else {
        let trimmed = current.trim_end();
        format!("{trimmed}\n{cron_line}\n")
    };

    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to run crontab - is it installed?")?;
    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        stdin.write_all(new_crontab.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("crontab returned non-zero exit code");
    }

    println!("  [ok] cron entry added");
    println!();
    println!("Watchdog configured - checks every {interval_mins} minute(s).");
    println!("If the agent stops responding, you'll get a Telegram alert.");
    println!();
    println!("Cron entry:");
    println!("  {cron_line}");
    println!();
    println!("To remove:  crontab -e  (delete the innerwarden watchdog line)");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "watchdog".to_string(),
        parameters: serde_json::json!({ "interval_mins": interval_mins }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
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
