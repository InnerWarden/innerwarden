use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{
    append_admin_action, commands, config_editor, count_jsonl_lines, current_operator,
    epoch_secs_to_date, load_env_file, make_opts, require_sudo, resolve_data_dir, restart_agent,
    systemd, today_date_string, AdminActionEntry, CapabilityRegistry, Cli,
};

pub(crate) fn cmd_configure_menu(cli: &Cli) -> Result<()> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);

    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let is_enabled = |section: &str| -> bool {
        agent_doc
            .as_ref()
            .and_then(|doc| doc.get(section))
            .and_then(|s| s.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    };
    let has_env = |key: &str| -> bool {
        env_vars.get(key).is_some_and(|v| !v.is_empty())
            || std::env::var(key).is_ok_and(|v| !v.is_empty())
    };

    let status = |ok: bool| -> &'static str {
        if ok {
            "✅ configured"
        } else {
            "○  not set up"
        }
    };

    let ai_ok = is_enabled("ai");
    let telegram_ok = has_env("TELEGRAM_BOT_TOKEN") && has_env("TELEGRAM_CHAT_ID");
    let slack_ok = has_env("SLACK_WEBHOOK_URL") || {
        agent_doc
            .as_ref()
            .and_then(|doc| doc.get("slack"))
            .and_then(|s| s.get("webhook_url"))
            .and_then(|u| u.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    let webhook_ok = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("webhook"))
        .and_then(|w| w.get("enabled"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    let dashboard_ok = has_env("INNERWARDEN_DASHBOARD_USER");
    let abuseipdb_ok = has_env("ABUSEIPDB_API_KEY") || is_enabled("abuseipdb");
    let geoip_ok = is_enabled("geoip");
    let fail2ban_ok = is_enabled("fail2ban");
    let cloudflare_ok = has_env("CLOUDFLARE_API_TOKEN") || is_enabled("cloudflare");
    let responder_ok = is_enabled("responder");
    let watchdog_ok = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("innerwarden watchdog"))
        .unwrap_or(false);

    println!("InnerWarden - configure\n");
    println!("Choose what to set up:\n");
    println!("   1. AI provider      {}", status(ai_ok));
    println!("   2. Telegram         {}", status(telegram_ok));
    println!("   3. Slack            {}", status(slack_ok));
    println!("   4. Webhook          {}", status(webhook_ok));
    println!("   5. Dashboard        {}", status(dashboard_ok));
    println!("   6. AbuseIPDB        {}", status(abuseipdb_ok));
    println!("   7. GeoIP            {}", status(geoip_ok));
    println!("   8. Fail2ban         {}", status(fail2ban_ok));
    println!("   9. Cloudflare       {}", status(cloudflare_ok));
    println!("  10. Responder        {}", status(responder_ok));
    println!("  11. Watchdog (cron)  {}", status(watchdog_ok));
    println!();
    print!("Enter number (or q to quit): ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    println!();
    match choice {
        "1" => commands::ai::cmd_configure_ai_interactive(cli),
        "2" => commands::notify::cmd_configure_telegram(cli, None, None, false),
        "3" => commands::notify::cmd_configure_slack(cli, None, "high", false),
        "4" => commands::notify::cmd_configure_webhook(cli, None, "high", false),
        "5" => commands::notify::cmd_configure_dashboard(cli, "admin", None),
        "6" => commands::integrations::cmd_configure_abuseipdb(cli, None, None),
        "7" => commands::integrations::cmd_configure_geoip(cli),
        "8" => cmd_configure_fail2ban(cli),
        "9" => commands::integrations::cmd_configure_cloudflare(cli, None, None),
        "10" => commands::responder::cmd_configure_responder(cli, false, false, None),
        "11" => commands::integrations::cmd_configure_watchdog(cli, 10),
        "q" | "Q" | "" => {
            println!(
                "Tip: run 'innerwarden configure <name>' to jump directly to any integration."
            );
            Ok(())
        }
        _ => {
            println!("Invalid choice. Run 'innerwarden configure' again.");
            Ok(())
        }
    }
}

pub(crate) fn cmd_configure_fail2ban(cli: &Cli) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let installed = std::process::Command::new("fail2ban-client")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !installed {
        if std::env::consts::OS == "macos" {
            anyhow::bail!(
                "fail2ban is not available on macOS.\n\
                 This integration only works on Linux."
            );
        }
        anyhow::bail!(
            "fail2ban-client not found. Install it first:\n\
             \n\
             Ubuntu/Debian:  sudo apt install fail2ban\n\
             RHEL/CentOS:    sudo yum install fail2ban\n\
             \n\
             Then run this command again."
        );
    }

    let running = std::process::Command::new("fail2ban-client")
        .arg("ping")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !running {
        println!("  Warning: fail2ban is installed but not running.");
        println!("  Start it with: sudo systemctl start fail2ban");
        println!("  Enabling the integration anyway - it will activate when fail2ban starts.\n");
    }

    if cli.dry_run {
        println!(
            "[dry-run] would set [fail2ban] enabled=true in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    config_editor::write_bool(&cli.agent_config, "fail2ban", "enabled", true)?;
    println!("  [ok] agent.toml: fail2ban.enabled = true");

    restart_agent(cli);
    println!();
    println!("Fail2ban integration enabled.");
    println!("IPs banned by fail2ban will automatically be enforced via your block skill.");
    Ok(())
}

pub(crate) fn cmd_configure_sensitivity(cli: &Cli, level: &str) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let min_severity = match level.to_lowercase().as_str() {
        "quiet" => "critical",
        "normal" => "high",
        "verbose" => "medium",
        _ => {
            println!(
                "Unknown level '{}'. Choose: quiet, normal, or verbose",
                level
            );
            return Ok(());
        }
    };
    config_editor::write_str(&cli.agent_config, "telegram", "min_severity", min_severity)?;
    config_editor::write_str(&cli.agent_config, "webhook", "min_severity", min_severity)?;
    println!("✅ Notification sensitivity: {level}");
    println!("   Telegram + webhook min_severity = \"{min_severity}\"");
    match level.to_lowercase().as_str() {
        "quiet" => println!("   You'll only be notified for Critical events."),
        "normal" => println!("   You'll be notified for High and Critical events."),
        "verbose" => println!("   You'll be notified for Medium, High, and Critical events."),
        _ => {}
    }
    systemd::restart_service("innerwarden-agent", false)?;
    println!("   Agent restarted.");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "sensitivity".to_string(),
        parameters: serde_json::json!({ "level": level }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_configure_2fa(cli: &Cli) -> Result<()> {
    println!();
    println!("  🔐 Two-Factor Authentication Setup");
    println!("  ================================");
    println!();
    println!("  Choose your second factor:");
    println!("  1. TOTP (Google Authenticator, Authy, 1Password)");
    println!("  2. None (disabled, default)");
    println!();
    print!("  Choose [1-2]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    match choice {
        "1" => {
            use rand_core::{OsRng, RngCore};
            let mut secret_bytes = [0u8; 20];
            OsRng.fill_bytes(&mut secret_bytes);
            let secret_b32 = base32_encode_simple(&secret_bytes);

            let uri = format!(
                "otpauth://totp/InnerWarden:admin?secret={}&issuer=InnerWarden&algorithm=SHA1&digits=6&period=30",
                secret_b32
            );

            println!();
            println!("  Scan this URI with your authenticator app:");
            println!();
            println!("  {}", uri);
            println!();
            print!("  Enter the 6-digit code to verify: ");
            std::io::stdout().flush()?;

            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let code = code.trim();

            if verify_totp_code(&secret_bytes, code) {
                let env_file = cli
                    .agent_config
                    .parent()
                    .map(|p| p.join("agent.env"))
                    .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

                append_or_update_env(&env_file, "INNERWARDEN_TOTP_SECRET", &secret_b32)?;

                config_editor::write_str(
                    &cli.agent_config,
                    "security",
                    "two_factor_method",
                    "totp",
                )?;

                println!();
                println!("  ✅ 2FA enabled with TOTP");
                println!("  Secret saved to {}", env_file.display());
                println!();
                println!("  All sensitive actions (allowlist, mode changes) now require a code.");

                if !cli.dry_run {
                    let _ = systemd::restart_service("innerwarden-agent", false);
                    println!("  Agent restarted.");
                }

                Ok(())
            } else {
                println!();
                println!("  ❌ Wrong code. Please try again.");
                println!("  Run: innerwarden configure 2fa");
                Ok(())
            }
        }
        "2" | "" => {
            config_editor::write_str(&cli.agent_config, "security", "two_factor_method", "none")?;
            println!();
            println!("  ✅ 2FA disabled");
            if !cli.dry_run {
                let _ = systemd::restart_service("innerwarden-agent", false);
                println!("  Agent restarted.");
            }
            Ok(())
        }
        _ => {
            println!("  Unknown option. Run: innerwarden configure 2fa");
            Ok(())
        }
    }
}

fn base32_encode_simple(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn verify_totp_code(secret: &[u8], code: &str) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let user_code: u32 = match code.parse() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_step = now / 30;

    for offset in [0i64, -1, 1] {
        let step = (time_step as i64 + offset) as u64;
        if generate_totp_code(secret, step) == user_code {
            return true;
        }
    }
    false
}

fn generate_totp_code(secret: &[u8], time_step: u64) -> u32 {
    let msg = time_step.to_be_bytes();
    let hash = hmac_sha1_simple(secret, &msg);
    let offset = (hash[19] & 0x0f) as usize;
    let code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    code % 1_000_000
}

fn hmac_sha1_simple(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..20].copy_from_slice(&sha1_simple(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha1_simple(&inner_data);

    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    sha1_simple(&outer_data)
}

#[allow(clippy::needless_range_loop)]
fn sha1_simple(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

fn append_or_update_env(env_file: &Path, key: &str, value: &str) -> Result<()> {
    let content = std::fs::read_to_string(env_file).unwrap_or_default();
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with(&format!("{key}=")) {
                found = true;
                format!("{key}=\"{value}\"")
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("{key}=\"{value}\""));
    }

    if let Some(parent) = env_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(env_file, lines.join("\n") + "\n")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(env_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

pub(crate) fn cmd_tune(cli: &Cli, days: u64, yes: bool, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    println!("InnerWarden Tune - analysing last {days} day(s) of data");
    println!("{}", "─".repeat(56));

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let detectors = [
        (
            "ssh_bruteforce",
            "ssh.login_failed",
            "detectors.ssh_bruteforce.threshold",
        ),
        (
            "credential_stuffing",
            "ssh.invalid_user",
            "detectors.credential_stuffing.threshold",
        ),
        (
            "sudo_abuse",
            "sudo.command",
            "detectors.sudo_abuse.threshold",
        ),
        (
            "search_abuse",
            "http.request",
            "detectors.search_abuse.threshold",
        ),
        ("web_scan", "http.error", "detectors.web_scan.threshold"),
        (
            "port_scan",
            "network.connection_blocked",
            "detectors.port_scan.threshold",
        ),
    ];

    let mut event_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut incident_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for i in 0..days {
        let date = epoch_secs_to_date(now_secs.saturating_sub(i * 86400));

        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(kind) = v["kind"].as_str() {
                    *event_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }

        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(id) = v["incident_id"].as_str() {
                    let detector = id.split(':').next().unwrap_or("");
                    if !detector.is_empty() {
                        *incident_counts.entry(detector.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    let sensor_content = std::fs::read_to_string(&cli.sensor_config).unwrap_or_default();
    let sensor_toml: Option<toml_edit::DocumentMut> = sensor_content.parse().ok();

    let current_threshold = |config_path: &str| -> Option<i64> {
        let parts: Vec<&str> = config_path.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        sensor_toml
            .as_ref()
            .and_then(|doc| doc.get(parts[0]))
            .and_then(|t| t.get(parts[1]))
            .and_then(|d| d.get(parts[2]))
            .and_then(|v| v.as_integer())
    };

    struct Suggestion {
        detector: &'static str,
        current: Option<i64>,
        suggested: i64,
        reason: String,
    }

    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut has_data = false;

    for (detector, event_kind, config_path) in &detectors {
        let events = *event_counts.get(*event_kind).unwrap_or(&0);
        let incidents = *incident_counts.get(*detector).unwrap_or(&0);
        let current = current_threshold(config_path);

        if events == 0 {
            continue;
        }
        has_data = true;

        let events_per_day = (events as f64 / days as f64).ceil() as i64;
        let current_val = current.unwrap_or(8);

        let incidents_per_day = incidents as f64 / days as f64;
        let suggested = if incidents_per_day > 10.0 && current_val > 3 {
            (current_val - 1).max(2)
        } else if events_per_day > (current_val * 20) && incidents == 0 {
            (current_val + 2).min(50)
        } else if events_per_day > (current_val * 5) && incidents_per_day < 1.0 {
            (current_val + 1).min(30)
        } else {
            current_val
        };

        if suggested == current_val {
            continue;
        }

        let direction = if suggested > current_val {
            "raise"
        } else {
            "lower"
        };
        let reason = format!(
            "{} events/day, {} incidents in {days} days - {direction} to reduce noise",
            events_per_day, incidents
        );
        suggestions.push(Suggestion {
            detector,
            current,
            suggested,
            reason,
        });
    }

    if !has_data {
        println!("\nNo event data found in {}.", effective_dir.display());
        println!("Run the sensor for a few days first, then re-run tune.");
        return Ok(());
    }

    if suggestions.is_empty() {
        println!("\n✅ All detector thresholds look well-calibrated for this host.");
        println!("   Events/day are within expected range relative to current thresholds.");
        println!("   Re-run after more data accumulates: --days 14");
        return Ok(());
    }

    println!("\nSuggested threshold changes:\n");
    println!(
        "  {:<22}  {:>8}  {:>9}  Reason",
        "Detector", "Current", "Suggested"
    );
    println!("  {}", "─".repeat(72));
    for s in &suggestions {
        let cur_str = s
            .current
            .map(|v| v.to_string())
            .unwrap_or_else(|| "default".to_string());
        println!(
            "  {:<22}  {:>8}  {:>9}  {}",
            s.detector, cur_str, s.suggested, s.reason
        );
    }

    let apply = if yes {
        true
    } else {
        print!(
            "\nApply these changes to {}? [y/N] ",
            cli.sensor_config.display()
        );
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    if !apply {
        println!("No changes made. Re-run with --yes to apply.");
        return Ok(());
    }

    if cli.dry_run {
        println!(
            "[dry-run] Would patch {} with {} change(s)",
            cli.sensor_config.display(),
            suggestions.len()
        );
        return Ok(());
    }

    let mut doc: toml_edit::DocumentMut = sensor_content
        .parse()
        .with_context(|| format!("failed to parse {}", cli.sensor_config.display()))?;

    for s in &suggestions {
        let parts: Vec<&str> = detectors
            .iter()
            .find(|(d, _, _)| *d == s.detector)
            .map(|(_, _, p)| p.split('.').collect())
            .unwrap_or_default();
        if parts.len() == 3 {
            if let Some(section) = doc
                .get_mut(parts[0])
                .and_then(|t| t.as_table_mut())
                .and_then(|t| t.get_mut(parts[1]))
                .and_then(|t| t.as_table_mut())
            {
                section.insert(parts[2], toml_edit::value(s.suggested));
            }
        }
    }

    std::fs::write(&cli.sensor_config, doc.to_string())
        .with_context(|| format!("failed to write {}", cli.sensor_config.display()))?;

    println!(
        "✅ Applied {} change(s) to {}",
        suggestions.len(),
        cli.sensor_config.display()
    );
    println!("Restart the sensor to apply: sudo systemctl restart innerwarden-sensor");

    let tuned: Vec<&str> = suggestions.iter().map(|s| s.detector).collect();
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "tune".to_string(),
        target: "detectors".to_string(),
        parameters: serde_json::json!({ "detectors": tuned, "days": days }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_doctor(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    #[derive(PartialEq)]
    enum Sev {
        Ok,
        Warn,
        Fail,
    }

    struct Check {
        label: String,
        sev: Sev,
        hint: Option<String>,
    }

    impl Check {
        fn ok(label: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Ok,
                hint: None,
            }
        }
        fn warn(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Warn,
                hint: Some(hint.into()),
            }
        }
        fn fail(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Fail,
                hint: Some(hint.into()),
            }
        }
        fn print(&self) {
            let tag = match self.sev {
                Sev::Ok => "[ok]  ",
                Sev::Warn => "[warn]",
                Sev::Fail => "[fail]",
            };
            println!("  {tag} {}", self.label);
            if let Some(h) = &self.hint {
                println!("         → {h}");
            }
        }
        fn is_issue(&self) -> bool {
            self.sev != Sev::Ok
        }
    }

    fn run_section(checks: Vec<Check>, issues: &mut u32) {
        for c in &checks {
            c.print();
            if c.is_issue() {
                *issues += 1;
            }
        }
    }

    println!("InnerWarden Doctor");
    println!("{}", "═".repeat(48));

    let mut total_issues: u32 = 0;

    let is_macos = std::env::consts::OS == "macos";

    // ── System ────────────────────────────────────────────
    println!("\nSystem");
    let mut sys = Vec::new();

    if is_macos {
        // launchctl
        let has_launchctl = std::path::Path::new("/bin/launchctl").exists()
            || std::path::Path::new("/usr/bin/launchctl").exists();
        sys.push(if has_launchctl {
            Check::ok("launchctl found (macOS service manager)")
        } else {
            Check::fail(
                "launchctl not found",
                "unexpected on macOS - check your PATH",
            )
        });

        // innerwarden user
        let user_ok = std::process::Command::new("id")
            .arg("innerwarden")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "run install.sh - it creates the user via dscl",
            )
        });

        // /etc/sudoers.d/ (exists on macOS too)
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::warn(
                "/etc/sudoers.d/ not found",
                "sudo mkdir -p /etc/sudoers.d  (needed for suspend-user-sudo skill)",
            )
        });

        // pfctl (needed for block-ip-pf)
        let has_pfctl = std::path::Path::new("/sbin/pfctl").exists();
        sys.push(if has_pfctl {
            Check::ok("pfctl found (block-ip-pf skill available)")
        } else {
            Check::warn(
                "pfctl not found",
                "pfctl is built-in on macOS - unexpected. block-ip-pf skill will not work.",
            )
        });

        // `log` binary (needed for macos_log collector)
        let has_log_bin = std::path::Path::new("/usr/bin/log").exists();
        sys.push(if has_log_bin {
            Check::ok("`log` binary found (macos_log collector available)")
        } else {
            Check::fail(
                "`log` binary not found at /usr/bin/log",
                "unexpected on macOS - macos_log collector requires Apple Unified Logging",
            )
        });
    } else {
        // systemctl
        let has_systemctl = std::path::Path::new("/usr/bin/systemctl").exists()
            || std::path::Path::new("/bin/systemctl").exists();
        sys.push(if has_systemctl {
            Check::ok("systemctl found")
        } else {
            Check::fail("systemctl not found", "install systemd or check PATH")
        });

        // innerwarden user
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let user_ok = passwd
            .lines()
            .any(|l| l.split(':').next() == Some("innerwarden"));
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "sudo useradd -r -s /sbin/nologin innerwarden",
            )
        });

        // /etc/sudoers.d/
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::fail("/etc/sudoers.d/ not found", "sudo mkdir -p /etc/sudoers.d")
        });
    }

    run_section(sys, &mut total_issues);

    // ── Services ──────────────────────────────────────────
    println!("\nServices");
    let mut svc = Vec::new();
    if is_macos {
        for (label, plist) in &[
            ("innerwarden-sensor", "com.innerwarden.sensor"),
            ("innerwarden-agent", "com.innerwarden.agent"),
        ] {
            let running = std::process::Command::new("launchctl")
                .args(["list", plist])
                .output()
                .map(|o| {
                    o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\"")
                })
                .unwrap_or(false);
            svc.push(if running {
                Check::ok(format!("{label} is running"))
            } else {
                Check::warn(
                    format!("{label} is not running"),
                    format!("sudo launchctl load /Library/LaunchDaemons/{plist}.plist"),
                )
            });
        }
    } else {
        for unit in &["innerwarden-sensor", "innerwarden-agent"] {
            svc.push(if systemd::is_service_active(unit) {
                Check::ok(format!("{unit} is running"))
            } else {
                Check::warn(
                    format!("{unit} is not running"),
                    format!("sudo systemctl start {unit}"),
                )
            });
        }
    }
    run_section(svc, &mut total_issues);

    // ── Configuration ─────────────────────────────────────
    println!("\nConfiguration");
    let mut cfg = Vec::new();

    for (label, path) in &[("Sensor", &cli.sensor_config), ("Agent", &cli.agent_config)] {
        if path.exists() {
            cfg.push(Check::ok(format!(
                "{} config found ({})",
                label,
                path.display()
            )));
            let valid_toml = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .is_some();
            cfg.push(if valid_toml {
                Check::ok(format!("{} config is valid TOML", label))
            } else {
                Check::fail(
                    format!(
                        "{} config has invalid TOML syntax ({})",
                        label,
                        path.display()
                    ),
                    format!("fix syntax in {}", path.display()),
                )
            });
        } else {
            cfg.push(Check::warn(
                format!(
                    "{} config not found ({}) - defaults are in use",
                    label,
                    path.display()
                ),
                "Run 'sudo innerwarden setup' to create your configuration",
            ));
        }
    }

    // AI provider + API key - detect provider from agent config then validate the right key
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Read agent.toml to find configured provider and whether AI is enabled
    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();

    // Helper: resolve a key from env var or agent.env file
    let resolve_key = |env_var: &str| -> Option<String> {
        if let Ok(v) = std::env::var(env_var) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        std::fs::read_to_string(&env_file).ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{env_var}=")))
                .and_then(|l| l.split_once('=').map(|x| x.1))
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        })
    };

    if !ai_enabled {
        cfg.push(Check::warn(
            "AI not configured (ai.enabled = false)",
            "Detection and logging still work without AI.\nTo add AI triage, run one of:\n\n  innerwarden configure ai openai --key sk-...\n  innerwarden configure ai anthropic --key sk-ant-...\n  innerwarden configure ai ollama --model llama3.2   (no key needed)",
        ));
    } else {
        match provider.as_str() {
            "anthropic" => {
                let key = resolve_key("ANTHROPIC_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "ANTHROPIC_API_KEY not set (provider = \"anthropic\")",
                            "Get a key at https://console.anthropic.com/settings/keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai anthropic --key sk-ant-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-ant-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("ANTHROPIC_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "ANTHROPIC_API_KEY is set but format looks wrong (should start with sk-ant-)",
                                "Run:\n  innerwarden configure ai anthropic --key sk-ant-...",
                            )
                        });
                    }
                }
            }
            "ollama" => {
                // Check if ollama is reachable
                let ollama_url = agent_doc
                    .as_ref()
                    .and_then(|doc| doc.get("ai"))
                    .and_then(|ai| ai.get("base_url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("http://localhost:11434")
                    .to_string();
                let ollama_ok = std::process::Command::new("curl")
                    .args(["-sf", "--max-time", "2", &format!("{ollama_url}/api/tags")])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                cfg.push(if ollama_ok {
                    Check::ok(format!("Ollama reachable at {ollama_url}"))
                } else {
                    Check::fail(
                        format!("Ollama not reachable at {ollama_url}"),
                        "Install and start Ollama:\n\n  curl -fsSL https://ollama.ai/install.sh | sh\n  ollama pull llama3.2\n\nThen run: innerwarden configure ai ollama --model llama3.2",
                    )
                });
            }
            _ => {
                // Default: openai (also handles unknown providers gracefully)
                let key = resolve_key("OPENAI_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "OPENAI_API_KEY not set (provider = \"openai\")",
                            "Get a key at https://platform.openai.com/api-keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai openai --key sk-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("OPENAI_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "OPENAI_API_KEY is set but format looks wrong (should start with sk-)",
                                "Run:\n  innerwarden configure ai openai --key sk-...",
                            )
                        });
                    }
                }
            }
        }
    }

    // AbuseIPDB enrichment - only when abuseipdb.enabled = true
    {
        let abuseipdb_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("abuseipdb"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if abuseipdb_enabled {
            let key_in_config = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("abuseipdb"))
                .and_then(|t| t.get("api_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let key_in_env = std::env::var("ABUSEIPDB_API_KEY")
                .ok()
                .filter(|s| !s.is_empty());
            let key_in_file = resolve_key("ABUSEIPDB_API_KEY");
            let resolved_key = key_in_config.or(key_in_env).or(key_in_file);

            cfg.push(match &resolved_key {
                None => Check::fail(
                    "abuseipdb.enabled=true but ABUSEIPDB_API_KEY not set",
                    "1. Register at https://www.abuseipdb.com/register (free)\n\
                     2. Go to https://www.abuseipdb.com/account/api\n\
                     3. Add to agent.toml:\n\
                     \n   [abuseipdb]\n   api_key = \"<your-key>\"\n\
                     \n   Or set env var: ABUSEIPDB_API_KEY=<your-key>",
                ),
                Some(k) if k.len() < 10 => Check::warn(
                    "ABUSEIPDB_API_KEY is set but looks too short",
                    "AbuseIPDB API keys are typically 80 characters.\n\
                     Get a fresh key at https://www.abuseipdb.com/account/api",
                ),
                Some(_) => Check::ok("ABUSEIPDB_API_KEY is set (free tier: 1,000 checks/day)"),
            });
        }
    }

    // Fail2ban integration - only when fail2ban.enabled = true
    {
        let fail2ban_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("fail2ban"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if fail2ban_enabled {
            let fb_bin = std::path::Path::new("/usr/bin/fail2ban-client").exists()
                || std::path::Path::new("/usr/local/bin/fail2ban-client").exists();
            cfg.push(if fb_bin {
                Check::ok("fail2ban-client binary found")
            } else {
                Check::fail(
                    "fail2ban-client not found but fail2ban.enabled=true",
                    "sudo apt-get install fail2ban",
                )
            });

            // Check fail2ban service is running
            let fb_running = if is_macos {
                false // fail2ban is Linux-only
            } else {
                std::process::Command::new("fail2ban-client")
                    .args(["ping"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            };
            cfg.push(if fb_running {
                Check::ok("fail2ban daemon is responding (ping ok)")
            } else if is_macos {
                Check::warn(
                    "fail2ban is Linux-only - integration will not run on macOS",
                    "disable [fail2ban] enabled=false in agent.toml on macOS",
                )
            } else {
                Check::warn(
                    "fail2ban daemon is not responding (fail2ban-client ping failed)",
                    "sudo systemctl start fail2ban",
                )
            });
        }
    }

    run_section(cfg, &mut total_issues);

    // ── Telegram ──────────────────────────────────────────
    // Only check Telegram when enabled = true in agent config.
    {
        let agent_toml: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let telegram_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("telegram"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if telegram_enabled {
            println!("\nTelegram");
            let mut tg = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve bot_token: config → env var → agent.env file
            let token_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("bot_token"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let token_in_env = std::env::var("TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let token_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_BOT_TOKEN="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_token = token_in_config.or(token_in_env).or(token_in_file);

            // Resolve chat_id: config → env var → agent.env file
            let chat_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("chat_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let chat_in_env = std::env::var("TELEGRAM_CHAT_ID")
                .ok()
                .filter(|s| !s.is_empty());
            let chat_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_CHAT_ID="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_chat = chat_in_config.or(chat_in_env).or(chat_in_file);

            // Check bot_token presence
            match &resolved_token {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_BOT_TOKEN not set",
                        format!(
                            "1. Open Telegram and message @BotFather\n\
                             2. Send /newbot and follow the steps\n\
                             3. Copy the token and add to {}:\n\
                             \n   TELEGRAM_BOT_TOKEN=1234567890:AABBccDDeeffGGHH...",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(token) => {
                    // Validate format: <digits>:<35+ alphanumeric chars>
                    let looks_valid = token.contains(':') && {
                        let mut parts = token.splitn(2, ':');
                        let id_part = parts.next().unwrap_or("");
                        let secret_part = parts.next().unwrap_or("");
                        id_part.chars().all(|c| c.is_ascii_digit())
                            && !id_part.is_empty()
                            && secret_part.len() >= 20
                    };
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_BOT_TOKEN is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_BOT_TOKEN is set but format looks wrong",
                            "Token should look like: 1234567890:AABBccDDeeffGGHHiijjKK...\n\
                             Get a fresh token from @BotFather on Telegram",
                        )
                    });
                }
            }

            // Check chat_id presence
            match &resolved_chat {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_CHAT_ID not set",
                        format!(
                            "1. Open Telegram and message @userinfobot\n\
                             2. It will reply with your chat ID (a number, e.g. 123456789)\n\
                             3. For a group/channel the ID starts with -100\n\
                             4. Add to {}:\n\
                             \n   TELEGRAM_CHAT_ID=123456789",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(chat_id) => {
                    // Chat ID should be numeric (possibly negative for groups)
                    let looks_valid = chat_id
                        .trim_start_matches('-')
                        .chars()
                        .all(|c| c.is_ascii_digit())
                        && !chat_id.is_empty();
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_CHAT_ID is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_CHAT_ID is set but format looks wrong",
                            "Chat ID should be a number like 123456789 (personal) or -1001234567890 (group/channel)\n\
                             Message @userinfobot on Telegram to find yours",
                        )
                    });
                }
            }

            // If both token and chat_id are valid, suggest a connectivity smoke-test
            if resolved_token.is_some() && resolved_chat.is_some() {
                tg.push(Check::ok(
                    "Telegram configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(tg, &mut total_issues);
        }

        // Only check Slack when enabled = true in agent config.
        let slack_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("slack"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if slack_enabled {
            println!("\nSlack");
            let mut sl = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve webhook_url: config → env var → agent.env file
            let url_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("slack"))
                .and_then(|t| t.get("webhook_url"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let url_in_env = std::env::var("SLACK_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.is_empty());
            let url_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("SLACK_WEBHOOK_URL="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_url = url_in_config.or(url_in_env).or(url_in_file);

            match &resolved_url {
                None => {
                    sl.push(Check::fail(
                        "SLACK_WEBHOOK_URL not set",
                        format!(
                            "1. In Slack: Apps → Incoming Webhooks → Add to Slack\n\
                             2. Choose a channel and copy the Webhook URL\n\
                             3. Add to {}:\n\
                             \n   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(url) => {
                    let looks_valid =
                        url.starts_with("https://hooks.slack.com/services/") && url.len() > 50;
                    sl.push(if looks_valid {
                        Check::ok("SLACK_WEBHOOK_URL is set and format looks correct")
                    } else {
                        Check::warn(
                            "SLACK_WEBHOOK_URL is set but format looks wrong",
                            "URL should start with https://hooks.slack.com/services/T.../B.../...\n\
                             Get a fresh webhook URL from your Slack workspace settings",
                        )
                    });
                }
            }

            if resolved_url.is_some() {
                sl.push(Check::ok(
                    "Slack configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(sl, &mut total_issues);
        }
    }

    // ── Webhook ────────────────────────────────────────────
    {
        let webhook_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if webhook_enabled {
            println!("\nWebhook");
            let mut wh: Vec<Check> = vec![];

            let url_val = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("webhook"))
                .and_then(|t| t.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if url_val.is_empty() {
                wh.push(Check::fail(
                    "webhook.url is not set",
                    "Run: innerwarden configure webhook",
                ));
            } else if !url_val.starts_with("http://") && !url_val.starts_with("https://") {
                wh.push(Check::fail(
                    "webhook.url does not look like a valid URL",
                    "Run: innerwarden configure webhook --url <correct-url>",
                ));
            } else {
                wh.push(Check::ok(format!("webhook.url = {url_val}").as_str()));
            }

            run_section(wh, &mut total_issues);
        }
    }

    // ── Dashboard ──────────────────────────────────────────
    {
        let dashboard_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("dashboard"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Always check if credentials are set (dashboard always available when agent runs)
        println!("\nDashboard");
        let mut db: Vec<Check> = vec![];

        let env_path = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
        let env_content = std::fs::read_to_string(&env_path).unwrap_or_default();

        let has_user = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_USER="))
            || std::env::var("INNERWARDEN_DASHBOARD_USER").is_ok();

        let has_hash = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_PASSWORD_HASH="))
            || std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").is_ok();

        // Check if --dashboard flag is in the service ExecStart
        let service_content =
            std::fs::read_to_string("/etc/systemd/system/innerwarden-agent.service")
                .unwrap_or_default();
        let dashboard_flag_in_service = service_content.contains("--dashboard");

        if dashboard_flag_in_service {
            db.push(Check::ok("--dashboard flag present in service ExecStart"));
        } else {
            db.push(Check::warn(
                "--dashboard flag is missing from innerwarden-agent.service ExecStart",
                "Run: innerwarden configure dashboard  (it will add the flag automatically)",
            ));
        }

        if has_user && has_hash {
            db.push(Check::ok(
                "Dashboard login is configured (credentials required)",
            ));
        } else {
            db.push(Check::ok(
                "Dashboard credentials: none set (open access when agent is running)",
            ));
            db.push(Check::ok(
                "To add a password: innerwarden configure dashboard",
            ));
        }

        // Check if the dashboard is actually reachable
        let dashboard_up = ureq::get("http://127.0.0.1:8787/api/status")
            .config()
            .timeout_global(Some(std::time::Duration::from_secs(2)))
            .build()
            .call()
            .is_ok();
        if dashboard_up {
            db.push(Check::ok(
                "Dashboard is reachable at http://YOUR_SERVER_IP:8787",
            ));
        } else if dashboard_flag_in_service {
            db.push(Check::warn(
                "Dashboard port 8787 is not responding",
                "Start the agent:  sudo systemctl start innerwarden-agent",
            ));
        }

        let _ = dashboard_enabled;
        run_section(db, &mut total_issues);
    }

    // ── GeoIP ──────────────────────────────────────────────
    {
        let geoip_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("geoip"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if geoip_enabled {
            println!("\nGeoIP");
            let mut geo: Vec<Check> = vec![];

            // Quick connectivity check
            let reachable = ureq::get("http://ip-api.com/json/8.8.8.8?fields=status")
                .config()
                .timeout_global(Some(std::time::Duration::from_secs(3)))
                .build()
                .call()
                .is_ok();

            if reachable {
                geo.push(Check::ok("ip-api.com is reachable"));
            } else {
                geo.push(Check::warn(
                    "ip-api.com is not reachable from this host",
                    "GeoIP lookups will fail silently. Check outbound HTTP access.",
                ));
            }

            run_section(geo, &mut total_issues);
        }
    }

    // ── Capabilities ──────────────────────────────────────
    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    let mut any_enabled = false;

    for cap in registry.all() {
        if !cap.is_enabled(&opts) {
            continue;
        }
        any_enabled = true;

        // Map capability → expected sudoers drop-in name
        let drop_in = match cap.id() {
            "block-ip" => Some("innerwarden-block-ip"),
            "sudo-protection" => Some("innerwarden-sudo-protection"),
            "search-protection" => Some("innerwarden-search-protection"),
            _ => None,
        };

        if let Some(name) = drop_in {
            let path = std::path::Path::new("/etc/sudoers.d").join(name);
            if path.exists() {
                println!("  [ok]   {} (enabled): sudoers drop-in present", cap.id());
            } else {
                println!(
                    "  [warn] {} (enabled): sudoers drop-in missing (/etc/sudoers.d/{name})",
                    cap.id()
                );
                println!("         → innerwarden enable {}", cap.id());
                total_issues += 1;
            }
        } else {
            println!("  [ok]   {} (enabled)", cap.id());
        }
    }

    if !any_enabled {
        println!("  (no capabilities enabled - run 'innerwarden list' to see options)");
    }

    // ── Integrations ──────────────────────────────────────
    // Only show this section when at least one integration collector is enabled.
    {
        let sensor_doc: Option<toml_edit::DocumentMut> = cli
            .sensor_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.sensor_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let collector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let collector_str = |name: &str, key: &str, default: &str| -> String {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };

        let detector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("detectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let falco_enabled = collector_enabled("falco_log");
        let suricata_enabled = collector_enabled("suricata_eve");
        let osquery_enabled = collector_enabled("osquery_log");
        let nginx_error_enabled = collector_enabled("nginx_error");
        let any_integration =
            falco_enabled || suricata_enabled || osquery_enabled || nginx_error_enabled;

        if any_integration {
            println!("\nIntegrations");

            // ── Falco ──────────────────────────────────────
            if falco_enabled {
                println!("  Falco");
                let mut falco = Vec::new();

                let falco_binary = std::path::Path::new("/usr/bin/falco").exists()
                    || std::path::Path::new("/usr/local/bin/falco").exists();
                falco.push(if falco_binary {
                    Check::ok("Falco binary found")
                } else {
                    Check::fail(
                        "Falco binary not found (/usr/bin/falco or /usr/local/bin/falco)",
                        "sudo apt-get install falco",
                    )
                });

                let falco_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.falco"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("falco")
                        || systemd::is_service_active("falco-modern-bpf")
                };
                let falco_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.falco.plist"
                } else {
                    "sudo systemctl start falco"
                };
                falco.push(if falco_active {
                    Check::ok("Falco service is running")
                } else {
                    Check::warn("Falco service is not running", falco_start_hint)
                });

                let falco_log = collector_str("falco_log", "path", "/var/log/falco/falco.log");
                let log_ok = std::path::Path::new(&falco_log).exists()
                    && std::fs::metadata(&falco_log)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false);
                let falco_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.falco"
                } else {
                    "sudo mkdir -p /var/log/falco && sudo systemctl restart falco"
                };
                let falco_json_hint = if is_macos {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo launchctl kickstart -k system/com.falco"
                } else {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo systemctl restart falco"
                };
                falco.push(if log_ok {
                    Check::ok(format!("Falco log file exists ({})", falco_log))
                } else {
                    Check::fail(
                        format!("Falco log file not found or not readable ({})", falco_log),
                        falco_restart_hint,
                    )
                });

                let falco_yaml =
                    std::fs::read_to_string("/etc/falco/falco.yaml").unwrap_or_default();
                let json_output_ok = falco_yaml.contains("json_output: true");
                falco.push(if json_output_ok {
                    Check::ok("Falco json_output is enabled")
                } else {
                    Check::warn(
                        "Falco json_output not enabled - events will not be parseable",
                        falco_json_hint,
                    )
                });

                run_section(falco, &mut total_issues);
            }

            // ── Suricata ───────────────────────────────────
            if suricata_enabled {
                println!("  Suricata (optional)");
                println!(
                    "    \x1b[2mNote: InnerWarden captures DNS, HTTP, and TLS natively.\x1b[0m"
                );
                println!(
                    "    \x1b[2mSuricata is optional — useful for deep packet inspection\x1b[0m"
                );
                println!("    \x1b[2mand CVE signatures in compliance-driven environments.\x1b[0m");
                let mut suri = Vec::new();

                let suri_binary = std::path::Path::new("/usr/bin/suricata").exists();
                suri.push(if suri_binary {
                    Check::ok("Suricata binary found")
                } else {
                    Check::fail(
                        "Suricata binary not found (/usr/bin/suricata)",
                        "sudo apt-get install suricata",
                    )
                });

                let suri_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.suricata"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("suricata")
                };
                let suri_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.suricata.plist"
                } else {
                    "sudo systemctl start suricata"
                };
                let suri_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.suricata  # creates eve.json on first run"
                } else {
                    "sudo systemctl restart suricata  # creates eve.json on first run"
                };
                suri.push(if suri_active {
                    Check::ok("Suricata service is running")
                } else {
                    Check::warn("Suricata service is not running", suri_start_hint)
                });

                let eve_log = collector_str("suricata_eve", "path", "/var/log/suricata/eve.json");
                let eve_ok = std::path::Path::new(&eve_log).exists();
                suri.push(if eve_ok {
                    Check::ok(format!("Suricata eve.json exists ({})", eve_log))
                } else {
                    Check::fail(
                        format!("Suricata eve.json not found ({})", eve_log),
                        suri_restart_hint,
                    )
                });

                let rules_present = std::path::Path::new("/var/lib/suricata/rules/suricata.rules")
                    .exists()
                    || std::fs::read_dir("/etc/suricata/rules/")
                        .map(|mut d| {
                            d.any(|e| {
                                e.map(|e| {
                                    e.path().extension().and_then(|x| x.to_str()) == Some("rules")
                                })
                                .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                suri.push(if rules_present {
                    Check::ok("Suricata ET rules present")
                } else {
                    Check::warn(
                        "Suricata ET rules not found",
                        if is_macos {
                            "sudo suricata-update && sudo launchctl kickstart -k system/com.suricata"
                        } else {
                            "sudo suricata-update && sudo systemctl restart suricata"
                        },
                    )
                });

                run_section(suri, &mut total_issues);
            }

            // ── osquery ────────────────────────────────────
            if osquery_enabled {
                println!("  osquery");
                let mut osq = Vec::new();

                let osq_binary = std::path::Path::new("/usr/bin/osqueryd").exists()
                    || std::path::Path::new("/usr/local/bin/osqueryd").exists();
                osq.push(if osq_binary {
                    Check::ok("osqueryd binary found")
                } else {
                    Check::fail(
                        "osqueryd binary not found (/usr/bin/osqueryd or /usr/local/bin/osqueryd)",
                        "sudo apt-get install osquery  # see modules/osquery-integration/docs/README.md",
                    )
                });

                let osq_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.facebook.osqueryd"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("osqueryd")
                };
                let osq_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist"
                } else {
                    "sudo systemctl start osqueryd"
                };
                osq.push(if osq_active {
                    Check::ok("osqueryd service is running")
                } else {
                    Check::warn("osqueryd service is not running", osq_start_hint)
                });

                let results_log = collector_str(
                    "osquery_log",
                    "path",
                    "/var/log/osquery/osqueryd.results.log",
                );
                let results_ok = std::path::Path::new(&results_log).exists();
                osq.push(if results_ok {
                    Check::ok(format!("osquery results log exists ({})", results_log))
                } else {
                    Check::warn(
                        format!("osquery results log not found yet ({})", results_log),
                        "ensure log_result_events=true in /etc/osquery/osquery.conf, then wait 60s for first query",
                    )
                });

                let osq_conf =
                    std::fs::read_to_string("/etc/osquery/osquery.conf").unwrap_or_default();
                let has_schedule = osq_conf.contains("\"schedule\"");
                osq.push(if has_schedule {
                    Check::ok("osquery config contains scheduled queries")
                } else {
                    Check::warn(
                        "osquery config does not contain scheduled queries",
                        "copy the recommended queries from modules/osquery-integration/config/sensor.example.toml into /etc/osquery/osquery.conf",
                    )
                });

                run_section(osq, &mut total_issues);
            }

            // ── nginx-error-monitor ────────────────────────
            if nginx_error_enabled {
                println!("  nginx-error-monitor");
                let mut nginx_err = Vec::new();

                // nginx binary
                let nginx_bin = std::path::Path::new("/usr/sbin/nginx").exists()
                    || std::path::Path::new("/usr/bin/nginx").exists()
                    || std::path::Path::new("/usr/local/sbin/nginx").exists();
                nginx_err.push(if nginx_bin {
                    Check::ok("nginx binary found")
                } else {
                    Check::fail("nginx binary not found", "sudo apt-get install nginx")
                });

                // error log path
                let err_log = collector_str("nginx_error", "path", "/var/log/nginx/error.log");
                let log_exists = std::path::Path::new(&err_log).exists();
                nginx_err.push(if log_exists {
                    Check::ok(format!("nginx error log exists ({})", err_log))
                } else {
                    Check::fail(
                        format!("nginx error log not found ({})", err_log),
                        "sudo systemctl start nginx  # log is created on first request or error",
                    )
                });

                // readability - can the current user read it?
                if log_exists {
                    let readable = std::fs::File::open(&err_log).is_ok();
                    nginx_err.push(if readable {
                        Check::ok(format!("nginx error log is readable ({})", err_log))
                    } else {
                        Check::warn(
                            format!("nginx error log is not readable by innerwarden user ({})", err_log),
                            "sudo usermod -aG adm innerwarden  # or: sudo chmod 640 /var/log/nginx/error.log",
                        )
                    });
                }

                // web_scan detector enabled?
                let web_scan_on = detector_enabled("web_scan");
                nginx_err.push(if web_scan_on {
                    Check::ok("web_scan detector is enabled")
                } else {
                    Check::warn(
                        "web_scan detector is disabled - http.error events are collected but not triaged",
                        "Add to sensor config:\n\n  [detectors.web_scan]\n  enabled = true\n  threshold = 15\n  window_seconds = 60",
                    )
                });

                run_section(nginx_err, &mut total_issues);
            }
        }
    }

    // ── Agent liveness ────────────────────────────────────
    {
        println!("\nAgent health");
        let mut liveness: Vec<Check> = vec![];

        let data_dir_opt: Option<std::path::PathBuf> = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("output"))
            .and_then(|o| o.get("data_dir"))
            .and_then(|d| d.as_str())
            .map(std::path::PathBuf::from)
            .or_else(|| Some(std::path::PathBuf::from("/var/lib/innerwarden")));

        if let Some(ref dir) = data_dir_opt {
            let today = chrono::Local::now().format("%Y-%m-%d").to_string();
            let telemetry_path = dir.join(format!("telemetry-{today}.jsonl"));
            if telemetry_path.exists() {
                if let Ok(meta) = std::fs::metadata(&telemetry_path) {
                    if let Ok(modified) = meta.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .map(|d| d.as_secs())
                            .unwrap_or(u64::MAX);
                        if age > 300 {
                            liveness.push(Check::warn(
                                format!("last telemetry write was {}s ago", age),
                                "agent may be stuck - check: journalctl -u innerwarden-agent -n 50",
                            ));
                        } else {
                            liveness
                                .push(Check::ok(format!("agent active - last write {}s ago", age)));
                        }
                    }
                }
            } else {
                liveness.push(Check::warn(
                    "no telemetry file for today",
                    "agent has not written telemetry yet - is it running? innerwarden status",
                ));
            }
        }
        run_section(liveness, &mut total_issues);
    }

    // ── Summary ───────────────────────────────────────────
    println!();
    println!("{}", "─".repeat(48));
    if total_issues == 0 {
        println!("All checks passed - system looks healthy.");
    } else {
        println!("{total_issues} issue(s) found - review hints above.");
        // If configs are missing, offer a one-command path forward
        let configs_missing = !cli.sensor_config.exists() || !cli.agent_config.exists();
        if configs_missing {
            println!();
            println!("Getting started:  sudo innerwarden setup");
            println!("  Walks you through AI, Telegram, and essential modules.");
        }
        std::process::exit(1);
    }
    Ok(())
}

pub(crate) fn cmd_pipeline_test(cli: &Cli, wait_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = today_date_string();
    let incidents_path = effective_dir.join(format!("incidents-{today}.jsonl"));
    let decisions_path = effective_dir.join(format!("decisions-{today}.jsonl"));

    // Count existing decisions to detect new ones
    let baseline = count_jsonl_lines(&decisions_path);

    // Use RFC 5737 documentation IP - safe, never routable
    let test_ip = "198.51.100.123";
    let now_iso = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days_since_epoch = secs / 86400;
        // Compute date from days
        let (y, mo, d) = {
            let mut y = 1970i64;
            let mut rem = days_since_epoch as i64;
            loop {
                let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                    366
                } else {
                    365
                };
                if rem < ydays {
                    break;
                }
                rem -= ydays;
                y += 1;
            }
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let mdays = [
                31,
                if leap { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            let mut mo = 0usize;
            while mo < 12 && rem >= mdays[mo] {
                rem -= mdays[mo];
                mo += 1;
            }
            (y, mo + 1, rem + 1)
        };
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
    };
    let marker = format!("innerwarden-test-{}", std::process::id());

    let hostname = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let incident = serde_json::json!({
        "ts": now_iso,
        "host": hostname,
        "incident_id": format!("ssh_bruteforce:{test_ip}:{marker}"),
        "severity": "high",
        "title": format!("Possible SSH brute force from {test_ip}"),
        "summary": format!("12 failed SSH login attempts from {test_ip} in the last 30 seconds (pipeline test)"),
        "evidence": [{
            "count": 12,
            "ip": test_ip,
            "kind": "ssh.login_failed",
            "window_seconds": 30
        }],
        "recommended_checks": [
            format!("This is a pipeline test using RFC 5737 documentation IP {test_ip}"),
            "No real threat - safe to ignore"
        ],
        "tags": ["auth", "ssh", "bruteforce", "pipeline-test"],
        "entities": [{
            "type": "ip",
            "value": test_ip
        }]
    });

    println!("InnerWarden Pipeline Test");
    println!("{}\n", "─".repeat(50));

    // Step 1: Write test incident
    println!("  [1/4] Writing test incident...");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&incidents_path)?;
    writeln!(file, "{}", incident)?;
    println!("        Title: Possible SSH brute force from {test_ip}");
    println!("        Severity: HIGH");
    println!("        SSH brute-force from {test_ip} (documentation IP, safe)");
    println!("        Written to {}\n", incidents_path.display());

    // Step 2: Check agent is running
    println!("  [2/4] Checking agent status...");
    let agent_running = std::process::Command::new("pgrep")
        .args(["-f", "innerwarden-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !agent_running {
        println!("        Agent process not detected.");
        println!("        The test incident was written but nobody is reading it.");
        println!("        Start the agent: sudo systemctl start innerwarden-agent\n");
        println!("  Result: PARTIAL - incident written, agent not running");
        return Ok(());
    }
    println!("        Agent is running.\n");

    // Step 3: Wait for agent to process
    println!("  [3/4] Waiting up to {wait_secs}s for agent to process...");
    let start = std::time::Instant::now();
    let mut found = false;
    while start.elapsed().as_secs() < wait_secs {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let current = count_jsonl_lines(&decisions_path);
        if current > baseline {
            // Check if the new decision references our test
            if let Ok(content) = std::fs::read_to_string(&decisions_path) {
                if content.contains(&marker) || content.contains(test_ip) {
                    found = true;
                    break;
                }
            }
            // Even if marker not found, new decisions appeared
            if current > baseline {
                found = true;
                break;
            }
        }
        print!(".");
        std::io::stdout().flush().ok();
    }
    println!();

    // Step 4: Report results
    println!("\n  [4/4] Results:");
    if found {
        println!("        Pipeline is working.");
        println!("        Incident was detected, processed, and a decision was logged.");
        // Show the latest decision
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            if let Some(last_line) = content.lines().rev().find(|l| l.contains(test_ip)) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(last_line) {
                    let action = val
                        .get("action_type")
                        .and_then(|a| a.as_str())
                        .or_else(|| val.get("action").and_then(|a| a.as_str()))
                        .unwrap_or("?");
                    let conf = val
                        .get("confidence")
                        .and_then(|c| c.as_f64())
                        .unwrap_or(0.0);
                    let dry = val.get("dry_run").and_then(|d| d.as_bool()).unwrap_or(true);
                    let reason = val.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                    println!("\n        Action: {action}");
                    println!("        Confidence: {:.0}%", conf * 100.0);
                    println!("        Dry-run: {dry}");
                    if !reason.is_empty() {
                        println!("        Reason: {reason}");
                    }
                    if dry {
                        println!("        (safe - no real firewall changes)");
                    }
                }
            }
        }
        println!("\n  Result: PASS");
    } else {
        println!("        No decision appeared within {wait_secs} seconds.");
        println!("        Possible causes:");
        println!("          - Agent is running but AI provider is not configured");
        println!("          - Agent hasn't reached this incident in its read cycle");
        println!("          - Try again with --wait 30");
        println!("\n  Result: TIMEOUT - check `innerwarden doctor` for diagnostics");
    }

    Ok(())
}

pub(crate) fn cmd_backup(cli: &Cli, output: Option<&Path>) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    // When no --output is given, create a secure temp file with an unpredictable name
    let tmp_file = if output.is_none() {
        Some(
            tempfile::Builder::new()
                .prefix("innerwarden-backup-")
                .suffix(".tar.gz")
                .tempfile()
                .context("failed to create temp file for backup")?,
        )
    } else {
        None
    };
    let default_path: PathBuf;
    let output_path = if let Some(ref tmp) = tmp_file {
        default_path = tmp.path().to_path_buf();
        &default_path
    } else {
        output.unwrap()
    };

    let files = [
        "etc/innerwarden/config.toml",
        "etc/innerwarden/agent.toml",
        "etc/innerwarden/agent.env",
    ];

    println!("InnerWarden - backup\n");
    println!("Backing up configuration files:");
    for f in &files {
        let abs = Path::new("/").join(f);
        let exists = abs.exists();
        println!("  {} /{}", if exists { "●" } else { "○ (missing)" }, f);
    }
    println!();
    println!("Output: {}", output_path.display());

    if cli.dry_run {
        println!("\n  [dry-run] would create archive - skipping.");
        return Ok(());
    }

    let status = std::process::Command::new("tar")
        .arg("czf")
        .arg(output_path)
        .arg("-C")
        .arg("/")
        .args(files)
        .status()
        .context("failed to run tar")?;

    if status.success() {
        // Keep the temp file so the backup persists on disk
        if let Some(tmp) = tmp_file {
            let _ = tmp.keep();
        }
        println!("\n  [ok] backup saved to {}", output_path.display());
    } else {
        anyhow::bail!(
            "tar exited with status {} - some files may be missing from /etc/innerwarden/",
            status
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden completions
// ---------------------------------------------------------------------------

pub(crate) fn cmd_completions(shell: &str) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::Shell;

    let mut cmd = Cli::command();
    let shell_enum = match shell.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        other => {
            anyhow::bail!("unsupported shell '{}' - supported: bash, zsh, fish", other)
        }
    };

    clap_complete::generate(shell_enum, &mut cmd, "innerwarden", &mut std::io::stdout());
    Ok(())
}
