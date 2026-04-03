use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{commands, config_editor, load_env_file, require_sudo, restart_agent, systemd, Cli};

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
