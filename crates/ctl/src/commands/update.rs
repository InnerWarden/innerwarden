use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{load_env_file, systemd, Cli};

pub(crate) fn cmd_upgrade(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
) -> Result<()> {
    use crate::upgrade::*;

    println!("Checking for updates...");

    let release =
        fetch_latest_release().context("could not reach GitHub - check network and try again")?;

    let current = CURRENT_VERSION;
    let latest = strip_v(&release.tag_name);

    let date_suffix = release
        .release_date()
        .map(|d| format!("  [{d}]"))
        .unwrap_or_default();

    println!("  Current version:  {current}");

    if !is_newer(current, &release.tag_name) {
        println!("  Latest release:   {latest}{date_suffix} - already up to date.");
        return Ok(());
    }

    println!(
        "  Latest release:   {latest}{date_suffix}  ({})",
        release.html_url
    );

    // --notify: send Telegram alert about available update (for cron use)
    if notify {
        let env_file = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/agent.env"));
        let env_vars = load_env_file(&env_file);
        let bot_token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok())
            .unwrap_or_default();
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok())
            .unwrap_or_default();
        if !bot_token.is_empty() && !chat_id.is_empty() {
            // Extract changelog from release body
            let changelog = release
                .body
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(500)
                .collect::<String>();
            let text = format!(
                "🆕 <b>Inner Warden {latest} available</b>\n\n\
                 Current: {current}\n\
                 New: {latest}{date_suffix}\n\n\
                 {changelog}\n\n\
                 Upgrade: <code>innerwarden upgrade --yes</code>"
            );
            let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
            let _ = ureq::post(&url).send_json(serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }));
            println!("  Telegram notification sent.");
        } else {
            println!("  --notify: Telegram not configured, skipping notification.");
        }
    }

    if check_only {
        println!("\nRun 'innerwarden upgrade' to install.");
        return Ok(());
    }

    // Auto-backup configs before upgrade
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or(Path::new("/etc/innerwarden"));
    if config_dir.exists() {
        match tempfile::Builder::new()
            .prefix("innerwarden-backup-pre-upgrade-")
            .suffix(".tar.gz")
            .tempfile()
        {
            Ok(tmp) => {
                let backup_path = tmp.path().to_string_lossy().to_string();
                print!("  Backing up configs to {backup_path}... ");
                match std::process::Command::new("tar")
                    .args(["czf", &backup_path, "-C", "/"])
                    .arg(config_dir.strip_prefix("/").unwrap_or(config_dir))
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        // Keep the backup file (prevent cleanup on drop)
                        let _ = tmp.keep();
                        println!("done");
                    }
                    _ => println!("skipped (tar failed, continuing anyway)"),
                }
            }
            Err(_) => {
                println!("  Skipping backup (could not create temp file)");
            }
        }
    }

    // Detect architecture
    let arch = detect_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported CPU architecture '{}' - build from source for your platform",
            std::env::consts::ARCH
        )
    })?;

    // Build download plan
    let plan = build_plan(&release, arch);

    if plan.is_empty() {
        anyhow::bail!(
            "no assets found for linux-{arch} in release {} - \
             check {} for manual download",
            release.tag_name,
            release.html_url
        );
    }

    println!("\nAssets available for linux-{arch}:");
    for dp in &plan {
        let sha_status = if dp.sha256_asset.is_some() {
            "sha256 ✓"
        } else {
            "no sha256"
        };
        let sig_status = if dp.sig_asset.is_some() {
            "  sig ✓"
        } else {
            ""
        };
        println!(
            "  {:<28} {}  ({}{})",
            dp.target.binary,
            fmt_bytes(dp.asset.size),
            sha_status,
            sig_status
        );
    }

    let dest_paths: Vec<_> = plan
        .iter()
        .flat_map(|dp| install_paths(dp.target, install_dir))
        .collect();

    println!("\nWill install to {}:", install_dir.display());
    for p in &dest_paths {
        println!("  {}", p.display());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    for dp in &plan {
        let binary = dp.target.binary;
        print!("  Downloading {binary}... ");
        std::io::stdout().flush()?;

        let tmp_path = tmp_dir.path().join(binary);
        let bytes = download(&dp.asset.browser_download_url, &tmp_path)?;

        // Verify SHA-256 if sidecar is present
        if let Some(sha_asset) = dp.sha256_asset {
            let expected = fetch_expected_hash(&sha_asset.browser_download_url)?;
            let actual = sha256_file(&tmp_path)?;
            if actual != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for {binary}:\n  expected {expected}\n  got      {actual}"
                );
            }
            print!("{}  sha256 ok", fmt_bytes(bytes));
        } else {
            print!("{}  (no sha256 sidecar)", fmt_bytes(bytes));
        }

        // Verify Ed25519 signature if .sig sidecar is present
        if let Some(sig_asset) = dp.sig_asset {
            let sig_b64 = fetch_signature(&sig_asset.browser_download_url)?;
            let binary_bytes =
                std::fs::read(&tmp_path).context("cannot read downloaded binary for sig check")?;
            verify_signature(&binary_bytes, &sig_b64)?;
            println!("  sig ok");
        } else {
            println!();
            println!("  [warn] unsigned release - signature verification skipped for {binary}");
        }

        // Install to all target names
        for dest in install_paths(dp.target, install_dir) {
            install_binary(&tmp_path, &dest, false)?;
            println!("  [done] {} → {}", binary, dest.display());
        }
    }

    // Fix permissions on existing config files - files written before v0.1.9 may
    // be root:root 600, which prevents innerwarden-agent (User=innerwarden) from
    // reading them. chmod 640 + chgrp innerwarden is fail-silent.
    fix_config_dir_permissions(
        cli.agent_config
            .parent()
            .unwrap_or(std::path::Path::new("/etc/innerwarden")),
    );

    // Restart running services; also start the agent if it has a unit file but is stopped
    println!();
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let unit_path = format!("/etc/systemd/system/{unit}.service");
        let unit_exists = std::path::Path::new(&unit_path).exists();
        if systemd::is_service_active(unit) {
            systemd::restart_service(unit, false)?;
            println!("  [done] Restarted {unit}");
        } else if unit_exists {
            // Unit is installed but stopped - try to start it
            match systemd::restart_service(unit, false) {
                Ok(()) => println!("  [done] Started {unit}"),
                Err(e) => {
                    println!("  [warn] Could not start {unit}: {e}");
                    println!("         Check logs: journalctl -u {unit} -n 30");
                }
            }
        }
    }

    let date_display = release
        .release_date()
        .map(|d| format!(" ({d})"))
        .unwrap_or_default();

    println!(
        "\nInnerWarden upgraded to {}{} successfully.",
        release.tag_name, date_display
    );

    // Show what's new in this release
    if let Some(preview) = release.changelog_preview() {
        println!("\nWhat's new in {}:", release.tag_name);
        println!("─────────────────────────────────────────────────");
        for line in preview.lines() {
            println!("  {line}");
        }
        println!("─────────────────────────────────────────────────");
        println!("  Full release notes: {}", release.html_url);
    } else {
        println!("  Release notes: {}", release.html_url);
    }

    Ok(())
}

/// Fix permissions on all config files in the innerwarden config directory.
/// chmod 640 + chgrp innerwarden so the service user (User=innerwarden) can read them.
/// Fail-silent - best-effort in environments where the group doesn't exist.
fn fix_config_dir_permissions(config_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640));
            let _ = std::process::Command::new("chgrp")
                .arg("innerwarden")
                .arg(&path)
                .output();
        }
    }
}
