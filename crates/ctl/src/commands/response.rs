use std::path::Path;

use anyhow::Result;

use crate::{
    append_admin_action, current_operator, looks_like_ip, resolve_data_dir, write_manual_decision,
    AdminActionEntry, Cli,
};

pub(crate) fn cmd_block(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    // Basic IP validation
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    // Read configured block backend from agent.toml
    let backend = std::fs::read_to_string(&cli.agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string());

    println!("Blocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would run block command for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    // Execute the block
    let blocked = match backend.as_str() {
        "iptables" => std::process::Command::new("sudo")
            .args(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "nftables" => std::process::Command::new("sudo")
            .args([
                "nft",
                "add",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                &format!("{{ {ip} }}"),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "pf" => std::process::Command::new("sudo")
            .args(["pfctl", "-t", "innerwarden-blocked", "-T", "add", ip])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => {
            // ufw (default)
            std::process::Command::new("sudo")
                .args(["ufw", "deny", "from", ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };

    if !blocked {
        anyhow::bail!("block command failed - check sudo permissions (run: innerwarden doctor)");
    }
    println!("  [ok] {ip} blocked via {backend}");

    // Write audit trail
    write_manual_decision(&effective_dir, ip, "block_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now blocked. To reverse: innerwarden unblock {ip} --reason \"...\"");
    Ok(())
}

pub(crate) fn cmd_unblock(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    let backend = std::fs::read_to_string(&cli.agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string());

    println!("Unblocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would remove block for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    let unblocked = match backend.as_str() {
        "iptables" => std::process::Command::new("sudo")
            .args(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "nftables" => std::process::Command::new("sudo")
            .args([
                "nft",
                "delete",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                &format!("{{ {ip} }}"),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "pf" => std::process::Command::new("sudo")
            .args(["pfctl", "-t", "innerwarden-blocked", "-T", "delete", ip])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => {
            // ufw: delete the deny rule
            std::process::Command::new("sudo")
                .args(["ufw", "delete", "deny", "from", ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };

    if !unblocked {
        println!("  Warning: unblock command may have failed (rule may not exist).");
        println!("  Check manually: sudo ufw status | grep {ip}");
    } else {
        println!("  [ok] {ip} unblocked via {backend}");
    }

    write_manual_decision(&effective_dir, ip, "unblock_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "unblock_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now unblocked.");
    Ok(())
}

pub(crate) fn cmd_allowlist_add(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use crate::config_editor::write_array_push;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if added {
            println!("Added to trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} is already in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if added {
            println!("Added to trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} is already in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_add".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

pub(crate) fn cmd_allowlist_remove(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use crate::config_editor::write_array_remove;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let removed = write_array_remove(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if removed {
            println!("Removed from trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} was not in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let removed =
            write_array_remove(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if removed {
            println!("Removed from trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} was not in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_remove".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

pub(crate) fn cmd_allowlist_list(cli: &Cli) -> Result<()> {
    use crate::config_editor::read_str_array;
    let ips = read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
    let users = read_str_array(&cli.agent_config, "allowlist", "trusted_users");

    if ips.is_empty() && users.is_empty() {
        println!("Allowlist is empty - no trusted IPs or users configured.");
        println!("Add entries with: innerwarden allowlist add --ip <cidr>");
        return Ok(());
    }

    if !ips.is_empty() {
        println!("Trusted IPs / CIDRs:");
        for ip in &ips {
            println!("  {ip}");
        }
    }
    if !users.is_empty() {
        println!("Trusted users:");
        for user in &users {
            println!("  {user}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden suppress
// ---------------------------------------------------------------------------

fn suppressed_file(cli: &Cli) -> std::path::PathBuf {
    cli.data_dir.join("suppressed-incidents.txt")
}

pub(crate) fn cmd_suppress_add(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Check if already exists
    if existing.lines().any(|l| l.trim() == pattern) {
        println!("Pattern already suppressed: {pattern}");
        return Ok(());
    }

    // Append
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{pattern}")?;

    println!("Suppressed: {pattern}");
    println!("Matching incidents will be silently logged but not alerted.");
    println!();
    println!("  The agent will pick this up on next restart, or you can restart now:");
    println!("  sudo systemctl restart innerwarden-agent");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_add".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_remove(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    let new_content: String = content
        .lines()
        .filter(|l| l.trim() != pattern)
        .collect::<Vec<_>>()
        .join("\n");

    if content == new_content {
        println!("Pattern not found: {pattern}");
        return Ok(());
    }

    std::fs::write(
        &path,
        if new_content.is_empty() {
            String::new()
        } else {
            format!("{new_content}\n")
        },
    )?;
    println!("Removed suppression: {pattern}");
    println!("Matching incidents will alert again after agent restart.");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_remove".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_list(cli: &Cli) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let patterns: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if patterns.is_empty() {
        println!("No suppressed patterns.");
        println!("Add with: innerwarden suppress add <pattern>");
        return Ok(());
    }

    println!("Suppressed incident patterns:");
    for p in &patterns {
        println!("  {p}");
    }
    println!();
    println!(
        "{} pattern(s) active. Matching incidents are silently logged.",
        patterns.len()
    );
    Ok(())
}
