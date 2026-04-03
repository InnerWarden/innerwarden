use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{config_editor, prompt, require_sudo, restart_agent, Cli};

pub(crate) fn cmd_configure_responder(
    cli: &Cli,
    enable: bool,
    disable: bool,
    dry_run_flag: Option<bool>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    if !enable && !disable && dry_run_flag.is_none() {
        return cmd_configure_responder_interactive(cli);
    }

    if enable || disable {
        let value = enable;

        if enable && dry_run_flag == Some(false) && !cli.dry_run {
            println!("  WARNING: This will enable LIVE execution of security responses.");
            println!("  InnerWarden will run commands like 'ufw deny from <IP>' automatically.");
            println!();
            print!("  Type 'yes' to confirm: ");
            std::io::stdout().flush()?;
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if ans.trim() != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }

        if cli.dry_run {
            println!(
                "  [dry-run] would set [responder] enabled={value} in {}",
                cli.agent_config.display()
            );
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "enabled", value)?;
            println!("  [ok] responder.enabled = {value}");
        }
    }

    if let Some(dr) = dry_run_flag {
        if cli.dry_run {
            println!(
                "  [dry-run] would set [responder] dry_run={dr} in {}",
                cli.agent_config.display()
            );
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "dry_run", dr)?;
            println!("  [ok] responder.dry_run = {dr}");
        }
    }

    restart_agent(cli);
    println!();
    if enable && dry_run_flag == Some(false) {
        println!("Responder is LIVE. Decisions will execute automatically.");
    } else if disable {
        println!("Responder disabled. System observes only.");
    } else {
        println!("Responder updated. Run 'innerwarden status' to confirm.");
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "responder".to_string(),
        parameters: serde_json::json!({
            "enable": enable,
            "disable": disable,
            "dry_run": dry_run_flag,
        }),
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

    Ok(())
}

fn cmd_configure_responder_interactive(cli: &Cli) -> Result<()> {
    println!("InnerWarden - Responder setup\n");
    println!("The responder controls what InnerWarden does when it detects an attack.\n");
    println!("  1. Observe only (safe)   - logs everything, takes no action");
    println!("  2. Dry-run mode          - shows what it WOULD do, but doesn't execute");
    println!("  3. Live (auto-block)     - automatically blocks IPs and suspends users\n");

    let choice = prompt("Choose [1/2/3]")?;

    match choice.trim() {
        "1" => {
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", false)?;
                println!("  [ok] responder disabled - observe only");
            } else {
                println!("  [dry-run] would disable responder");
            }
            restart_agent(cli);
            println!("\nSystem is in observe mode. No automatic actions will be taken.");
        }
        "2" => {
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
                config_editor::write_bool(&cli.agent_config, "responder", "dry_run", true)?;
                println!("  [ok] responder.enabled = true, dry_run = true");
            } else {
                println!("  [dry-run] would set responder.enabled=true, dry_run=true");
            }
            restart_agent(cli);
            println!(
                "\nDry-run mode enabled. InnerWarden will log what it would do but take no action."
            );
            println!("Check decisions-*.jsonl to review. When ready, run:");
            println!("  innerwarden configure responder --enable --dry-run false");
        }
        "3" => {
            println!();
            println!("  WARNING: In live mode, InnerWarden will automatically:");
            println!("    - Block IPs with: sudo ufw deny from <IP>  (or iptables/nftables)");
            println!("    - Suspend users:  drop-in in /etc/sudoers.d/");
            println!();
            println!("  Make sure block-ip is enabled: innerwarden enable block-ip");
            println!();
            print!("  Type 'yes' to enable live execution: ");
            std::io::stdout().flush()?;
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if ans.trim() != "yes" {
                println!("Aborted.");
                return Ok(());
            }
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
                config_editor::write_bool(&cli.agent_config, "responder", "dry_run", false)?;
                println!("  [ok] responder is LIVE");
            } else {
                println!("  [dry-run] would set responder.enabled=true, dry_run=false");
            }
            restart_agent(cli);
            println!(
                "\nResponder is LIVE. InnerWarden will act automatically on high-confidence threats."
            );
            println!(
                "Monitor decisions: tail -f /var/lib/innerwarden/decisions-$(date +%Y-%m-%d).jsonl"
            );
        }
        _ => {
            anyhow::bail!("invalid choice - enter 1, 2, or 3");
        }
    }
    Ok(())
}
