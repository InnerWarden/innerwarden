use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod capability;
mod capabilities;
mod config_editor;
mod preflight;
mod sudoers;
mod systemd;

use capability::{ActivationOptions, CapabilityRegistry};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "innerwarden",
    about = "InnerWarden control plane — manage capabilities",
    long_about = "Activate and manage InnerWarden capabilities.\n\n\
                  Run 'innerwarden list' to see available capabilities.\n\
                  Run 'innerwarden enable <id>' to activate one."
)]
struct Cli {
    /// Path to sensor config (config.toml)
    #[arg(long, default_value = "/etc/innerwarden/config.toml")]
    sensor_config: PathBuf,

    /// Path to agent config (agent.toml)
    #[arg(long, default_value = "/etc/innerwarden/agent.toml")]
    agent_config: PathBuf,

    /// Show what would happen without applying any changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Activate a capability
    Enable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Capability-specific parameters as KEY=VALUE
        #[arg(long = "param", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
        params: Vec<String>,

        /// Skip interactive confirmation prompts (e.g. privacy gate)
        #[arg(long)]
        yes: bool,
    },

    /// Deactivate a capability (not yet implemented)
    Disable {
        capability: String,
    },

    /// List all capabilities with their current status
    List,

    /// Show the status of a specific capability
    Status {
        capability: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let registry = CapabilityRegistry::default_all();

    match cli.command {
        Command::List => cmd_list(&cli, &registry),
        Command::Status { ref capability } => cmd_status(&cli, &registry, capability),
        Command::Enable {
            ref capability,
            ref params,
            yes,
        } => {
            let params = parse_params(params)?;
            cmd_enable(&cli, &registry, capability, params, yes)
        }
        Command::Disable { ref capability } => cmd_disable(&registry, capability),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn cmd_list(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    println!("{:<20} {:<10} {}", "Capability", "Status", "Description");
    println!("{}", "─".repeat(72));
    for cap in registry.all() {
        let opts = make_opts(cli, HashMap::new(), false);
        let status = if cap.is_enabled(&opts) {
            "enabled"
        } else {
            "disabled"
        };
        println!("{:<20} {:<10} {}", cap.id(), status, cap.description());
    }
    Ok(())
}

fn cmd_status(cli: &Cli, registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let cap = registry
        .get(id)
        .ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), false);
    let status = if cap.is_enabled(&opts) {
        "enabled"
    } else {
        "disabled"
    };
    println!("Capability:  {}", cap.name());
    println!("ID:          {}", cap.id());
    println!("Status:      {status}");
    println!("Description: {}", cap.description());
    Ok(())
}

fn cmd_enable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
) -> Result<()> {
    let cap = registry
        .get(id)
        .ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, params, yes);

    if cap.is_enabled(&opts) {
        println!("Capability '{}' is already enabled. Nothing to do.", cap.id());
        return Ok(());
    }

    println!("Enabling capability: {}\n", cap.name());

    // --- Preflight checks ---
    println!("Preflight checks:");
    let preflights = cap.preflights(&opts);
    let mut any_failed = false;
    for pf in &preflights {
        match pf.check() {
            Ok(()) => println!("  [ok] {}", pf.name()),
            Err(e) => {
                println!("  [fail] {}", e.message);
                if let Some(hint) = &e.fix_hint {
                    println!("         → {hint}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("preflight checks failed — no changes applied");
    }

    // --- Planned effects ---
    println!("\nPlanned changes:");
    let effects = cap.planned_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // --- Confirmation ---
    if !yes {
        print!("\nApply? [Y/n] ");
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

    // --- Activate ---
    let report = cap.activate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    println!("\nCapability '{}' is now enabled.", cap.id());
    Ok(())
}

fn cmd_disable(registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let _cap = registry
        .get(id)
        .ok_or_else(|| unknown_cap_error(id))?;
    anyhow::bail!(
        "'disable' is not yet implemented. \
         To manually revert, set the corresponding config keys back to their defaults."
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_opts(cli: &Cli, params: HashMap<String, String>, yes: bool) -> ActivationOptions {
    ActivationOptions {
        sensor_config: cli.sensor_config.clone(),
        agent_config: cli.agent_config.clone(),
        dry_run: cli.dry_run,
        params,
        yes,
    }
}

fn parse_params(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (k, v) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid param '{}' — expected KEY=VALUE format", item)
        })?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

fn unknown_cap_error(id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unknown capability '{}' — run 'innerwarden list' to see available capabilities",
        id
    )
}
