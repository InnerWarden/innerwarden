use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use crate::{commands, make_opts, CapabilityRegistry, Cli, DailyCommand};

pub(crate) fn cmd_list(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    println!("{:<20} {:<10} Description", "Capability", "Status");
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

    println!();
    println!("System coverage:");
    println!("  22 eBPF kernel hooks (execve, connect, ptrace, setuid, bind, mount, ...)");
    println!("  36 stateful detectors (SSH brute-force, rootkit, reverse shell, ransomware, ...)");
    println!("  13 log collectors (auth_log, journald, docker, nginx, suricata, ...)");
    println!("  7 kill chain patterns blocked at kernel level");
    println!();
    println!("These run automatically. Capabilities above are optional add-ons.");
    println!("Run 'innerwarden scan' to see what's recommended for this machine.");

    Ok(())
}

pub(crate) fn cmd_daily(
    cli: &Cli,
    registry: &CapabilityRegistry,
    command: Option<&DailyCommand>,
) -> Result<()> {
    match command {
        Some(DailyCommand::Status) => {
            let modules_dir = Path::new("/etc/innerwarden/modules");
            commands::status::cmd_status_global(cli, registry, modules_dir)
        }
        Some(DailyCommand::Threats {
            days,
            severity,
            live,
        }) => {
            if *live {
                commands::history::cmd_incidents_live(cli, severity, &cli.data_dir.clone())
            } else {
                commands::history::cmd_incidents(cli, *days, severity, &cli.data_dir.clone())
            }
        }
        Some(DailyCommand::Actions { days }) => {
            commands::history::cmd_decisions(cli, *days, None, &cli.data_dir.clone())
        }
        Some(DailyCommand::Report { date }) => {
            commands::status::cmd_report(cli, date, &cli.data_dir.clone())
        }
        Some(DailyCommand::Doctor) => commands::ops::cmd_doctor(cli, registry),
        Some(DailyCommand::Test { wait }) => {
            commands::ops::cmd_pipeline_test(cli, *wait, &cli.data_dir.clone())
        }
        Some(DailyCommand::Agent { command }) => commands::agent::cmd_agent(cli, command.as_ref()),
        None => {
            println!("InnerWarden Daily Commands");
            println!("{}", "═".repeat(52));
            println!("Use these for day-to-day operations:");
            println!("  innerwarden daily status");
            println!("  innerwarden daily threats");
            println!("  innerwarden daily actions");
            println!("  innerwarden daily report");
            println!("  innerwarden daily doctor");
            println!("  innerwarden daily test");
            println!("  innerwarden daily agent");
            println!();
            println!("Short aliases:");
            println!("  innerwarden quick status");
            println!("  innerwarden day threats --live");
            println!("  innerwarden quick agent scan");
            println!();
            println!("Need advanced operations?");
            println!("  innerwarden --help");
            println!("  innerwarden <command> --help");
            Ok(())
        }
    }
}
