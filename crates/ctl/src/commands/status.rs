use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::capability::CapabilityRegistry;
use crate::module_manifest::{is_module_enabled, scan_modules_dir};
use crate::{
    count_jsonl_lines, epoch_secs_to_date, make_opts, read_last_incident_summary, resolve_data_dir,
    systemd, today_date_string, unknown_cap_error, yesterday_date_string, Cli,
};

pub(crate) fn cmd_status(cli: &Cli, registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
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

pub(crate) fn cmd_status_global(
    cli: &Cli,
    registry: &CapabilityRegistry,
    modules_dir: &Path,
) -> Result<()> {
    println!("InnerWarden Status");
    println!("{}", "═".repeat(56));

    println!("\nServices");
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let active = systemd::is_service_active(unit);
        let indicator = if active { "●" } else { "○" };
        let label = if active { "running" } else { "stopped" };
        println!("  {indicator} {unit:<28} {label}");
    }

    let data_dir: Option<PathBuf> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("output")
                .and_then(|o| o.get("data_dir"))
                .and_then(|d| d.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| Some(PathBuf::from("/var/lib/innerwarden")));

    if let Some(ref dir) = data_dir {
        let today = today_date_string();
        let events_count = count_jsonl_lines(&dir.join(format!("events-{today}.jsonl")));
        let incidents_count = count_jsonl_lines(&dir.join(format!("incidents-{today}.jsonl")));
        let last_incident =
            read_last_incident_summary(&dir.join(format!("incidents-{today}.jsonl")));

        println!("\nToday  ({})", today);
        println!("  Events logged:    {events_count}");
        println!("  Threats detected: {incidents_count}");
        if let Some((title, when)) = last_incident {
            println!("  Last threat:      {title}  [{when}]");
        } else if incidents_count == 0 {
            println!("  Last threat:      none - quiet day so far");
        }
    }

    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ai_provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();
    let responder_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dry_run = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("dry_run"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    println!("\nAI & Response");
    if ai_enabled {
        println!("  ● AI analysis     active  ({ai_provider})");
    } else {
        println!("  ○ AI analysis     disabled");
    }
    if responder_enabled {
        let mode = if dry_run {
            "dry-run (observe only)"
        } else {
            "live (executing actions)"
        };
        println!("  ● Responder       active  ({mode})");
    } else {
        println!("  ○ Responder       disabled");
    }

    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    for cap in registry.all() {
        let enabled = cap.is_enabled(&opts);
        let indicator = if enabled { "●" } else { "○" };
        let label = if enabled { "enabled " } else { "disabled" };
        println!(
            "  {indicator} {:<20} {}  {}",
            cap.id(),
            label,
            cap.description()
        );
    }

    println!("\nModules  ({})", modules_dir.display());
    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("  (none installed)");
    } else {
        for m in &modules {
            let enabled = is_module_enabled(&cli.sensor_config, &cli.agent_config, m);
            let indicator = if enabled { "●" } else { "○" };
            let label = if enabled { "enabled " } else { "disabled" };
            println!("  {indicator} {:<20} {}  {}", m.id, label, m.name);
        }
    }

    println!();
    Ok(())
}

pub(crate) fn cmd_report(cli: &Cli, date_arg: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = if data_dir == Path::new("/var/lib/innerwarden") {
        cli.agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    };

    let date = match date_arg {
        "today" => today_date_string(),
        "yesterday" => yesterday_date_string(),
        other => other.to_string(),
    };

    let summary_path = effective_dir.join(format!("summary-{date}.md"));

    if !summary_path.exists() {
        let mut available: Vec<String> = std::fs::read_dir(&effective_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.strip_prefix("summary-")
                    .and_then(|s| s.strip_suffix(".md"))
                    .map(|d| d.to_string())
            })
            .collect();

        if available.is_empty() {
            println!("No summary found for {date}.");
            println!();
            println!("Summary files are generated by innerwarden-agent every 30 minutes.");
            println!("Make sure the agent is running:  innerwarden status");
        } else {
            available.sort();
            available.reverse();
            println!("No summary found for {date}.");
            println!();
            println!("Available dates:");
            for d in available.iter().take(7) {
                println!("  innerwarden report --date {d}");
            }
        }
        return Ok(());
    }

    let content = std::fs::read_to_string(&summary_path)
        .with_context(|| format!("failed to read {}", summary_path.display()))?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            println!("\n  {}", rest);
        } else if let Some(rest) = line.strip_prefix("## ") {
            println!("\n{}", rest.to_uppercase());
            println!("{}", "─".repeat(48));
        } else if let Some(rest) = line.strip_prefix("# ") {
            println!("{}", rest);
            println!("{}", "═".repeat(56));
        } else if line.starts_with("---") {
        } else {
            println!("{line}");
        }
    }

    println!();
    println!("Full report: {}", summary_path.display());
    Ok(())
}

pub(crate) fn cmd_sensor_status(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = epoch_secs_to_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let snapshot: Option<serde_json::Value> = std::fs::read_to_string(&telemetry_path)
        .ok()
        .and_then(|content| {
            content
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .and_then(|line| serde_json::from_str(line).ok())
        });

    println!("InnerWarden - sensor status  ({})\n", today);

    let Some(snap) = snapshot else {
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("Collectors (events today):");
    let by_collector = snap["events_by_collector"].as_object();
    match by_collector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (source, count) in &pairs {
                println!("  ● {:<30} {:>6} events", source, count);
            }
        }
        _ => println!("  (no events recorded yet today)"),
    }

    println!();
    println!("Detectors (incidents today):");
    let by_detector = snap["incidents_by_detector"].as_object();
    match by_detector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (detector, count) in &pairs {
                println!("  ⚠  {:<30} {:>6} incidents", detector, count);
            }
        }
        _ => println!("  (no incidents today)"),
    }

    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI & Response (today):");
    println!("  Passed algorithm gate:  {gate_pass}");
    println!("  Sent to AI:             {ai_sent}");
    println!("  AI decisions:           {ai_decided}  (avg {avg_ms:.0}ms)");
    if real_exec > 0 {
        println!("  Actions executed:       {real_exec}  (live)");
    }
    if dry_exec > 0 {
        println!("  Actions simulated:      {dry_exec}  (dry-run)");
    }

    let errors = snap["errors_by_component"].as_object();
    if let Some(map) = errors {
        if !map.is_empty() {
            println!();
            println!("Errors:");
            for (comp, count) in map {
                println!("  ✗ {comp}: {}", count.as_u64().unwrap_or(0));
            }
        }
    }

    println!();
    Ok(())
}

pub(crate) fn cmd_metrics(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let content = std::fs::read_to_string(&telemetry_path)
        .with_context(|| format!("cannot read {}", telemetry_path.display()))?;

    let first_line: Option<serde_json::Value> = content
        .lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let snapshot: Option<serde_json::Value> = content
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let Some(snap) = snapshot else {
        println!("InnerWarden - metrics  ({})\n", today);
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("InnerWarden - metrics  ({})\n", today);

    println!("Events processed today:");
    let by_collector = snap["events_by_collector"].as_object();
    let mut total_events: u64 = 0;
    match by_collector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_events += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (source, count) in &pairs {
                println!("  {:<30} {:>6}", source, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_events);
        }
        _ => println!("  (no events recorded yet today)"),
    }

    println!();
    println!("Incidents detected today:");
    let by_detector = snap["incidents_by_detector"].as_object();
    let mut total_incidents: u64 = 0;
    match by_detector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_incidents += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (detector, count) in &pairs {
                println!("  {:<30} {:>6}", detector, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_incidents);
        }
        _ => println!("  (no incidents today)"),
    }

    println!();
    println!("Decisions made today:");
    let by_action = snap["decisions_by_action"].as_object();
    let mut total_decisions: u64 = 0;
    match by_action {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_decisions += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (action, count) in &pairs {
                println!("  {:<30} {:>6}", action, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_decisions);
        }
        _ => println!("  (no decisions today)"),
    }

    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI pipeline:");
    println!("  Passed algorithm gate:    {:>6}", gate_pass);
    println!("  Sent to AI:               {:>6}", ai_sent);
    println!("  AI decisions:             {:>6}", ai_decided);
    println!("  Avg decision latency:     {:>5.0} ms", avg_ms);
    println!("  Actions executed (live):  {:>6}", real_exec);
    println!("  Actions simulated (dry):  {:>6}", dry_exec);

    if let Some(ref first) = first_line {
        if let Some(first_ts) = first["ts"].as_u64().or_else(|| first["timestamp"].as_u64()) {
            let uptime_secs = now_secs.saturating_sub(first_ts);
            let hours = uptime_secs / 3600;
            let minutes = (uptime_secs % 3600) / 60;
            println!();
            println!("Agent uptime (approx):      {}h {}m", hours, minutes);
        }
    }

    println!();
    Ok(())
}
