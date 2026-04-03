use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{
    append_admin_action, current_operator, epoch_secs_to_date, looks_like_ip, resolve_data_dir,
    AdminActionEntry, Cli,
};

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn sev_tag_bracket(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => "[CRITICAL]",
        "high" => "[HIGH]    ",
        "medium" => "[MEDIUM]  ",
        "low" => "[LOW]     ",
        _ => "[INFO]    ",
    }
}

fn sev_tag_plain(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => " CRITICAL",
        "high" => " HIGH    ",
        "medium" => " MEDIUM  ",
        "low" => " LOW     ",
        _ => "         ",
    }
}

pub(crate) fn cmd_incidents(
    cli: &Cli,
    days: u64,
    severity_filter: &str,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let min_rank = severity_rank(severity_filter);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut dates = Vec::new();
    for i in 0..days {
        let secs = now_secs.saturating_sub(i * 86400);
        dates.push(epoch_secs_to_date(secs));
    }

    let mut total = 0usize;
    for date in &dates {
        let path = effective_dir.join(format!("incidents-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            continue;
        }

        println!("── {date} ─────────────────────────────────────────────");

        for line in &lines {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let sev = v["severity"].as_str().unwrap_or("Info");
            if severity_rank(sev) < min_rank {
                continue;
            }
            let title = v["title"].as_str().unwrap_or("Unknown threat");
            let ts = v["ts"].as_str().unwrap_or("");
            let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
            let ip = v["entities"]
                .as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|e| e["type"].as_str() == Some("Ip"))
                        .and_then(|e| e["value"].as_str())
                })
                .unwrap_or("");
            let sev_tag = sev_tag_bracket(sev);
            let ip_part = if ip.is_empty() {
                String::new()
            } else {
                format!("  {ip}")
            };
            println!("  {time}  {sev_tag}  {title}{ip_part}");
            total += 1;
        }
        println!();
    }

    if total == 0 {
        if severity_filter != "low" {
            println!(
                "No {} or higher incidents found in the last {} day(s).",
                severity_filter, days
            );
        } else {
            println!("No incidents found in the last {} day(s). Quiet!", days);
        }
    } else {
        println!("{total} incident(s) shown.  Run 'innerwarden report' for the full narrative.");
    }
    Ok(())
}

pub(crate) fn cmd_export(
    cli: &Cli,
    kind: &str,
    from_arg: Option<&str>,
    to_arg: Option<&str>,
    format: &str,
    output_path: Option<&Path>,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let from = from_arg.unwrap_or(&today).to_string();
    let to = to_arg.unwrap_or(&today).to_string();

    let prefix = match kind {
        "events" => "events",
        "decisions" => "decisions",
        _ => "incidents",
    };

    let mut all_lines: Vec<serde_json::Value> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&effective_dir) {
        let mut files: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(date) = name
                    .strip_prefix(&format!("{prefix}-"))
                    .and_then(|s| s.strip_suffix(".jsonl"))
                {
                    date >= from.as_str() && date <= to.as_str()
                } else {
                    false
                }
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        all_lines.push(v);
                    }
                }
            }
        }
    }

    if all_lines.is_empty() {
        eprintln!("No {kind} found between {from} and {to}.");
        return Ok(());
    }

    let content = match format {
        "csv" => {
            let mut keys: Vec<String> = all_lines
                .iter()
                .filter_map(|v| v.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            keys.retain(|k| k != "evidence" && k != "details" && k != "entities");

            let mut out = keys.join(",") + "\n";
            for row in &all_lines {
                let fields: Vec<String> = keys
                    .iter()
                    .map(|k| {
                        let v = &row[k];
                        let s = match v {
                            serde_json::Value::String(s) => s.replace('"', "\"\""),
                            serde_json::Value::Null => String::new(),
                            other => other.to_string().replace('"', "\"\""),
                        };
                        if s.contains(',') || s.contains('"') || s.contains('\n') {
                            format!("\"{s}\"")
                        } else {
                            s
                        }
                    })
                    .collect();
                out += &(fields.join(",") + "\n");
            }
            out
        }
        _ => serde_json::to_string_pretty(&all_lines)?,
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &content)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!(
                "Exported {} {kind}(s) ({from} → {to}) to {}",
                all_lines.len(),
                path.display()
            );
        }
        None => print!("{content}"),
    }

    Ok(())
}

pub(crate) fn cmd_tail(cli: &Cli, kind: &str, interval_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let prefix = if kind == "events" {
        "events"
    } else {
        "incidents"
    };

    println!("Streaming {kind}... (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let path = effective_dir.join(format!("{prefix}-{today}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        print_tail_entry(&v, kind);
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
    }
}

fn print_tail_entry(v: &serde_json::Value, kind: &str) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 16 { &ts[11..16] } else { ts };

    if kind == "events" {
        let source = v["source"].as_str().unwrap_or("?");
        let ev_kind = v["kind"].as_str().unwrap_or("?");
        let sev = v["severity"].as_str().unwrap_or("Info");
        let summary = v["summary"].as_str().unwrap_or("");
        println!("{time}  [{sev:<8}]  {source:<16}  {ev_kind}  {summary}");
    } else {
        let sev = v["severity"].as_str().unwrap_or("Info");
        let title = v["title"].as_str().unwrap_or("Unknown");
        let ip = v["entities"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|e| e["type"].as_str() == Some("Ip"))
                    .and_then(|e| e["value"].as_str())
            })
            .unwrap_or("");
        let sev_tag = sev_tag_bracket(sev);
        let ip_part = if ip.is_empty() {
            String::new()
        } else {
            format!("  {ip}")
        };
        println!("{time}  {sev_tag}  {title}{ip_part}");
    }
}

pub(crate) fn cmd_incidents_live(cli: &Cli, severity_filter: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let min_sev = parse_severity_filter(severity_filter);

    println!("● LIVE - streaming incidents (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let safe_date: String = today
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let path = effective_dir.join(format!("incidents-{safe_date}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        let sev = v["severity"].as_str().unwrap_or("info");
                        if severity_rank_str(sev) >= min_sev {
                            print_live_incident(&v);
                        }
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn print_live_incident(v: &serde_json::Value) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 19 { &ts[11..19] } else { ts };
    let sev = v["severity"].as_str().unwrap_or("info");
    let title = v["title"].as_str().unwrap_or("Unknown");
    let summary = v["summary"].as_str().unwrap_or("");

    let icon = match sev {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        _ => "⚪",
    };

    let entities: Vec<String> = v["entities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e["value"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let entity_str = if entities.is_empty() {
        String::new()
    } else {
        format!("  [{}]", entities.join(", "))
    };

    println!("{icon} {time}  {title}{entity_str}");
    if !summary.is_empty() && summary != title {
        let short: String = summary.chars().take(100).collect();
        println!("  └ {short}");
    }
    println!();
}

fn parse_severity_filter(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub(crate) fn cmd_decisions(
    cli: &Cli,
    days: u64,
    action_filter: Option<&str>,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    let mut total = 0usize;
    for date in &dates {
        let path = effective_dir.join(format!("decisions-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            continue;
        }

        println!("── {date} ─────────────────────────────────────────────");

        for line in &lines {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let action = v["action_type"].as_str().unwrap_or("unknown");
            if let Some(f) = action_filter {
                if !action.eq_ignore_ascii_case(f) {
                    continue;
                }
            }
            let ts = v["ts"].as_str().unwrap_or("");
            let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
            let target_ip = v["target_ip"].as_str().unwrap_or("");
            let target_user = v["target_user"].as_str().unwrap_or("");
            let confidence = v["confidence"].as_f64().unwrap_or(0.0);
            let dry_run = v["dry_run"].as_bool().unwrap_or(false);
            let provider = v["ai_provider"].as_str().unwrap_or("");

            let target = if !target_ip.is_empty() {
                target_ip.to_string()
            } else if !target_user.is_empty() {
                format!("user:{target_user}")
            } else {
                String::new()
            };

            let dry_tag = if dry_run { " [dry-run]" } else { "" };
            let conf_tag = if confidence > 0.0 {
                format!("  conf:{:.2}", confidence)
            } else {
                String::new()
            };
            let provider_tag = if !provider.is_empty() {
                format!("  via:{provider}")
            } else {
                String::new()
            };
            let target_part = if target.is_empty() {
                String::new()
            } else {
                format!("  {target}")
            };

            let action_tag = match action {
                "block_ip" => "[BLOCK]      ",
                "suspend_user_sudo" => "[SUSPEND]    ",
                "ignore" => "[IGNORE]     ",
                "monitor" => "[MONITOR]    ",
                "honeypot" => "[HONEYPOT]   ",
                "request_confirmation" => "[PENDING]    ",
                _ => "[UNKNOWN]    ",
            };

            println!("  {time}  {action_tag}{target_part}{conf_tag}{provider_tag}{dry_tag}");
            total += 1;
        }
        println!();
    }

    if total == 0 {
        if let Some(f) = action_filter {
            println!("No '{f}' decisions found in the last {days} day(s).");
        } else {
            println!("No decisions recorded in the last {days} day(s).");
            println!("The agent may be in observe-only mode or not running.");
            println!("Run 'innerwarden status' to check.");
        }
    } else {
        println!(
            "{total} decision(s) shown.  Full audit trail: {}/decisions-*.jsonl",
            effective_dir.display()
        );
    }
    Ok(())
}

pub(crate) fn cmd_entity(cli: &Cli, target: &str, days: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let is_ip = looks_like_ip(target);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    #[derive(Debug)]
    struct Entry {
        ts: String,
        kind: &'static str,
        severity: String,
        summary: String,
        extra: String,
    }

    let mut entries: Vec<Entry> = Vec::new();

    for date in &dates {
        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("Ip")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("User")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "event",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["summary"].as_str().unwrap_or("").to_string(),
                        extra: v["kind"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("ip"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("user"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "incident",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["title"].as_str().unwrap_or("").to_string(),
                        extra: v["summary"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        let decisions_path = effective_dir.join(format!("decisions-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let ip_match = is_ip && v["target_ip"].as_str() == Some(target);
                let user_match = !is_ip && v["target_user"].as_str() == Some(target);
                if ip_match || user_match {
                    let action = v["action_type"].as_str().unwrap_or("unknown");
                    let dry_run = v["dry_run"].as_bool().unwrap_or(false);
                    let dry_tag = if dry_run { " [dry-run]" } else { "" };
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "decision",
                        severity: String::new(),
                        summary: format!("Action: {action}{dry_tag}"),
                        extra: format!(
                            "conf:{:.2}  via:{}",
                            v["confidence"].as_f64().unwrap_or(0.0),
                            v["ai_provider"].as_str().unwrap_or("?")
                        ),
                    });
                }
            }
        }
    }

    if entries.is_empty() {
        let entity_type = if is_ip { "IP" } else { "user" };
        println!("No activity found for {entity_type} '{target}' in the last {days} day(s).");
        println!("Try --days 7 to search further back.");
        return Ok(());
    }

    entries.sort_by(|a, b| a.ts.cmp(&b.ts));

    let entity_type = if is_ip { "IP" } else { "User" };
    let event_count = entries.iter().filter(|e| e.kind == "event").count();
    let incident_count = entries.iter().filter(|e| e.kind == "incident").count();
    let decision_count = entries.iter().filter(|e| e.kind == "decision").count();

    println!("Entity: {entity_type} {target}");
    println!("Period: last {days} day(s)");
    println!("Found:  {event_count} event(s)  {incident_count} incident(s)  {decision_count} decision(s)");
    println!("{}", "─".repeat(72));

    for entry in &entries {
        let time = if entry.ts.len() >= 16 {
            &entry.ts[..16]
        } else {
            &entry.ts
        };
        let kind_tag = match entry.kind {
            "incident" => "[INCIDENT]  ",
            "decision" => "[DECISION]  ",
            _ => "[event]     ",
        };
        let sev_tag = if entry.kind == "event" || entry.kind == "incident" {
            sev_tag_plain(&entry.severity)
        } else {
            "         "
        };
        println!("{time}  {kind_tag}{sev_tag}  {}", entry.summary);
        if !entry.extra.is_empty() && entry.kind != "event" {
            println!("                                     {}", entry.extra);
        }
    }

    println!("{}", "─".repeat(72));
    println!("Open dashboard for full details: innerwarden status");
    Ok(())
}

pub(crate) fn matches_entity(line: &str, entity: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(entities) = value.get("entities").and_then(|v| v.as_array()) {
            for e in entities {
                if let Some(val) = e.get("value").and_then(|v| v.as_str()) {
                    if val == entity {
                        return true;
                    }
                }
            }
        }
        for field in &["target_ip", "target_user", "operator", "target"] {
            if let Some(val) = value.get(*field).and_then(|v| v.as_str()) {
                if val == entity {
                    return true;
                }
            }
        }
    }
    false
}

fn recompute_hash_chain(lines: &mut [String]) {
    use innerwarden_core::audit::sha256_hex;
    let mut last_hash: Option<String> = None;
    for line in lines.iter_mut() {
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) {
            value["prev_hash"] = match &last_hash {
                Some(h) => serde_json::Value::String(h.clone()),
                None => serde_json::Value::Null,
            };
            let new_line = serde_json::to_string(&value).unwrap();
            last_hash = Some(sha256_hex(&new_line));
            *line = new_line;
        }
    }
}

pub(crate) fn cmd_gdpr_export(data_dir: &Path, entity: &str, output: Option<&Path>) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let mut total = 0usize;
    let mut writer: Box<dyn Write> = match output {
        Some(p) => Box::new(std::fs::File::create(p)?),
        None => Box::new(std::io::stdout()),
    };

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        if !patterns.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        let content = std::fs::read_to_string(entry.path())?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                writeln!(writer, "{line}")?;
                total += 1;
            }
        }
    }

    eprintln!("  Found {total} records matching '{entity}'");
    Ok(())
}

pub(crate) fn cmd_gdpr_erase(data_dir: &Path, entity: &str, yes: bool) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let hash_chained = &["decisions-", "admin-actions-"];

    let mut file_matches: Vec<(PathBuf, String, usize)> = Vec::new();
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let prefix = match patterns.iter().find(|p| name.starts_with(**p)) {
            Some(p) => p.to_string(),
            None => continue,
        };

        let content = std::fs::read_to_string(entry.path())?;
        let count = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| matches_entity(l, entity))
            .count();
        if count > 0 {
            file_matches.push((entry.path(), prefix, count));
        }
    }

    let total: usize = file_matches.iter().map(|(_, _, c)| *c).sum();
    if total == 0 {
        println!("  No records found matching '{entity}'");
        return Ok(());
    }

    println!(
        "  Found {total} records matching '{entity}' across {} files",
        file_matches.len()
    );
    if !yes {
        print!("  Proceed with erasure? [y/N] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let mut erased = 0usize;
    for (path, prefix, _) in &file_matches {
        let content = std::fs::read_to_string(path)?;
        let mut kept: Vec<String> = Vec::new();
        let mut removed = 0usize;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                removed += 1;
            } else {
                kept.push(line.to_string());
            }
        }

        if hash_chained.iter().any(|h| prefix.starts_with(h)) {
            recompute_hash_chain(&mut kept);
        }

        let tmp = tempfile::Builder::new()
            .prefix("innerwarden-gdpr-")
            .tempfile_in(data_dir)?;
        let tmp_path = tmp.path().to_path_buf();
        {
            let mut writer = std::io::BufWriter::new(&tmp);
            for line in &kept {
                writeln!(writer, "{line}")?;
            }
            writer.flush()?;
        }
        std::fs::rename(&tmp_path, path)?;

        erased += removed;
    }

    println!(
        "  Erased {erased} records across {} files",
        file_matches.len()
    );

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "gdpr_erase".to_string(),
        target: entity.to_string(),
        parameters: serde_json::json!({
            "records_erased": erased,
            "files_modified": file_matches.len(),
        }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        eprintln!("  [warn] failed to write audit: {e:#}");
    }

    Ok(())
}
