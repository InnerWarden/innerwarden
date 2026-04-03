use std::path::Path;

/// Count the number of lines in a JSONL file in data_dir (fail-silent -> 0).
pub(crate) fn count_jsonl_lines(data_dir: &Path, filename: &str) -> usize {
    let path = data_dir.join(filename);
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

/// Read the last N incidents from today's incidents file, formatted for display.
pub(crate) fn read_last_incidents(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "🔇 Clean slate - no intrusion attempts today.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "🔇 Clean slate - no intrusion attempts today.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();
    let now = chrono::Utc::now();

    let sev_icon = |s: &str| match s {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        _ => "⚪",
    };

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let severity = v["severity"].as_str().unwrap_or("?");
            let icon = sev_icon(severity);
            let title = v["title"].as_str().unwrap_or("unknown").to_string();
            let entity = v["entities"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|e| e["value"].as_str())
                .unwrap_or("?")
                .to_string();
            let ts_str = v["ts"].as_str().unwrap_or("");
            let age = chrono::DateTime::parse_from_rfc3339(ts_str)
                .ok()
                .map(|t| {
                    let mins = now
                        .signed_duration_since(t.with_timezone(&chrono::Utc))
                        .num_minutes();
                    if mins < 1 {
                        "just now".to_string()
                    } else if mins < 60 {
                        format!("{mins}m ago")
                    } else {
                        format!("{}h ago", mins / 60)
                    }
                })
                .unwrap_or_default();
            Some(format!("{icon} {title}\n   <code>{entity}</code> · {age}"))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable incidents today.".to_string()
    } else {
        format!(
            "🚨 <b>Recent threats</b> (last {})\n\n{}",
            formatted.len(),
            formatted.join("\n\n")
        )
    }
}

/// Read the last N decisions from today's decisions file, formatted for display.
pub(crate) fn read_last_decisions(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return "⚖️ No decisions yet today - standing by.".to_string(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return "⚖️ No decisions yet today - standing by.".to_string();
    }

    let last_n: Vec<&str> = lines.iter().rev().take(n).copied().collect::<Vec<_>>();

    let action_icon = |a: &str| {
        if a.contains("block") || a.contains("Block") {
            "🚫"
        } else if a.contains("suspend") || a.contains("Suspend") {
            "👑"
        } else if a.contains("honeypot") || a.contains("Honeypot") {
            "🍯"
        } else if a.contains("monitor") || a.contains("Monitor") {
            "👁"
        } else if a.contains("kill") || a.contains("Kill") {
            "💀"
        } else if a.contains("kill_chain") || a.contains("Kill chain") {
            "🔗"
        } else if a.contains("Ignore") || a.contains("ignore") {
            "🙈"
        } else {
            "⚡"
        }
    };

    let formatted: Vec<String> = last_n
        .into_iter()
        .rev()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let action = v["action_type"].as_str().unwrap_or("?").to_string();
            let icon = action_icon(&action);
            let target = v["target_ip"]
                .as_str()
                .or_else(|| v["target_user"].as_str())
                .unwrap_or("?")
                .to_string();
            let confidence = v["confidence"].as_f64().unwrap_or(0.0);
            let pct = (confidence * 100.0) as u32;
            let dry_run = v["dry_run"].as_bool().unwrap_or(true);
            let mode = if dry_run { "sim" } else { "live" };
            Some(format!(
                "{icon} {action} <code>{target}</code>\n   {pct}% confidence · {mode}"
            ))
        })
        .collect();

    if formatted.is_empty() {
        "No parseable decisions today.".to_string()
    } else {
        format!(
            "⚖️ <b>Recent decisions</b> (last {})\n\n{}",
            formatted.len(),
            formatted.join("\n\n")
        )
    }
}

/// Read the last N incidents as compact JSON strings (for AI context).
pub(crate) fn read_last_incidents_raw(data_dir: &Path, today: &str, n: usize) -> String {
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return String::new();
    }

    lines
        .iter()
        .rev()
        .take(n)
        .map(|l| {
            // Summarise to avoid sending huge JSON blobs to the AI
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .map(|v| {
                    format!(
                        "[{}] {} - {}",
                        v["severity"].as_str().unwrap_or("?"),
                        v["title"].as_str().unwrap_or("?"),
                        v["summary"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(120)
                            .collect::<String>()
                    )
                })
                .unwrap_or_default()
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}
