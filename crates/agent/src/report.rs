use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDate, Utc};
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::Serialize;
use serde_json::Value;

use crate::decisions::DecisionEntry;

#[derive(Debug, Serialize)]
pub struct GeneratedReport {
    pub markdown_path: PathBuf,
    pub json_path: PathBuf,
    pub report: TrialReport,
}

#[derive(Debug, Serialize)]
pub struct TrialReport {
    pub generated_at: DateTime<Utc>,
    pub analyzed_date: String,
    pub data_dir: String,
    pub operational_health: OperationalHealth,
    pub detection_summary: DetectionSummary,
    pub agent_ai_summary: AgentAiSummary,
    pub data_quality: DataQuality,
    pub suggested_improvements: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OperationalHealth {
    pub expected_files_present: bool,
    pub state_json_readable: bool,
    pub agent_state_json_readable: bool,
    pub files: Vec<FileHealth>,
}

#[derive(Debug, Serialize)]
pub struct FileHealth {
    pub file: String,
    pub exists: bool,
    pub readable: bool,
    pub size_bytes: u64,
    pub modified_secs_ago: Option<u64>,
    pub jsonl_valid: Option<bool>,
    pub lines: Option<u64>,
    pub malformed_lines: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DetectionSummary {
    pub total_events: u64,
    pub total_incidents: u64,
    pub incidents_by_type: BTreeMap<String, u64>,
    pub top_ips: Vec<NamedCount>,
    pub top_entities: Vec<NamedCount>,
}

#[derive(Debug, Serialize)]
pub struct AgentAiSummary {
    pub total_decisions: u64,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub average_confidence: f64,
    pub ignore_count: u64,
    pub block_ip_count: u64,
    pub dry_run_count: u64,
    pub skills_used: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct DataQuality {
    pub empty_files: Vec<String>,
    pub malformed_jsonl: BTreeMap<String, u64>,
    pub incidents_without_entities: u64,
    pub decisions_without_action: u64,
    pub files_not_growing: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Default, Clone)]
struct ParseOutcome {
    exists: bool,
    readable: bool,
    size_bytes: u64,
    modified_secs_ago: Option<u64>,
    lines: u64,
    malformed_lines: u64,
}

impl ParseOutcome {
    fn jsonl_valid(&self) -> bool {
        self.exists && self.readable && self.malformed_lines == 0
    }
}

#[derive(Debug, Default)]
struct Counters {
    total_events: u64,
    total_incidents: u64,
    total_decisions: u64,
    confidence_sum: f64,

    incidents_by_type: HashMap<String, u64>,
    ip_counts: HashMap<String, u64>,
    entity_counts: HashMap<String, u64>,
    decisions_by_action: HashMap<String, u64>,
    skills_used: HashMap<String, u64>,

    ignore_count: u64,
    block_ip_count: u64,
    dry_run_count: u64,

    incidents_without_entities: u64,
    decisions_without_action: u64,

    malformed_jsonl: BTreeMap<String, u64>,
    empty_files: Vec<String>,
    files_not_growing: Vec<String>,
}

pub fn generate(data_dir: &Path) -> Result<GeneratedReport> {
    let report_date = Local::now().date_naive().format("%Y-%m-%d").to_string();
    let analyzed_date = detect_latest_date(data_dir).unwrap_or_else(|| report_date.clone());
    let analyzed_is_today = analyzed_date == report_date;

    let events = data_dir.join(format!("events-{analyzed_date}.jsonl"));
    let incidents = data_dir.join(format!("incidents-{analyzed_date}.jsonl"));
    let decisions = data_dir.join(format!("decisions-{analyzed_date}.jsonl"));
    let summary = data_dir.join(format!("summary-{analyzed_date}.md"));
    let state = data_dir.join("state.json");
    let agent_state = data_dir.join("agent-state.json");

    let mut counters = Counters::default();
    let mut files = Vec::new();

    let events_outcome = parse_events_file(&events, &mut counters);
    record_quality_hints(
        "events",
        &events_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("events", &events_outcome));

    let incidents_outcome = parse_incidents_file(&incidents, &mut counters);
    record_quality_hints(
        "incidents",
        &incidents_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("incidents", &incidents_outcome));

    let decisions_outcome = parse_decisions_file(&decisions, &mut counters);
    record_quality_hints(
        "decisions",
        &decisions_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("decisions", &decisions_outcome));

    let summary_info = parse_plain_file(&summary);
    record_plain_file_hints("summary", &summary_info, analyzed_is_today, &mut counters);
    files.push(file_health_plain("summary", &summary_info));

    let state_info = parse_state_file(&state);
    record_plain_file_hints("state", &state_info, false, &mut counters);
    files.push(file_health_plain("state", &state_info));

    let agent_state_info = parse_state_file(&agent_state);
    record_plain_file_hints("agent-state", &agent_state_info, false, &mut counters);
    files.push(file_health_plain("agent-state", &agent_state_info));

    let expected_files_present = files.iter().all(|f| f.exists);
    let state_json_readable = state_info.exists && state_info.readable;
    let agent_state_json_readable = agent_state_info.exists && agent_state_info.readable;

    let detection_summary = DetectionSummary {
        total_events: counters.total_events,
        total_incidents: counters.total_incidents,
        incidents_by_type: to_btreemap(counters.incidents_by_type.clone()),
        top_ips: top_n(&counters.ip_counts, 10),
        top_entities: top_n(&counters.entity_counts, 10),
    };

    let avg_conf = if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    };
    let agent_ai_summary = AgentAiSummary {
        total_decisions: counters.total_decisions,
        decisions_by_action: to_btreemap(counters.decisions_by_action.clone()),
        average_confidence: avg_conf,
        ignore_count: counters.ignore_count,
        block_ip_count: counters.block_ip_count,
        dry_run_count: counters.dry_run_count,
        skills_used: to_btreemap(counters.skills_used.clone()),
    };

    let data_quality = DataQuality {
        empty_files: counters.empty_files.clone(),
        malformed_jsonl: counters.malformed_jsonl.clone(),
        incidents_without_entities: counters.incidents_without_entities,
        decisions_without_action: counters.decisions_without_action,
        files_not_growing: counters.files_not_growing.clone(),
    };

    let operational_health = OperationalHealth {
        expected_files_present,
        state_json_readable,
        agent_state_json_readable,
        files,
    };

    let mut report = TrialReport {
        generated_at: Utc::now(),
        analyzed_date,
        data_dir: data_dir.display().to_string(),
        operational_health,
        detection_summary,
        agent_ai_summary,
        data_quality,
        suggested_improvements: vec![],
    };
    report.suggested_improvements = build_suggestions(&report);

    let json_path = data_dir.join(format!("trial-report-{report_date}.json"));
    let md_path = data_dir.join(format!("trial-report-{report_date}.md"));

    let json_file = File::create(&json_path)
        .with_context(|| format!("failed to create {}", json_path.display()))?;
    serde_json::to_writer_pretty(json_file, &report)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    let markdown = render_markdown(&report);
    fs::write(&md_path, markdown)
        .with_context(|| format!("failed to write {}", md_path.display()))?;

    Ok(GeneratedReport {
        markdown_path: md_path,
        json_path,
        report,
    })
}

fn detect_latest_date(data_dir: &Path) -> Option<String> {
    let mut latest: Option<String> = None;
    let entries = fs::read_dir(data_dir).ok()?;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let candidate = extract_date(&name, "events-", ".jsonl")
            .or_else(|| extract_date(&name, "incidents-", ".jsonl"))
            .or_else(|| extract_date(&name, "decisions-", ".jsonl"))
            .or_else(|| extract_date(&name, "summary-", ".md"));

        if let Some(date) = candidate {
            match &latest {
                Some(current) if current >= &date => {}
                _ => latest = Some(date),
            }
        }
    }

    latest
}

fn extract_date(name: &str, prefix: &str, suffix: &str) -> Option<String> {
    let raw = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .map(|_| raw.to_string())
}

fn parse_events_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |event: Event| {
        counters.total_events += 1;

        for e in event.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

fn parse_incidents_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |incident: Incident| {
        counters.total_incidents += 1;

        let incident_type = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *counters.incidents_by_type.entry(incident_type).or_insert(0) += 1;

        if incident.entities.is_empty() {
            counters.incidents_without_entities += 1;
        }

        for e in incident.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

fn parse_decisions_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;

        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        let action_present = value
            .get("action_type")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !action_present {
            counters.decisions_without_action += 1;
        }

        let decision: DecisionEntry = match serde_json::from_value(value) {
            Ok(d) => d,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        counters.total_decisions += 1;
        counters.confidence_sum += f64::from(decision.confidence);

        *counters
            .decisions_by_action
            .entry(decision.action_type.clone())
            .or_insert(0) += 1;

        if decision.action_type == "ignore" {
            counters.ignore_count += 1;
        }
        if decision.action_type == "block_ip" {
            counters.block_ip_count += 1;
        }
        if decision.dry_run {
            counters.dry_run_count += 1;
        }
        if let Some(skill) = decision.skill_id {
            *counters.skills_used.entry(skill).or_insert(0) += 1;
        }
    }

    outcome
}

fn parse_state_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    let content = match fs::read_to_string(path) {
        Ok(c) => {
            outcome.readable = true;
            c
        }
        Err(_) => return outcome,
    };
    if serde_json::from_str::<Value>(&content).is_err() {
        outcome.readable = false;
    }
    outcome
}

fn parse_plain_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    if File::open(path).is_ok() {
        outcome.readable = true;
    }
    outcome
}

fn parse_jsonl<T, F>(path: &Path, mut on_item: F) -> ParseOutcome
where
    T: serde::de::DeserializeOwned,
    F: FnMut(T),
{
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;
        match serde_json::from_str::<T>(trimmed) {
            Ok(item) => on_item(item),
            Err(_) => outcome.malformed_lines += 1,
        }
    }

    outcome
}

fn file_info(path: &Path) -> ParseOutcome {
    match fs::metadata(path) {
        Ok(meta) => ParseOutcome {
            exists: true,
            size_bytes: meta.len(),
            modified_secs_ago: meta
                .modified()
                .ok()
                .and_then(|m| SystemTime::now().duration_since(m).ok())
                .map(|d| d.as_secs()),
            ..Default::default()
        },
        Err(_) => ParseOutcome::default(),
    }
}

fn file_health_jsonl(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: Some(outcome.jsonl_valid()),
        lines: Some(outcome.lines),
        malformed_lines: Some(outcome.malformed_lines),
    }
}

fn file_health_plain(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: None,
        lines: None,
        malformed_lines: None,
    }
}

fn record_quality_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if outcome.malformed_lines > 0 {
        counters
            .malformed_jsonl
            .insert(name.to_string(), outcome.malformed_lines);
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn record_plain_file_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn to_btreemap(map: HashMap<String, u64>) -> BTreeMap<String, u64> {
    map.into_iter().collect()
}

fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<NamedCount> {
    let mut items: Vec<NamedCount> = map
        .iter()
        .map(|(name, count)| NamedCount {
            name: name.clone(),
            count: *count,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    items.truncate(n);
    items
}

fn build_suggestions(report: &TrialReport) -> Vec<String> {
    let mut suggestions = Vec::new();

    if !report.operational_health.expected_files_present {
        suggestions.push(
            "Some expected artifacts are missing; verify both sensor and agent services are running."
                .to_string(),
        );
    }
    if !report.operational_health.state_json_readable
        || !report.operational_health.agent_state_json_readable
    {
        suggestions.push(
            "State files could not be parsed; inspect state.json/agent-state.json integrity."
                .to_string(),
        );
    }
    if !report.data_quality.malformed_jsonl.is_empty() {
        suggestions.push(
            "Malformed JSONL lines detected; review producer logs and rotate corrupted files."
                .to_string(),
        );
    }
    if report.detection_summary.total_events == 0 {
        suggestions.push(
            "No events were captured; validate collector permissions (auth.log/journald access)."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents == 0 && report.detection_summary.total_events > 0 {
        suggestions.push(
            "Events exist but no incidents; run a controlled SSH brute-force test to validate detection."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents > 0 && report.agent_ai_summary.total_decisions == 0 {
        suggestions.push(
            "Incidents exist but no AI decisions; verify agent AI config and API key availability."
                .to_string(),
        );
    }
    if report.agent_ai_summary.total_decisions > 0 {
        let ignore_ratio =
            report.agent_ai_summary.ignore_count as f64 / report.agent_ai_summary.total_decisions as f64;
        if ignore_ratio > 0.8 {
            suggestions.push(
                "Most AI decisions are ignore; review detector thresholds and context_events for signal quality."
                    .to_string(),
            );
        }
    }
    if report.data_quality.incidents_without_entities > 0 {
        suggestions.push(
            "Some incidents were emitted without entities; improve detector payload completeness."
                .to_string(),
        );
    }
    if !report.data_quality.files_not_growing.is_empty() {
        suggestions.push(
            "Some active-day files appear stale (>6h without updates); verify ingest pipeline health."
                .to_string(),
        );
    }
    if suggestions.is_empty() {
        suggestions.push(
            "Trial looks healthy; proceed to next phase by enabling responder in dry-run mode."
                .to_string(),
        );
    }

    suggestions
}

fn render_markdown(report: &TrialReport) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "# InnerWarden Trial Report");
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "- Generated at: {}", report.generated_at.to_rfc3339());
    let _ = writeln!(&mut out, "- Analyzed date: {}", report.analyzed_date);
    let _ = writeln!(&mut out, "- Data dir: `{}`", report.data_dir);
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Operational health");
    let _ = writeln!(
        &mut out,
        "- Expected files present: {}",
        yes_no(report.operational_health.expected_files_present)
    );
    let _ = writeln!(
        &mut out,
        "- state.json readable: {}",
        yes_no(report.operational_health.state_json_readable)
    );
    let _ = writeln!(
        &mut out,
        "- agent-state.json readable: {}",
        yes_no(report.operational_health.agent_state_json_readable)
    );
    let _ = writeln!(&mut out);
    let _ = writeln!(
        &mut out,
        "| File | Exists | Readable | Size (bytes) | JSONL valid | Lines | Malformed |"
    );
    let _ = writeln!(
        &mut out,
        "|------|--------|----------|--------------|-------------|-------|-----------|"
    );
    for f in &report.operational_health.files {
        let _ = writeln!(
            &mut out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            f.file,
            yes_no(f.exists),
            yes_no(f.readable),
            f.size_bytes,
            f.jsonl_valid
                .map(yes_no)
                .unwrap_or_else(|| "-".to_string()),
            f.lines.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            f.malformed_lines
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Detection summary");
    let _ = writeln!(
        &mut out,
        "- Total events: {}",
        report.detection_summary.total_events
    );
    let _ = writeln!(
        &mut out,
        "- Total incidents: {}",
        report.detection_summary.total_incidents
    );
    let _ = writeln!(&mut out, "- Incidents by type:");
    if report.detection_summary.incidents_by_type.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.detection_summary.incidents_by_type {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Top IPs:");
    if report.detection_summary.top_ips.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_ips {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out, "- Most frequent entities:");
    if report.detection_summary.top_entities.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_entities {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Agent / AI summary");
    let _ = writeln!(
        &mut out,
        "- Total decisions: {}",
        report.agent_ai_summary.total_decisions
    );
    let _ = writeln!(
        &mut out,
        "- Average confidence: {:.3}",
        report.agent_ai_summary.average_confidence
    );
    let _ = writeln!(
        &mut out,
        "- Ignore decisions: {}",
        report.agent_ai_summary.ignore_count
    );
    let _ = writeln!(
        &mut out,
        "- block_ip decisions: {}",
        report.agent_ai_summary.block_ip_count
    );
    let _ = writeln!(
        &mut out,
        "- Dry-run decisions: {}",
        report.agent_ai_summary.dry_run_count
    );
    let _ = writeln!(&mut out, "- Decisions by action:");
    if report.agent_ai_summary.decisions_by_action.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.decisions_by_action {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Skills used:");
    if report.agent_ai_summary.skills_used.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.skills_used {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Data quality / anomalies");
    let _ = writeln!(
        &mut out,
        "- Empty files: {}",
        list_or_none(&report.data_quality.empty_files)
    );
    let _ = writeln!(
        &mut out,
        "- Malformed JSONL: {}",
        map_or_none(&report.data_quality.malformed_jsonl)
    );
    let _ = writeln!(
        &mut out,
        "- Incidents without entities: {}",
        report.data_quality.incidents_without_entities
    );
    let _ = writeln!(
        &mut out,
        "- Decisions without action: {}",
        report.data_quality.decisions_without_action
    );
    let _ = writeln!(
        &mut out,
        "- Files not growing (heuristic): {}",
        list_or_none(&report.data_quality.files_not_growing)
    );
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Suggested improvements");
    for suggestion in &report.suggested_improvements {
        let _ = writeln!(&mut out, "- {}", suggestion);
    }

    out
}

fn yes_no(v: bool) -> String {
    if v {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn map_or_none(items: &BTreeMap<String, u64>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    #[test]
    fn generates_report_files_and_counts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let decisions_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let summary_path = dir.path().join(format!("summary-{date}.md"));
        let state_path = dir.path().join("state.json");
        let agent_state_path = dir.path().join("agent-state.json");

        let e1 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
        };
        let e2 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail2".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &events_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&e1).unwrap(),
                serde_json::to_string(&e2).unwrap()
            ),
        )
        .unwrap();

        let inc = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(&incidents_path, format!("{}\n", serde_json::to_string(&inc).unwrap())).unwrap();

        let dec = DecisionEntry {
            ts: Utc::now(),
            incident_id: inc.incident_id.clone(),
            host: "h".to_string(),
            ai_provider: "openai".to_string(),
            action_type: "ignore".to_string(),
            target_ip: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: false,
            dry_run: true,
            reason: "test".to_string(),
            estimated_threat: "low".to_string(),
            execution_result: "skipped".to_string(),
        };
        fs::write(&decisions_path, format!("{}\n", serde_json::to_string(&dec).unwrap())).unwrap();

        fs::write(&summary_path, "# summary\n").unwrap();
        fs::write(&state_path, r#"{"cursors":{"auth_log":10}}"#).unwrap();
        fs::write(
            &agent_state_path,
            r#"{"events":{"2026-03-13":10},"incidents":{"2026-03-13":5}}"#,
        )
        .unwrap();

        let out = generate(dir.path()).unwrap();
        assert!(out.markdown_path.exists());
        assert!(out.json_path.exists());
        assert_eq!(out.report.detection_summary.total_events, 2);
        assert_eq!(out.report.detection_summary.total_incidents, 1);
        assert_eq!(out.report.agent_ai_summary.total_decisions, 1);
    }

    #[test]
    fn tracks_malformed_decisions_and_missing_action() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            "not-json\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("incidents-{date}.jsonl")),
            "",
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            r#"{"foo":"bar","confidence":0.5}"#,
        )
        .unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let out = generate(dir.path()).unwrap();
        assert!(out.report.data_quality.decisions_without_action > 0);
        assert!(!out.report.data_quality.malformed_jsonl.is_empty());
    }
}
