//! Monthly Threat Report generation.
//!
//! Scans all JSONL files for a given month and produces a comprehensive
//! report: executive summary, top attackers, campaign detection, MITRE
//! heatmap, geographic distribution, honeypot intel, mesh summary, and
//! weekly trends. Output as JSON + publishable Markdown.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::Serialize;

use crate::attacker_intel::{self, AttackerProfile, CampaignCluster};
use crate::decisions::DecisionEntry;
use crate::mitre;

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MonthlyThreatReport {
    pub generated_at: DateTime<Utc>,
    pub month: String,
    pub executive_summary: ExecutiveSummary,
    pub top_attackers: Vec<AttackerSummaryCompact>,
    pub campaigns: Vec<CampaignCluster>,
    pub mitre_coverage: MitreCoverage,
    pub geographic_distribution: GeoDistribution,
    pub honeypot_intelligence: HoneypotIntel,
    pub mesh_network: MeshSummary,
    pub weekly_trends: Vec<WeeklyBucket>,
}

#[derive(Debug, Serialize)]
pub struct ExecutiveSummary {
    pub total_events: u64,
    pub total_incidents: u64,
    pub total_decisions: u64,
    pub total_blocks: u64,
    pub unique_attackers: u64,
    pub unique_countries: u64,
    pub top_detector: String,
    pub top_mitre_technique: String,
    pub avg_incidents_per_day: f64,
    pub days_with_data: u32,
}

#[derive(Debug, Serialize)]
pub struct AttackerSummaryCompact {
    pub ip: String,
    pub risk_score: u8,
    pub country: String,
    pub total_incidents: u32,
    pub detectors: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub action_taken: String,
    pub dna_hash: String,
    pub pattern_class: String,
}

#[derive(Debug, Serialize)]
pub struct MitreCoverage {
    pub techniques_seen: Vec<MitreTechniqueSeen>,
    pub tactics_counts: BTreeMap<String, u64>,
    pub total_unique_techniques: usize,
}

#[derive(Debug, Serialize)]
pub struct MitreTechniqueSeen {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub incident_count: u64,
    pub attacker_count: u64,
}

#[derive(Debug, Serialize)]
pub struct GeoDistribution {
    pub by_country: Vec<CountryStats>,
}

#[derive(Debug, Serialize)]
pub struct CountryStats {
    pub country_code: String,
    pub country: String,
    pub attacker_count: u64,
    pub incident_count: u64,
}

#[derive(Debug, Serialize)]
pub struct HoneypotIntel {
    pub total_sessions: u64,
    pub unique_ips: u64,
    pub top_credentials: Vec<(String, String, u64)>,
    pub top_commands: Vec<(String, u64)>,
    pub tool_signatures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MeshSummary {
    pub threats_shared: u64,
    pub threats_received: u64,
    pub peer_count: u64,
}

#[derive(Debug, Serialize)]
pub struct WeeklyBucket {
    pub week_label: String,
    pub date_range: String,
    pub events: u64,
    pub incidents: u64,
    pub decisions: u64,
    pub blocks: u64,
    pub unique_attackers: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check if a monthly report already exists for the given month (YYYY-MM).
pub fn report_exists(data_dir: &Path, month: &str) -> bool {
    data_dir
        .join(format!("monthly-report-{month}.json"))
        .exists()
}

/// List available months that have report files or data.
pub fn available_months(data_dir: &Path) -> Vec<String> {
    let mut months = HashSet::new();

    // Existing reports
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(month) = name
                .strip_prefix("monthly-report-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                months.insert(month.to_string());
            }
            // Also detect months with incident data
            if let Some(date) = name
                .strip_prefix("incidents-")
                .and_then(|s| s.strip_suffix(".jsonl"))
            {
                if date.len() >= 7 {
                    months.insert(date[..7].to_string());
                }
            }
        }
    }

    let mut sorted: Vec<_> = months.into_iter().collect();
    sorted.sort();
    sorted.reverse();
    sorted
}

/// Generate the monthly report for a given month (YYYY-MM).
pub fn generate_monthly(
    data_dir: &Path,
    month: &str,
    profiles: &HashMap<String, AttackerProfile>,
) -> Result<MonthlyThreatReport> {
    let month_start =
        NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d").context("invalid month")?;
    let next_month = if month_start.month() == 12 {
        NaiveDate::from_ymd_opt(month_start.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(month_start.year(), month_start.month() + 1, 1)
    }
    .unwrap_or(month_start);
    let days_in_month = (next_month - month_start).num_days() as u32;

    // Scan all data files for the month
    let mut total_events: u64 = 0;
    let mut total_incidents: u64 = 0;
    let mut total_decisions: u64 = 0;
    let mut total_blocks: u64 = 0;
    let mut incidents_by_detector: BTreeMap<String, u64> = BTreeMap::new();
    let mut attacker_ips: HashSet<String> = HashSet::new();
    let mut days_with_data: u32 = 0;

    // Weekly buckets
    let mut weekly: Vec<WeeklyBucket> = (0..4)
        .map(|w| {
            let start = month_start + chrono::Duration::days(w * 7);
            let end = (start + chrono::Duration::days(6)).min(next_month - chrono::Duration::days(1));
            WeeklyBucket {
                week_label: format!("W{}", w + 1),
                date_range: format!("{} — {}", start.format("%b %d"), end.format("%b %d")),
                events: 0,
                incidents: 0,
                decisions: 0,
                blocks: 0,
                unique_attackers: 0,
            }
        })
        .collect();
    let mut weekly_ips: Vec<HashSet<String>> = vec![HashSet::new(); 4];

    for day_offset in 0..days_in_month {
        let date = month_start + chrono::Duration::days(day_offset as i64);
        let date_str = date.format("%Y-%m-%d").to_string();
        let week_idx = (day_offset / 7).min(3) as usize;

        // Count events
        let events_path = data_dir.join(format!("events-{date_str}.jsonl"));
        if events_path.exists() {
            let count = count_jsonl_lines(&events_path);
            total_events += count;
            weekly[week_idx].events += count;
            if count > 0 {
                days_with_data += 1;
            }
        }

        // Count incidents and extract metadata
        let incidents_path = data_dir.join(format!("incidents-{date_str}.jsonl"));
        if incidents_path.exists() {
            if let Ok(file) = std::fs::File::open(&incidents_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                        total_incidents += 1;
                        weekly[week_idx].incidents += 1;

                        // Extract detector from incident_id
                        if let Some(iid) = val["incident_id"].as_str() {
                            let detector = mitre::detector_from_incident_id(iid);
                            *incidents_by_detector.entry(detector.to_string()).or_default() += 1;
                        }

                        // Extract attacker IPs
                        if let Some(entities) = val["entities"].as_array() {
                            for entity in entities {
                                if entity["type"].as_str() == Some("ip") {
                                    if let Some(ip) = entity["value"].as_str() {
                                        attacker_ips.insert(ip.to_string());
                                        weekly_ips[week_idx].insert(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Count decisions
        let decisions_path = data_dir.join(format!("decisions-{date_str}.jsonl"));
        if decisions_path.exists() {
            if let Ok(file) = std::fs::File::open(&decisions_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(entry) = serde_json::from_str::<DecisionEntry>(&line) {
                        total_decisions += 1;
                        weekly[week_idx].decisions += 1;
                        if entry.action_type == "block_ip" {
                            total_blocks += 1;
                            weekly[week_idx].blocks += 1;
                        }
                    }
                }
            }
        }
    }

    // Fill weekly unique attackers
    for (i, ips) in weekly_ips.iter().enumerate() {
        weekly[i].unique_attackers = ips.len() as u64;
    }

    // Top detector
    let top_detector = incidents_by_detector
        .iter()
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.clone())
        .unwrap_or_else(|| "none".to_string());

    // MITRE coverage
    let mitre_coverage = build_mitre_coverage(&incidents_by_detector, profiles);

    let top_mitre_technique = mitre_coverage
        .techniques_seen
        .first()
        .map(|t| format!("{} ({})", t.technique_id, t.technique_name))
        .unwrap_or_else(|| "none".to_string());

    // Build top attackers from profiles
    let mut month_profiles: Vec<&AttackerProfile> = profiles
        .values()
        .filter(|p| {
            p.visit_dates
                .iter()
                .any(|d| d.starts_with(month))
        })
        .collect();
    month_profiles.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let top_attackers: Vec<AttackerSummaryCompact> = month_profiles
        .iter()
        .take(20)
        .map(|p| {
            let action = if p.total_blocks > 0 {
                "blocked"
            } else if p.total_honeypot_diversions > 0 {
                "honeypot"
            } else if p.total_monitors > 0 {
                "monitoring"
            } else {
                "observed"
            };
            AttackerSummaryCompact {
                ip: p.ip.clone(),
                risk_score: p.risk_score,
                country: p
                    .geo
                    .as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_default(),
                total_incidents: p.total_incidents,
                detectors: p.detectors_triggered.iter().cloned().collect(),
                mitre_techniques: p.mitre_techniques.iter().cloned().collect(),
                action_taken: action.to_string(),
                dna_hash: p.dna.hash.chars().take(12).collect(),
                pattern_class: p.dna.pattern_class.clone(),
            }
        })
        .collect();

    // Geographic distribution
    let geo = build_geo_distribution(&month_profiles);

    // Unique countries
    let unique_countries = geo.by_country.len() as u64;

    // Honeypot intelligence
    let honeypot = build_honeypot_intel(&month_profiles);

    // Campaign detection (DNA + IOC correlation from attacker_intel engine)
    let month_profiles_map: HashMap<String, AttackerProfile> = month_profiles
        .iter()
        .map(|p| (p.ip.clone(), (*p).clone()))
        .collect();
    let campaigns = attacker_intel::detect_campaigns(&month_profiles_map);

    // Mesh summary (from profiles)
    let mesh = MeshSummary {
        threats_shared: month_profiles.iter().map(|p| p.mesh_peer_confirmations as u64).sum(),
        threats_received: month_profiles.iter().map(|p| p.mesh_signals_received as u64).sum(),
        peer_count: 0, // would need live mesh state
    };

    let avg_incidents_per_day = if days_with_data > 0 {
        total_incidents as f64 / days_with_data as f64
    } else {
        0.0
    };

    Ok(MonthlyThreatReport {
        generated_at: Utc::now(),
        month: month.to_string(),
        executive_summary: ExecutiveSummary {
            total_events,
            total_incidents,
            total_decisions,
            total_blocks,
            unique_attackers: attacker_ips.len() as u64,
            unique_countries,
            top_detector,
            top_mitre_technique,
            avg_incidents_per_day,
            days_with_data,
        },
        top_attackers,
        campaigns,
        mitre_coverage,
        geographic_distribution: geo,
        honeypot_intelligence: honeypot,
        mesh_network: mesh,
        weekly_trends: weekly,
    })
}

/// Write report as JSON and Markdown to the data directory.
pub fn write_report(report: &MonthlyThreatReport, data_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let json_path = data_dir.join(format!("monthly-report-{}.json", report.month));
    let md_path = data_dir.join(format!("monthly-report-{}.md", report.month));

    let json = serde_json::to_string_pretty(report).context("serialize report")?;
    std::fs::write(&json_path, json).context("write JSON report")?;

    let md = render_markdown(report);
    std::fs::write(&md_path, md).context("write Markdown report")?;

    Ok((json_path, md_path))
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

fn render_markdown(r: &MonthlyThreatReport) -> String {
    let mut md = String::with_capacity(8192);
    let s = &r.executive_summary;

    md.push_str(&format!(
        "# InnerWarden Threat Report — {}\n\n",
        r.month
    ));
    md.push_str(&format!(
        "*Generated: {}*\n\n",
        r.generated_at.format("%Y-%m-%d %H:%M UTC")
    ));

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n|--------|-------|\n"));
    md.push_str(&format!("| Total Events | {} |\n", s.total_events));
    md.push_str(&format!("| Total Incidents | {} |\n", s.total_incidents));
    md.push_str(&format!("| Total Decisions | {} |\n", s.total_decisions));
    md.push_str(&format!("| Total Blocks | {} |\n", s.total_blocks));
    md.push_str(&format!("| Unique Attackers | {} |\n", s.unique_attackers));
    md.push_str(&format!("| Unique Countries | {} |\n", s.unique_countries));
    md.push_str(&format!("| Top Detector | {} |\n", s.top_detector));
    md.push_str(&format!("| Top MITRE Technique | {} |\n", s.top_mitre_technique));
    md.push_str(&format!(
        "| Avg Incidents/Day | {:.1} |\n",
        s.avg_incidents_per_day
    ));
    md.push_str(&format!("| Days with Data | {} |\n\n", s.days_with_data));

    // Top Attackers
    if !r.top_attackers.is_empty() {
        md.push_str("## Top Attackers\n\n");
        md.push_str("| # | IP | Risk | Country | Incidents | Pattern | Action |\n");
        md.push_str("|---|-----|------|---------|-----------|---------|--------|\n");
        for (i, a) in r.top_attackers.iter().enumerate() {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} | {} |\n",
                i + 1,
                a.ip,
                a.risk_score,
                a.country,
                a.total_incidents,
                a.pattern_class,
                a.action_taken
            ));
        }
        md.push('\n');
    }

    // MITRE ATT&CK Coverage
    if !r.mitre_coverage.techniques_seen.is_empty() {
        md.push_str("## MITRE ATT&CK Coverage\n\n");
        md.push_str("| Technique | Tactic | Incidents | Attackers |\n");
        md.push_str("|-----------|--------|-----------|----------|\n");
        for t in &r.mitre_coverage.techniques_seen {
            md.push_str(&format!(
                "| {} ({}) | {} | {} | {} |\n",
                t.technique_id, t.technique_name, t.tactic, t.incident_count, t.attacker_count
            ));
        }
        md.push('\n');
    }

    // Geographic Distribution
    if !r.geographic_distribution.by_country.is_empty() {
        md.push_str("## Geographic Distribution\n\n");
        md.push_str("| Country | Attackers | Incidents |\n");
        md.push_str("|---------|-----------|----------|\n");
        for c in r.geographic_distribution.by_country.iter().take(15) {
            md.push_str(&format!(
                "| {} ({}) | {} | {} |\n",
                c.country, c.country_code, c.attacker_count, c.incident_count
            ));
        }
        md.push('\n');
    }

    // Campaigns
    if !r.campaigns.is_empty() {
        md.push_str("## Detected Campaigns\n\n");
        for c in &r.campaigns {
            md.push_str(&format!(
                "### {} — {} (confidence: {})\n\n",
                c.campaign_id, c.correlation_type, c.confidence
            ));
            md.push_str(&format!("- **Summary:** {}\n", c.summary));
            md.push_str(&format!(
                "- **IPs ({}):** {}\n",
                c.member_ips.len(),
                c.member_ips.join(", ")
            ));
            if !c.shared_dna_signature.is_empty() {
                md.push_str(&format!(
                    "- **DNA Signature:** `{}`\n",
                    c.shared_dna_signature
                ));
            }
            if !c.shared_iocs.is_empty() {
                md.push_str(&format!(
                    "- **Shared IOCs:** {}\n",
                    c.shared_iocs.join(", ")
                ));
            }
            if !c.shared_detectors.is_empty() {
                md.push_str(&format!(
                    "- **Detectors:** {}\n",
                    c.shared_detectors.join(", ")
                ));
            }
            md.push('\n');
        }
    }

    // Honeypot Intelligence
    if r.honeypot_intelligence.total_sessions > 0 {
        md.push_str("## Honeypot Intelligence\n\n");
        md.push_str(&format!(
            "- **Sessions:** {} from {} unique IPs\n",
            r.honeypot_intelligence.total_sessions, r.honeypot_intelligence.unique_ips
        ));
        if !r.honeypot_intelligence.top_credentials.is_empty() {
            md.push_str("\n**Top Credentials:**\n\n");
            md.push_str("| Username | Password | Count |\n");
            md.push_str("|----------|----------|-------|\n");
            for (u, p, c) in r.honeypot_intelligence.top_credentials.iter().take(10) {
                md.push_str(&format!("| `{}` | `{}` | {} |\n", u, p, c));
            }
        }
        if !r.honeypot_intelligence.top_commands.is_empty() {
            md.push_str("\n**Top Commands:**\n\n");
            for (cmd, count) in r.honeypot_intelligence.top_commands.iter().take(10) {
                md.push_str(&format!("- `{}` ({}x)\n", cmd, count));
            }
        }
        md.push('\n');
    }

    // Weekly Trends
    if !r.weekly_trends.is_empty() {
        md.push_str("## Weekly Trends\n\n");
        md.push_str("| Week | Date Range | Events | Incidents | Blocks | Attackers |\n");
        md.push_str("|------|-----------|--------|-----------|--------|----------|\n");
        for w in &r.weekly_trends {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                w.week_label,
                w.date_range,
                w.events,
                w.incidents,
                w.blocks,
                w.unique_attackers
            ));
        }
        md.push('\n');
    }

    md.push_str("---\n\n*Report generated by InnerWarden.*\n");
    md
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn count_jsonl_lines(path: &Path) -> u64 {
    std::fs::File::open(path)
        .map(|f| BufReader::new(f).lines().count() as u64)
        .unwrap_or(0)
}

fn build_mitre_coverage(
    incidents_by_detector: &BTreeMap<String, u64>,
    profiles: &HashMap<String, AttackerProfile>,
) -> MitreCoverage {
    let mut techniques: BTreeMap<String, (String, String, String, u64, HashSet<String>)> =
        BTreeMap::new();
    let mut tactics_counts: BTreeMap<String, u64> = BTreeMap::new();

    for (detector, count) in incidents_by_detector {
        if let Some(mapping) = mitre::map_detector(detector) {
            let key = mapping.technique_id.to_string();
            let entry = techniques.entry(key.clone()).or_insert_with(|| {
                (
                    mapping.technique_id.to_string(),
                    mapping.technique_name.to_string(),
                    mapping.tactic.to_string(),
                    0,
                    HashSet::new(),
                )
            });
            entry.3 += count;
            *tactics_counts.entry(mapping.tactic.to_string()).or_default() += count;
        }
    }

    // Count attackers per technique from profiles
    for profile in profiles.values() {
        for tech in &profile.mitre_techniques {
            // tech format: "T1110 (Brute Force)"
            if let Some(tid) = tech.split(' ').next() {
                if let Some(entry) = techniques.get_mut(tid) {
                    entry.4.insert(profile.ip.clone());
                }
            }
        }
    }

    let mut seen: Vec<MitreTechniqueSeen> = techniques
        .into_values()
        .map(|(tid, name, tactic, count, attackers)| MitreTechniqueSeen {
            technique_id: tid,
            technique_name: name,
            tactic,
            incident_count: count,
            attacker_count: attackers.len() as u64,
        })
        .collect();
    seen.sort_by(|a, b| b.incident_count.cmp(&a.incident_count));

    let total = seen.len();
    MitreCoverage {
        techniques_seen: seen,
        tactics_counts,
        total_unique_techniques: total,
    }
}

fn build_geo_distribution(profiles: &[&AttackerProfile]) -> GeoDistribution {
    let mut by_country: BTreeMap<String, (String, u64, u64)> = BTreeMap::new();

    for p in profiles {
        if let Some(geo) = &p.geo {
            if !geo.country_code.is_empty() {
                let entry = by_country
                    .entry(geo.country_code.clone())
                    .or_insert_with(|| (geo.country.clone(), 0, 0));
                entry.1 += 1;
                entry.2 += p.total_incidents as u64;
            }
        }
    }

    let mut stats: Vec<CountryStats> = by_country
        .into_iter()
        .map(|(code, (name, attackers, incidents))| CountryStats {
            country_code: code,
            country: name,
            attacker_count: attackers,
            incident_count: incidents,
        })
        .collect();
    stats.sort_by(|a, b| b.attacker_count.cmp(&a.attacker_count));

    GeoDistribution { by_country: stats }
}

fn build_honeypot_intel(profiles: &[&AttackerProfile]) -> HoneypotIntel {
    let mut total_sessions: u64 = 0;
    let mut unique_ips: HashSet<String> = HashSet::new();
    let mut cred_counts: HashMap<(String, String), u64> = HashMap::new();
    let mut cmd_counts: HashMap<String, u64> = HashMap::new();
    let mut tools: HashSet<String> = HashSet::new();

    for p in profiles {
        if p.honeypot_sessions > 0 {
            total_sessions += p.honeypot_sessions as u64;
            unique_ips.insert(p.ip.clone());

            for (user, pass) in &p.credentials_attempted {
                *cred_counts.entry((user.clone(), pass.clone())).or_default() += 1;
            }
            for cmd in &p.commands_executed {
                *cmd_counts.entry(cmd.clone()).or_default() += 1;
            }
            for tool in &p.dna.tool_signatures {
                tools.insert(tool.clone());
            }
        }
    }

    let mut top_credentials: Vec<(String, String, u64)> = cred_counts
        .into_iter()
        .map(|((u, p), c)| (u, p, c))
        .collect();
    top_credentials.sort_by(|a, b| b.2.cmp(&a.2));
    top_credentials.truncate(15);

    let mut top_commands: Vec<(String, u64)> = cmd_counts.into_iter().collect();
    top_commands.sort_by(|a, b| b.1.cmp(&a.1));
    top_commands.truncate(15);

    HoneypotIntel {
        total_sessions,
        unique_ips: unique_ips.len() as u64,
        top_credentials,
        top_commands,
        tool_signatures: tools.into_iter().collect(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacker_intel;
    use std::collections::BTreeSet;

    fn make_profile(ip: &str, risk: u8, detectors: &[&str]) -> AttackerProfile {
        let mut p = attacker_intel::new_profile(ip, Utc::now());
        p.risk_score = risk;
        p.total_incidents = risk as u32; // ensure non-zero for campaign detection
        for d in detectors {
            p.detectors_triggered.insert(d.to_string());
        }
        p.visit_dates.push("2026-03-15".to_string());
        p
    }

    #[test]
    fn report_exists_returns_false_for_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!report_exists(dir.path(), "2026-03"));
    }

    #[test]
    fn available_months_finds_reports() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("monthly-report-2026-03.json"),
            "{}",
        )
        .unwrap();
        let months = available_months(dir.path());
        assert!(months.contains(&"2026-03".to_string()));
    }

    #[test]
    fn campaign_detection_uses_dna_engine() {
        let mut profiles = HashMap::new();
        let p1 = make_profile("1.1.1.1", 80, &["ssh_bruteforce", "port_scan", "credential_stuffing"]);
        let p2 = make_profile("2.2.2.2", 70, &["ssh_bruteforce", "port_scan", "credential_stuffing"]);
        let p3 = make_profile("3.3.3.3", 50, &["web_scan"]);
        profiles.insert("1.1.1.1".into(), p1);
        profiles.insert("2.2.2.2".into(), p2);
        profiles.insert("3.3.3.3".into(), p3);

        let campaigns = attacker_intel::detect_campaigns(&profiles);
        // p1 and p2 share DNA signature (same detectors)
        assert!(!campaigns.is_empty());
        let camp = &campaigns[0];
        assert_eq!(camp.member_ips.len(), 2);
    }

    #[test]
    fn empty_profiles_no_campaigns() {
        let profiles = HashMap::new();
        let campaigns = attacker_intel::detect_campaigns(&profiles);
        assert!(campaigns.is_empty());
    }

    #[test]
    fn generate_monthly_empty_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        assert_eq!(report.executive_summary.total_events, 0);
        assert_eq!(report.month, "2026-03");
    }

    #[test]
    fn markdown_renders_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        let md = render_markdown(&report);
        assert!(md.contains("# InnerWarden Threat Report"));
        assert!(md.contains("2026-03"));
    }

    #[test]
    fn write_report_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        let (json_path, md_path) = write_report(&report, dir.path()).unwrap();
        assert!(json_path.exists());
        assert!(md_path.exists());
    }
}
