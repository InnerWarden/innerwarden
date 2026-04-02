//! Sigma-compatible rule engine for log-based detection.
//!
//! Loads Sigma rules from `rules/sigma/*.yml` and applies them to incoming
//! events. Sigma is the open standard for log-based detection rules, with
//! thousands of community rules available at https://github.com/SigmaHQ/sigma.
//!
//! Simplified Sigma format supported:
//! ```yaml
//! title: Suspicious Cron Modification
//! id: SIGMA-001
//! status: production
//! level: high
//! logsource:
//!   product: linux
//!   category: file_change
//! detection:
//!   selection:
//!     kind|contains: "crontab"
//!     summary|contains: "modified"
//!   condition: selection
//! tags:
//!   - persistence
//!   - t1053
//! ```
//!
//! Supported field modifiers: `|contains`, `|startswith`, `|endswith`, `|re`.
//! Condition: "selection" (AND of all fields in selection block).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use tracing::{debug, info, warn};

use innerwarden_core::{event::Event, event::Severity, incident::Incident};

// ---------------------------------------------------------------------------
// Rule structures
// ---------------------------------------------------------------------------

/// A Sigma detection rule.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub level: Severity,
    /// Field matchers: field_name → (modifier, value).
    pub selection: Vec<FieldMatcher>,
    pub tags: Vec<String>,
}

/// A field matcher for Sigma detection.
#[derive(Debug, Clone)]
pub struct FieldMatcher {
    /// Event field to check: "kind", "source", "summary", or "details.X"
    pub field: String,
    /// Match operation.
    pub op: MatchOp,
    /// Value(s) to match against.
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum MatchOp {
    /// Exact match (or any of values).
    Equals,
    /// Substring match (case-insensitive).
    Contains,
    /// Starts with (case-insensitive).
    StartsWith,
    /// Ends with (case-insensitive).
    EndsWith,
    /// Regex match.
    Regex,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

pub struct SigmaRuleDetector {
    host: String,
    rules: Vec<SigmaRule>,
    /// Cooldown per rule ID to suppress re-alerts.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
    rules_dir: PathBuf,
}

impl SigmaRuleDetector {
    pub fn new(host: impl Into<String>, rules_dir: &Path, cooldown_seconds: u64) -> Self {
        let rules = load_sigma_rules(rules_dir);
        info!(rules = rules.len(), "Sigma rule engine loaded");
        Self {
            host: host.into(),
            rules,
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            rules_dir: rules_dir.to_path_buf(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if self.rules.is_empty() {
            return None;
        }

        // Skip events from InnerWarden's own processes (uid 998 or innerwarden comm).
        // Without this, the agent's integrity checks trigger Sigma rules (e.g., SIGMA-004
        // fires when the sensor reads /etc/shadow for hash verification).
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        if super::allowlists::is_innerwarden_process(uid, comm)
            || super::allowlists::comm_in_allowlist(comm, super::allowlists::SENSITIVE_FILE_READERS)
        {
            return None;
        }

        // Skip system operations that trigger many Sigma rules:
        // - file.read_access on /etc/profile.d (bash sourcing profiles on login)
        // - shell.command_exec from cron/systemd/cloud-init
        if event.kind == "file.read_access" {
            let path = event
                .details
                .get("filename")
                .or_else(|| event.details.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if path.starts_with("/etc/profile.d/")
                || path.starts_with("/etc/skel/")
                || path.starts_with("/etc/bash_completion.d/")
            {
                return None;
            }
        }

        let now = event.ts;

        // Sigma rules suppressed because they are too noisy on production Linux
        // servers. These fire on normal operations (cron, builds, logins).
        const SUPPRESSED_RULES: &[&str] = &[
            // "Inline Python Execution - Spawn Shell Via OS System Library"
            // Fires on ANY /bin/sh -c command, including ip neigh, cron jobs, etc.
            "2d2f44ff-4611-4778-a8fc-323a0e9850cc",
            // "Linux Shell Pipe to Shell" — fires on normal shell pipelines
            "ab75c0b8-4e80-4940-b3f1-0e8ddf5ae1f3",
        ];

        for rule in &self.rules {
            if SUPPRESSED_RULES.contains(&rule.id.as_str()) {
                continue;
            }
            // Cooldown check
            if let Some(&last) = self.alerted.get(&rule.id) {
                if now - last < self.cooldown {
                    continue;
                }
            }

            // Check if ALL field matchers match (AND condition)
            if rule.selection.iter().all(|m| matches_field(event, m)) {
                self.alerted.insert(rule.id.clone(), now);

                let mut tags = vec!["sigma".to_string()];
                tags.extend(rule.tags.iter().cloned());

                // Prune stale cooldowns
                if self.alerted.len() > 5000 {
                    let cutoff = now - self.cooldown;
                    self.alerted.retain(|_, ts| *ts > cutoff);
                }

                return Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!("sigma:{}:{}", rule.id, now.format("%Y-%m-%dT%H:%MZ")),
                    severity: rule.level.clone(),
                    title: format!("Sigma rule matched: {}", rule.title),
                    summary: format!(
                        "Sigma rule {} ({}) matched event kind='{}' source='{}': {}",
                        rule.id, rule.title, event.kind, event.source, event.summary
                    ),
                    evidence: serde_json::json!([{
                        "kind": "sigma_rule",
                        "rule_id": rule.id,
                        "rule_title": rule.title,
                        "event_kind": event.kind,
                        "event_source": event.source,
                        "event_summary": event.summary,
                    }]),
                    recommended_checks: vec![
                        format!("Review Sigma rule {} for context", rule.id),
                        "Investigate the source event for additional indicators".to_string(),
                    ],
                    tags,
                    entities: event.entities.clone(),
                });
            }
        }

        None
    }

    /// Number of loaded rules.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Reload rules from disk.
    #[allow(dead_code)]
    pub fn reload_rules(&mut self) {
        self.rules = load_sigma_rules(&self.rules_dir);
        info!(rules = self.rules.len(), "Sigma rules reloaded");
    }
}

// ---------------------------------------------------------------------------
// Field matching
// ---------------------------------------------------------------------------

fn matches_field(event: &Event, matcher: &FieldMatcher) -> bool {
    let field_value = extract_field(event, &matcher.field);
    let field_value = field_value.as_deref().unwrap_or("");

    matcher.values.iter().any(|expected| {
        match matcher.op {
            MatchOp::Equals => field_value.eq_ignore_ascii_case(expected),
            MatchOp::Contains => field_value
                .to_lowercase()
                .contains(&expected.to_lowercase()),
            MatchOp::StartsWith => field_value
                .to_lowercase()
                .starts_with(&expected.to_lowercase()),
            MatchOp::EndsWith => field_value
                .to_lowercase()
                .ends_with(&expected.to_lowercase()),
            MatchOp::Regex => {
                // Simple wildcard-based matching (no regex crate dependency).
                // Supports * as glob. For full regex, use the agent-side correlation engine.
                let pattern = expected.replace('*', "");
                field_value.to_lowercase().contains(&pattern.to_lowercase())
            }
        }
    })
}

/// Map Sigma standard field names to InnerWarden event fields.
/// This allows importing community Sigma rules (SigmaHQ) without modification.
fn alias_field(field: &str) -> &str {
    match field {
        // Process creation fields (Sigma process_creation category)
        "Image" | "image" => "details.filename",
        "CommandLine" | "commandline" | "command_line" => "details.command",
        "ParentImage" | "parentimage" => "details.parent",
        "ParentCommandLine" | "parentcommandline" => "details.parent_command",
        "User" | "user" => "details.user",
        "OriginalFileName" | "originalfilename" => "details.filename",
        "CurrentDirectory" | "currentdirectory" => "details.cwd",
        "Product" | "product" => "source",
        "Category" | "category" => "kind",
        // File event fields
        "TargetFilename" | "targetfilename" => "details.filename",
        // Network fields
        "DestinationIp" | "destinationip" | "dst_ip" => "details.dst_ip",
        "DestinationPort" | "destinationport" | "dst_port" => "details.dst_port",
        "SourceIp" | "sourceip" | "src_ip" => "details.src_ip",
        // Auditd fields
        "type" => "kind",
        "exe" => "details.filename",
        "key" | "a0" | "a1" | "a2" | "a3" => field, // pass through
        // Already correct format
        _ => field,
    }
}

/// Extract a field value from an event.
/// Supports: "kind", "source", "summary", "host", "details.X" (nested JSON).
/// Also resolves Sigma field aliases (Image, CommandLine, etc).
fn extract_field(event: &Event, field: &str) -> Option<String> {
    let field = alias_field(field);
    match field {
        "kind" => Some(event.kind.clone()),
        "source" => Some(event.source.clone()),
        "summary" => Some(event.summary.clone()),
        "host" => Some(event.host.clone()),
        "severity" => Some(format!("{:?}", event.severity).to_lowercase()),
        _ if field.starts_with("details.") => {
            let detail_key = &field["details.".len()..];
            event.details.get(detail_key).and_then(|v| {
                if v.is_string() {
                    v.as_str().map(String::from)
                } else {
                    Some(v.to_string())
                }
            })
        }
        _ => {
            // Try as details key directly (for pass-through fields like "a0")
            event.details.get(field).and_then(|v| {
                if v.is_string() {
                    v.as_str().map(String::from)
                } else {
                    Some(v.to_string())
                }
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Rule loading
// ---------------------------------------------------------------------------

fn load_sigma_rules(rules_dir: &Path) -> Vec<SigmaRule> {
    let mut rules = Vec::new();

    // Recursively walk the rules directory (supports subdirectories)
    load_sigma_dir(rules_dir, &mut rules);

    if rules.is_empty() {
        info!("No custom Sigma rules found, using built-in rules only");
    } else {
        info!(count = rules.len(), "Loaded custom Sigma rules from disk");
    }

    rules.extend(builtin_sigma_rules());
    rules
}

fn load_sigma_dir(dir: &Path, rules: &mut Vec<SigmaRule>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            load_sigma_dir(&path, rules);
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_sigma_yaml(&content) {
                Some(rule) => {
                    debug!(id = %rule.id, title = %rule.title, "loaded Sigma rule");
                    rules.push(rule);
                }
                None => {
                    // Many community rules use complex conditions we don't support yet — skip silently
                }
            },
            Err(e) => warn!(path = %path.display(), "failed to read Sigma rule: {e}"),
        }
    }
}

/// Parse a Sigma YAML rule.
/// Supports: single selection, multiple selections (selection_1, selection_2),
/// filters (selection and not filter), 1 of selection*, all of selection*.
fn parse_sigma_yaml(content: &str) -> Option<SigmaRule> {
    let mut id = String::new();
    let mut title = String::new();
    let mut level = Severity::Medium;
    let mut tags = Vec::new();

    // Track all named sections: selection, selection_1, filter, etc.
    let mut sections: std::collections::HashMap<String, Vec<FieldMatcher>> =
        std::collections::HashMap::new();
    let mut _condition = String::new();
    let mut current_section: Option<String> = None;
    let mut in_tags = false;
    let mut in_detection = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect indent level to know when we leave a section
        let indent = line.len() - line.trim_start().len();

        // Top-level keys (no/low indent)
        if indent == 0 {
            current_section = None;
            in_tags = false;
            in_detection = false;
        }

        if let Some(v) = trimmed.strip_prefix("id:") {
            id = v.trim().trim_matches('"').trim_matches('\'').to_string();
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("title:") {
            title = v.trim().trim_matches('"').trim_matches('\'').to_string();
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("level:") {
            level = match v.trim() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                "informational" => Severity::Info,
                _ => Severity::Medium,
            };
            continue;
        }
        if trimmed == "detection:" {
            in_detection = true;
            in_tags = false;
            continue;
        }
        if trimmed == "tags:" || trimmed.starts_with("tags:") {
            in_tags = true;
            in_detection = false;
            current_section = None;
            continue;
        }
        if trimmed.starts_with("logsource:")
            || trimmed.starts_with("status:")
            || trimmed.starts_with("description:")
            || trimmed.starts_with("references:")
            || trimmed.starts_with("author:")
            || trimmed.starts_with("date:")
            || trimmed.starts_with("modified:")
            || trimmed.starts_with("falsepositives:")
        {
            in_detection = false;
            in_tags = false;
            current_section = None;
            continue;
        }

        // Inside detection block
        if in_detection {
            if let Some(v) = trimmed.strip_prefix("condition:") {
                _condition = v.trim().to_string();
                current_section = None;
                continue;
            }

            // Skip logsource sub-fields
            if trimmed.starts_with("product:")
                || trimmed.starts_with("category:")
                || trimmed.starts_with("service:")
            {
                continue;
            }

            // Named section header (selection, selection_1, filter, etc.)
            if trimmed.ends_with(':')
                && !trimmed.contains('|')
                && indent <= 8
                && !trimmed.starts_with('-')
            {
                let name = trimmed.trim_end_matches(':').to_string();
                if name.starts_with("selection") || name.starts_with("filter") {
                    current_section = Some(name.clone());
                    sections.entry(name).or_default();
                    continue;
                }
            }

            // Parse fields inside current section
            if let Some(ref sec) = current_section {
                // List item
                if let Some(rest) = trimmed.strip_prefix("- ") {
                    let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                    if !val.is_empty() {
                        if let Some(matchers) = sections.get_mut(sec) {
                            if let Some(last) = matchers.last_mut() {
                                last.values.push(val);
                            }
                        }
                    }
                    continue;
                }

                // Field: value
                if trimmed.contains(':') {
                    if let Some((field_spec, value)) = trimmed.split_once(':') {
                        let field_spec = field_spec.trim();
                        let value = value
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string();

                        let (field, op) = if let Some(f) = field_spec.strip_suffix("|contains") {
                            (f.to_string(), MatchOp::Contains)
                        } else if let Some(f) = field_spec.strip_suffix("|startswith") {
                            (f.to_string(), MatchOp::StartsWith)
                        } else if let Some(f) = field_spec.strip_suffix("|endswith") {
                            (f.to_string(), MatchOp::EndsWith)
                        } else if let Some(f) = field_spec.strip_suffix("|re") {
                            (f.to_string(), MatchOp::Regex)
                        } else if let Some(f) = field_spec.strip_suffix("|contains|all") {
                            (f.to_string(), MatchOp::Contains)
                        } else {
                            (field_spec.to_string(), MatchOp::Equals)
                        };

                        let values = if value.is_empty() {
                            vec![]
                        } else {
                            vec![value]
                        };
                        sections.entry(sec.clone()).or_default().push(FieldMatcher {
                            field,
                            op,
                            values,
                        });
                    }
                }
            }
        }

        // Parse tags
        if in_tags {
            if let Some(rest) = trimmed.strip_prefix("- ") {
                tags.push(rest.trim().trim_matches('"').trim_matches('\'').to_string());
            }
        }
    }

    // Build the final selection based on condition
    // Merge all selection* sections (OR between selections, AND within each)
    // For "selection and not filter": use selection, ignore filter (conservative)
    let mut selection: Vec<FieldMatcher> = Vec::new();

    if sections.contains_key("selection") && sections.len() == 1 {
        // Simple case: single selection
        selection = sections.remove("selection").unwrap_or_default();
    } else {
        // Multiple selections or complex conditions
        // Strategy: merge all selection* fields as OR (any match triggers)
        // This is conservative — may generate more alerts than intended
        // but never misses a true positive
        for (name, matchers) in &sections {
            if name.starts_with("selection") {
                selection.extend(matchers.iter().cloned());
            }
        }
    }

    if id.is_empty() || title.is_empty() || selection.is_empty() {
        return None;
    }

    Some(SigmaRule {
        id,
        title,
        level,
        selection,
        tags,
    })
}

// ---------------------------------------------------------------------------
// Built-in Sigma rules
// ---------------------------------------------------------------------------

fn builtin_sigma_rules() -> Vec<SigmaRule> {
    vec![
        SigmaRule {
            id: "SIGMA-001".into(),
            title: "Suspicious Cron Modification".into(),
            level: Severity::High,
            selection: vec![FieldMatcher {
                field: "kind".into(),
                op: MatchOp::Contains,
                values: vec!["crontab".into(), "cron".into()],
            }],
            tags: vec!["persistence".into(), "t1053".into()],
        },
        SigmaRule {
            id: "SIGMA-002".into(),
            title: "Systemd Service Created".into(),
            level: Severity::Medium,
            selection: vec![
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Contains,
                    values: vec!["systemd".into()],
                },
                FieldMatcher {
                    field: "summary".into(),
                    op: MatchOp::Contains,
                    values: vec!["created".into(), "new service".into()],
                },
            ],
            tags: vec!["persistence".into(), "t1543".into()],
        },
        SigmaRule {
            id: "SIGMA-003".into(),
            title: "SSH Authorized Keys Modified".into(),
            level: Severity::High,
            selection: vec![
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Contains,
                    values: vec!["file.write".into()],
                },
                FieldMatcher {
                    field: "summary".into(),
                    op: MatchOp::Contains,
                    values: vec!["authorized_keys".into()],
                },
            ],
            tags: vec!["persistence".into(), "t1098".into()],
        },
        SigmaRule {
            id: "SIGMA-004".into(),
            title: "Passwd or Shadow File Access".into(),
            level: Severity::High,
            selection: vec![
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Contains,
                    values: vec!["file.read".into()],
                },
                FieldMatcher {
                    field: "details.filename".into(),
                    op: MatchOp::Contains,
                    values: vec!["/etc/shadow".into()],
                },
            ],
            tags: vec!["credential_access".into(), "t1003".into()],
        },
        SigmaRule {
            id: "SIGMA-005".into(),
            title: "Process Executed from /tmp or /dev/shm".into(),
            level: Severity::Critical,
            selection: vec![
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Equals,
                    values: vec!["shell.command_exec".into()],
                },
                FieldMatcher {
                    field: "details.filename".into(),
                    op: MatchOp::StartsWith,
                    values: vec!["/tmp/".into(), "/dev/shm/".into(), "/var/tmp/".into()],
                },
            ],
            tags: vec!["execution".into(), "defense_evasion".into(), "t1059".into()],
        },
        SigmaRule {
            id: "SIGMA-006".into(),
            title: "Kernel Module Loaded".into(),
            level: Severity::High,
            selection: vec![
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Contains,
                    values: vec!["module".into()],
                },
                FieldMatcher {
                    field: "summary".into(),
                    op: MatchOp::Contains,
                    values: vec!["loaded".into(), "insmod".into(), "modprobe".into()],
                },
            ],
            tags: vec!["persistence".into(), "rootkit".into(), "t1547".into()],
        },
        SigmaRule {
            id: "SIGMA-007".into(),
            title: "User Added to Sudoers".into(),
            level: Severity::High,
            selection: vec![
                FieldMatcher {
                    field: "summary".into(),
                    op: MatchOp::Contains,
                    values: vec!["sudoers".into()],
                },
                FieldMatcher {
                    field: "kind".into(),
                    op: MatchOp::Contains,
                    values: vec!["file.write".into()],
                },
            ],
            tags: vec!["privilege_escalation".into(), "t1548".into()],
        },
        SigmaRule {
            id: "SIGMA-008".into(),
            title: "Docker Socket Accessed by Non-Root".into(),
            level: Severity::High,
            selection: vec![FieldMatcher {
                field: "details.filename".into(),
                op: MatchOp::Contains,
                values: vec!["docker.sock".into()],
            }],
            tags: vec![
                "privilege_escalation".into(),
                "container".into(),
                "t1611".into(),
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_event(kind: &str, source: &str, summary: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: source.into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: summary.into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        }
    }

    fn make_event_with_details(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn builtin_rules_load() {
        let rules = builtin_sigma_rules();
        assert!(rules.len() >= 8);
    }

    #[test]
    fn sigma_matches_cron_modification() {
        let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
        let ev = make_event(
            "crontab.modified",
            "audit",
            "crontab modified by user admin",
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("Cron"));
    }

    #[test]
    fn sigma_matches_tmp_execution() {
        let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
        let ev = make_event_with_details(
            "shell.command_exec",
            serde_json::json!({"filename": "/tmp/payload", "pid": 1234, "comm": "bash"}),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn sigma_matches_shadow_read() {
        let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
        let ev = make_event_with_details(
            "file.read_access",
            serde_json::json!({"filename": "/etc/shadow", "pid": 1234}),
        );
        let inc = det.process(&ev);
        assert!(inc.is_some());
    }

    #[test]
    fn sigma_no_match_normal_event() {
        let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
        let ev = make_event("ssh.login_failed", "auth_log", "Failed password for root");
        let inc = det.process(&ev);
        assert!(inc.is_none());
    }

    #[test]
    fn sigma_cooldown_suppresses_duplicate() {
        let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
        let ev = make_event("crontab.modified", "audit", "crontab modified");
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none()); // suppressed by cooldown
    }

    #[test]
    fn parse_sigma_yaml_basic() {
        let yaml = r#"
title: Test Rule
id: TEST-001
level: high
detection:
  selection:
    kind|contains: "crontab"
    summary|contains: "modified"
  condition: selection
tags:
  - persistence
  - t1053
"#;
        let rule = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(rule.id, "TEST-001");
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.selection.len(), 2);
        assert_eq!(rule.tags.len(), 2);
    }

    #[test]
    fn field_extraction() {
        let ev = make_event_with_details(
            "shell.command_exec",
            serde_json::json!({"filename": "/tmp/test", "pid": 42}),
        );
        assert_eq!(
            extract_field(&ev, "kind"),
            Some("shell.command_exec".into())
        );
        assert_eq!(
            extract_field(&ev, "details.filename"),
            Some("/tmp/test".into())
        );
        assert_eq!(extract_field(&ev, "details.pid"), Some("42".into()));
        assert_eq!(extract_field(&ev, "nonexistent"), None);
    }

    #[test]
    fn match_op_contains() {
        let matcher = FieldMatcher {
            field: "kind".into(),
            op: MatchOp::Contains,
            values: vec!["cron".into()],
        };
        let ev = make_event("crontab.modified", "audit", "");
        assert!(matches_field(&ev, &matcher));
    }

    #[test]
    fn match_op_startswith() {
        let matcher = FieldMatcher {
            field: "details.filename".into(),
            op: MatchOp::StartsWith,
            values: vec!["/tmp/".into()],
        };
        let ev = make_event_with_details("exec", serde_json::json!({"filename": "/tmp/exploit"}));
        assert!(matches_field(&ev, &matcher));
    }

    #[test]
    fn match_op_equals() {
        let matcher = FieldMatcher {
            field: "kind".into(),
            op: MatchOp::Equals,
            values: vec!["shell.command_exec".into()],
        };
        let ev = make_event("shell.command_exec", "ebpf", "");
        assert!(matches_field(&ev, &matcher));

        let ev2 = make_event("file.read", "ebpf", "");
        assert!(!matches_field(&ev2, &matcher));
    }
}
