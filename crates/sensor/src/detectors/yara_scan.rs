//! Binary scanning detector using YAML-defined pattern rules.
//!
//! When eBPF detects execution of an unknown binary (`shell.command_exec`),
//! this detector reads the binary file, computes its SHA-256 hash, checks
//! against a known-good allowlist, and if unknown, scans content against
//! pattern rules for malware indicators.
//!
//! Rules are loaded from `rules/yara/*.yml` in a simple format:
//! ```yaml
//! id: MAL-001
//! name: Cryptominer XMRig
//! severity: critical
//! strings:
//!   - "stratum+tcp://"
//!   - "xmrig"
//!   - "--donate-level"
//! hex_patterns:
//!   - "48 8b 05 ?? ?? ?? ?? 48 89 c7"  # optional hex with wildcards
//! condition: any  # "any" or "all"
//! tags: [cryptominer, malware]
//! ```
//!
//! Pure Rust — no libyara dependency.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/// A binary scanning rule.
#[derive(Debug, Clone)]
pub struct ScanRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    /// ASCII string patterns to search for in the binary.
    pub strings: Vec<String>,
    /// Hex byte patterns (with ?? wildcards for any byte).
    pub hex_patterns: Vec<Vec<HexByte>>,
    /// "any" = at least one match, "all" = all patterns must match.
    pub condition: MatchCondition,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MatchCondition {
    Any,
    All,
}

/// A byte in a hex pattern: exact value or wildcard.
#[derive(Debug, Clone, Copy)]
pub enum HexByte {
    Exact(u8),
    Wildcard,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Maximum binary size to scan (10 MB). Larger files are skipped.
const MAX_SCAN_SIZE: u64 = 10 * 1024 * 1024;
/// Maximum number of hashes in the known-good allowlist.
const MAX_ALLOWLIST: usize = 50_000;

pub struct YaraScanDetector {
    host: String,
    rules: Vec<ScanRule>,
    /// SHA-256 hashes of known-good binaries (auto-populated on first exec).
    known_hashes: HashSet<String>,
    /// Cooldown per binary path.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
    /// Rules directory path.
    rules_dir: PathBuf,
}

impl YaraScanDetector {
    /// Create a new detector, loading rules from `rules_dir`.
    pub fn new(host: impl Into<String>, rules_dir: &Path, cooldown_seconds: u64) -> Self {
        let rules = load_rules(rules_dir);
        info!(rules = rules.len(), "YARA scanner loaded rules");
        Self {
            host: host.into(),
            rules,
            known_hashes: HashSet::new(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            rules_dir: rules_dir.to_path_buf(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process binary executions
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }
        if self.rules.is_empty() {
            return None;
        }

        let filename = event.details.get("filename").and_then(|v| v.as_str())?;
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip if not a real file path
        if filename.is_empty() || !filename.starts_with('/') {
            return None;
        }

        // Skip well-known system binaries by path prefix
        if is_trusted_path(filename) {
            return None;
        }

        // Cooldown check
        let now = event.ts;
        if let Some(&last) = self.alerted.get(filename) {
            if now - last < self.cooldown {
                return None;
            }
        }

        // Read binary and compute hash
        let binary_path = Path::new(filename);
        let metadata = std::fs::metadata(binary_path).ok()?;
        if metadata.len() > MAX_SCAN_SIZE || metadata.len() == 0 {
            return None;
        }

        let content = read_binary(binary_path)?;
        let hash = sha256_hex(&content);

        // Check allowlist
        if self.known_hashes.contains(&hash) {
            return None;
        }

        // Scan against rules
        let matched_rules = scan_content(&content, &self.rules);

        if matched_rules.is_empty() {
            // Binary is clean — add to known-good allowlist
            if self.known_hashes.len() < MAX_ALLOWLIST {
                self.known_hashes.insert(hash);
            }
            return None;
        }

        self.alerted.insert(filename.to_string(), now);

        // Build incident from matched rules
        let top_rule = &matched_rules[0];
        let all_rule_names: Vec<String> = matched_rules.iter().map(|r| r.id.clone()).collect();
        let all_tags: Vec<String> = matched_rules
            .iter()
            .flat_map(|r| r.tags.iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let mut tags = vec!["yara".to_string(), "malware_scan".to_string()];
        tags.extend(all_tags);

        // Prune stale entries
        if self.alerted.len() > 5000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "yara_scan:{}:{}:{}",
                top_rule.id,
                pid,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: top_rule.severity.clone(),
            title: format!(
                "Malware detected: {} in {} ({})",
                top_rule.name, filename, top_rule.id
            ),
            summary: format!(
                "Binary {} (SHA-256: {}) executed by {comm} (pid={pid}) matched {} \
                 scanning rules: {}. The file should be quarantined and the process killed.",
                filename,
                &hash[..16],
                matched_rules.len(),
                all_rule_names.join(", ")
            ),
            evidence: serde_json::json!([{
                "kind": "yara_scan",
                "filename": filename,
                "sha256": hash,
                "file_size": metadata.len(),
                "comm": comm,
                "pid": pid,
                "matched_rules": all_rule_names,
                "top_rule": {
                    "id": top_rule.id,
                    "name": top_rule.name,
                },
            }]),
            recommended_checks: vec![
                format!("Kill process: kill -9 {pid}"),
                format!("Quarantine binary: mv {filename} /var/quarantine/"),
                format!("Check hash on VirusTotal: {hash}"),
                "Investigate how the binary arrived on this host".to_string(),
                "Check for persistence mechanisms".to_string(),
            ],
            tags,
            entities: vec![EntityRef::path(filename)],
        })
    }

    /// Reload rules from disk.
    #[allow(dead_code)]
    pub fn reload_rules(&mut self) {
        self.rules = load_rules(&self.rules_dir);
        info!(rules = self.rules.len(), "YARA rules reloaded");
    }

    /// Number of loaded rules.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ---------------------------------------------------------------------------
// Scanning engine
// ---------------------------------------------------------------------------

/// Scan binary content against all rules. Returns matching rules.
fn scan_content<'a>(content: &[u8], rules: &'a [ScanRule]) -> Vec<&'a ScanRule> {
    let content_str = String::from_utf8_lossy(content);
    let content_lower = content_str.to_lowercase();

    rules
        .iter()
        .filter(|rule| {
            let string_matches: Vec<bool> = rule
                .strings
                .iter()
                .map(|s| content_lower.contains(&s.to_lowercase()))
                .collect();

            let hex_matches: Vec<bool> = rule
                .hex_patterns
                .iter()
                .map(|pattern| hex_pattern_match(content, pattern))
                .collect();

            let all_matches: Vec<bool> =
                string_matches.iter().chain(hex_matches.iter()).copied().collect();

            if all_matches.is_empty() {
                return false;
            }

            match rule.condition {
                MatchCondition::Any => all_matches.iter().any(|&m| m),
                MatchCondition::All => all_matches.iter().all(|&m| m),
            }
        })
        .collect()
}

/// Match a hex byte pattern (with wildcards) against binary content.
fn hex_pattern_match(content: &[u8], pattern: &[HexByte]) -> bool {
    if pattern.is_empty() || content.len() < pattern.len() {
        return false;
    }
    'outer: for start in 0..=(content.len() - pattern.len()) {
        for (i, hex_byte) in pattern.iter().enumerate() {
            match hex_byte {
                HexByte::Exact(b) => {
                    if content[start + i] != *b {
                        continue 'outer;
                    }
                }
                HexByte::Wildcard => {} // matches anything
            }
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Rule loading
// ---------------------------------------------------------------------------

/// Load all YAML rules from a directory.
fn load_rules(rules_dir: &Path) -> Vec<ScanRule> {
    let mut rules = Vec::new();

    let entries = match std::fs::read_dir(rules_dir) {
        Ok(e) => e,
        Err(_) => {
            // Directory doesn't exist yet — use built-in rules only
            return builtin_rules();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_rule_yaml(&content) {
                Some(rule) => {
                    debug!(id = %rule.id, name = %rule.name, "loaded YARA rule");
                    rules.push(rule);
                }
                None => warn!(path = %path.display(), "failed to parse YARA rule"),
            },
            Err(e) => warn!(path = %path.display(), "failed to read YARA rule: {e}"),
        }
    }

    // Always include built-in rules
    rules.extend(builtin_rules());
    rules
}

/// Parse a single YAML rule file.
fn parse_rule_yaml(content: &str) -> Option<ScanRule> {
    let val: serde_json::Value = serde_yaml_to_json(content)?;

    let id = val.get("id")?.as_str()?.to_string();
    let name = val.get("name")?.as_str()?.to_string();
    let severity = match val.get("severity").and_then(|v| v.as_str()).unwrap_or("high") {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::High,
    };

    let strings: Vec<String> = val
        .get("strings")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let hex_patterns: Vec<Vec<HexByte>> = val
        .get("hex_patterns")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(parse_hex_pattern)).collect())
        .unwrap_or_default();

    let condition = match val
        .get("condition")
        .and_then(|v| v.as_str())
        .unwrap_or("any")
    {
        "all" => MatchCondition::All,
        _ => MatchCondition::Any,
    };

    let tags: Vec<String> = val
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if strings.is_empty() && hex_patterns.is_empty() {
        return None;
    }

    Some(ScanRule {
        id,
        name,
        severity,
        strings,
        hex_patterns,
        condition,
        tags,
    })
}

/// Minimal YAML → JSON parser for our simple rule format.
/// Handles basic key: value, arrays with - prefix. No nested objects needed.
fn serde_yaml_to_json(yaml: &str) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    let mut current_array_key: Option<String> = None;
    let mut current_array: Vec<serde_json::Value> = Vec::new();

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Array item: "  - value"
        if let Some(rest) = trimmed.strip_prefix("- ") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            current_array.push(serde_json::Value::String(value.to_string()));
            continue;
        }

        // Flush previous array
        if let Some(key) = current_array_key.take() {
            if !current_array.is_empty() {
                map.insert(key, serde_json::Value::Array(current_array.clone()));
                current_array.clear();
            }
        }

        // Key: value or Key: (start of array)
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim();

            if value.is_empty() {
                // Start of array
                current_array_key = Some(key);
                current_array.clear();
            } else if value.starts_with('[') && value.ends_with(']') {
                // Inline array: [a, b, c]
                let inner = &value[1..value.len() - 1];
                let items: Vec<serde_json::Value> = inner
                    .split(',')
                    .map(|s| {
                        serde_json::Value::String(s.trim().trim_matches('"').trim_matches('\'').to_string())
                    })
                    .collect();
                map.insert(key, serde_json::Value::Array(items));
            } else {
                // Simple value
                let clean = value.trim_matches('"').trim_matches('\'');
                map.insert(key, serde_json::Value::String(clean.to_string()));
            }
        }
    }

    // Flush last array
    if let Some(key) = current_array_key {
        if !current_array.is_empty() {
            map.insert(key, serde_json::Value::Array(current_array));
        }
    }

    if map.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(map))
    }
}

/// Parse a hex pattern string like "48 8b 05 ?? ?? ?? ??" into HexBytes.
fn parse_hex_pattern(hex_str: &str) -> Vec<HexByte> {
    hex_str
        .split_whitespace()
        .filter_map(|token| {
            if token == "??" {
                Some(HexByte::Wildcard)
            } else {
                u8::from_str_radix(token, 16).ok().map(HexByte::Exact)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Built-in rules (always loaded)
// ---------------------------------------------------------------------------

fn builtin_rules() -> Vec<ScanRule> {
    vec![
        ScanRule {
            id: "MAL-001".into(),
            name: "XMRig Cryptominer".into(),
            severity: Severity::Critical,
            strings: vec![
                "stratum+tcp://".into(),
                "stratum+ssl://".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["cryptominer".into(), "xmrig".into()],
        },
        ScanRule {
            id: "MAL-002".into(),
            name: "Webshell Indicators".into(),
            severity: Severity::Critical,
            strings: vec![
                "c99shell".into(),
                "r57shell".into(),
                "WSO ".into(),
                "FilesMan".into(),
                "b374k".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["webshell".into()],
        },
        ScanRule {
            id: "MAL-003".into(),
            name: "ELF Packer/Obfuscation".into(),
            severity: Severity::High,
            strings: vec![
                "UPX!".into(),
            ],
            hex_patterns: vec![
                // UPX magic at typical offset
                parse_hex_pattern("55 50 58 21"),
            ],
            condition: MatchCondition::Any,
            tags: vec!["packer".into(), "upx".into()],
        },
        ScanRule {
            id: "MAL-004".into(),
            name: "Reverse Shell Strings in Binary".into(),
            severity: Severity::Critical,
            strings: vec![
                "/dev/tcp/".into(),
                "fsockopen".into(),
                "TCPSocket.open".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["reverse_shell".into()],
        },
        ScanRule {
            id: "MAL-005".into(),
            name: "Credential Harvesting Tool".into(),
            severity: Severity::Critical,
            strings: vec![
                "mimikatz".into(),
                "LaZagne".into(),
                "secretsdump".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["credential_theft".into()],
        },
        ScanRule {
            id: "MAL-006".into(),
            name: "Cobalt Strike Beacon".into(),
            severity: Severity::Critical,
            strings: vec![
                "beacon.dll".into(),
                "ReflectiveLoader".into(),
                "%%IMPORT%%".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["cobalt_strike".into(), "c2".into()],
        },
        ScanRule {
            id: "MAL-007".into(),
            name: "Metasploit Payload".into(),
            severity: Severity::Critical,
            strings: vec![
                "meterpreter".into(),
                "met_server".into(),
                "stdapi_".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["metasploit".into(), "meterpreter".into()],
        },
        ScanRule {
            id: "MAL-008".into(),
            name: "Linux Rootkit Strings".into(),
            severity: Severity::Critical,
            strings: vec![
                "hide_proc".into(),
                "hide_file".into(),
                "rootkit".into(),
                "invisible".into(),
            ],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec!["rootkit".into()],
        },
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_binary(path: &Path) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;
    Some(content)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Paths that are trusted and should never be scanned.
fn is_trusted_path(path: &str) -> bool {
    // System binaries
    path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/libexec/")
        || path.starts_with("/snap/")
        || path.starts_with("/nix/store/")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_pattern_parsing() {
        let pattern = parse_hex_pattern("48 8b 05 ?? ?? ?? ??");
        assert_eq!(pattern.len(), 7);
        assert!(matches!(pattern[0], HexByte::Exact(0x48)));
        assert!(matches!(pattern[3], HexByte::Wildcard));
    }

    #[test]
    fn hex_pattern_matching() {
        let content = vec![0x00, 0x48, 0x8b, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let pattern = parse_hex_pattern("48 8b 05 ?? ?? ?? ??");
        assert!(hex_pattern_match(&content, &pattern));
    }

    #[test]
    fn hex_pattern_no_match() {
        let content = vec![0x00, 0x49, 0x8b, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        let pattern = parse_hex_pattern("48 8b 05 ?? ?? ?? ??");
        assert!(!hex_pattern_match(&content, &pattern));
    }

    #[test]
    fn string_matching_case_insensitive() {
        let content = b"hello STRATUM+TCP://pool.example.com world";
        let rules = vec![ScanRule {
            id: "TEST-001".into(),
            name: "Test".into(),
            severity: Severity::High,
            strings: vec!["stratum+tcp://".into()],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec![],
        }];
        let matches = scan_content(content, &rules);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn condition_all_requires_all_patterns() {
        let content = b"xmrig stratum+tcp://pool.com";
        let rule_any = ScanRule {
            id: "TEST".into(),
            name: "Test".into(),
            severity: Severity::High,
            strings: vec!["xmrig".into(), "stratum+tcp://".into(), "nonexistent".into()],
            hex_patterns: vec![],
            condition: MatchCondition::Any,
            tags: vec![],
        };
        let rule_all = ScanRule {
            id: "TEST".into(),
            name: "Test".into(),
            severity: Severity::High,
            strings: vec!["xmrig".into(), "stratum+tcp://".into(), "nonexistent".into()],
            hex_patterns: vec![],
            condition: MatchCondition::All,
            tags: vec![],
        };
        assert_eq!(scan_content(content, &[rule_any]).len(), 1);
        assert_eq!(scan_content(content, &[rule_all]).len(), 0);
    }

    #[test]
    fn builtin_rules_load() {
        let rules = builtin_rules();
        assert!(rules.len() >= 8);
        assert!(rules.iter().any(|r| r.id == "MAL-001"));
    }

    #[test]
    fn yaml_parser_basic() {
        let yaml = r#"
id: TEST-001
name: Test Rule
severity: critical
strings:
  - "pattern1"
  - "pattern2"
condition: any
tags: [tag1, tag2]
"#;
        let rule = parse_rule_yaml(yaml).unwrap();
        assert_eq!(rule.id, "TEST-001");
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.strings.len(), 2);
        assert_eq!(rule.condition, MatchCondition::Any);
        assert_eq!(rule.tags.len(), 2);
    }

    #[test]
    fn yaml_parser_with_hex() {
        let yaml = r#"
id: TEST-002
name: Hex Test
severity: high
hex_patterns:
  - "48 8b 05 ?? ??"
condition: any
"#;
        let rule = parse_rule_yaml(yaml).unwrap();
        assert_eq!(rule.hex_patterns.len(), 1);
        assert_eq!(rule.hex_patterns[0].len(), 5);
    }

    #[test]
    fn trusted_paths() {
        assert!(is_trusted_path("/usr/bin/ls"));
        assert!(is_trusted_path("/usr/sbin/sshd"));
        assert!(is_trusted_path("/bin/bash"));
        assert!(!is_trusted_path("/tmp/malware"));
        assert!(!is_trusted_path("/dev/shm/payload"));
        assert!(!is_trusted_path("/home/user/exploit"));
    }

    #[test]
    fn cryptominer_detection() {
        let content = b"some binary data stratum+tcp://pool.minexmr.com:4444 more data";
        let rules = builtin_rules();
        let matches = scan_content(content, &rules);
        assert!(matches.iter().any(|r| r.id == "MAL-001"));
    }

    #[test]
    fn webshell_detection() {
        let content = b"<?php eval($_POST['cmd']); // c99shell v2.0";
        let rules = builtin_rules();
        let matches = scan_content(content, &rules);
        assert!(matches.iter().any(|r| r.id == "MAL-002"));
    }

    #[test]
    fn clean_binary_no_match() {
        let content = b"normal application data without malware indicators";
        let rules = builtin_rules();
        let matches = scan_content(content, &rules);
        assert!(matches.is_empty());
    }
}
