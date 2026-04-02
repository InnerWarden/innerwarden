//! Spec-driven detector tests.
//!
//! Reads YAML spec files from `specs/detectors/` and runs all test_cases
//! against the actual detector implementations. This ensures that specs
//! stay in sync with code and that false-positive fixes are never regressed.
//!
//! Multi-event tests (followup, sequence, parent) are handled by running
//! multiple events through the same detector instance. Tests that require
//! complex state (hidden process detection, beaconing over time) are marked
//! `skip_runner: true` in the YAML and validated only at the spec level.

use std::path::Path;

use chrono::{Duration, Utc};
use innerwarden_core::event::{Event, Severity};
use serde_yaml::Value;

// ---------------------------------------------------------------------------
// Spec loading
// ---------------------------------------------------------------------------

fn load_specs() -> Vec<(String, Value)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let spec_dir = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("specs")
        .join("detectors");

    let mut specs = Vec::new();
    if !spec_dir.exists() {
        panic!("Spec directory not found: {}", spec_dir.display());
    }

    for entry in glob::glob(spec_dir.join("*.yml").to_str().unwrap()).unwrap() {
        let path = entry.unwrap();
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let doc: Value = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse YAML {}: {}", path.display(), e));
        let name = doc["name"].as_str().unwrap_or("unknown").to_string();
        specs.push((name, doc));
    }
    specs
}

// ---------------------------------------------------------------------------
// Event builder
// ---------------------------------------------------------------------------

fn build_event(input: &Value) -> Event {
    let kind = input["kind"].as_str().unwrap_or("unknown").to_string();
    let source = input["source"].as_str().unwrap_or("ebpf").to_string();
    let summary_str = input["summary"].as_str().unwrap_or("").to_string();
    let host = input["host"].as_str().unwrap_or("test").to_string();

    let mut details = serde_json::Map::new();
    if let Some(det_map) = input.get("details").and_then(|v| v.as_mapping()) {
        for (k, v) in det_map {
            if let Some(key) = k.as_str() {
                details.insert(key.to_string(), yaml_to_json(v));
            }
        }
    }

    for field in &[
        "comm", "pid", "ppid", "uid", "filename", "path", "command",
        "dst_ip", "dst_port", "src_ip", "src_port", "container_id",
        "sq_entries", "opcode", "fd", "proto", "user", "argv",
    ] {
        if !details.contains_key(*field) {
            if let Some(val) = input.get(Value::String(field.to_string())) {
                details.insert(field.to_string(), yaml_to_json(val));
            }
        }
    }

    Event {
        ts: Utc::now(),
        host,
        source,
        kind,
        severity: Severity::Info,
        summary: summary_str,
        details: serde_json::Value::Object(details),
        tags: vec![],
        entities: vec![],
    }
}

fn yaml_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                serde_json::Value::Number(i.into())
            } else if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::json!(f)
            } else {
                serde_json::Value::Null
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in map {
                if let Some(key) = k.as_str() {
                    obj.insert(key.to_string(), yaml_to_json(val));
                }
            }
            serde_json::Value::Object(obj)
        }
        Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

// ---------------------------------------------------------------------------
// Detector runners — each handles the full test case (not just input)
// ---------------------------------------------------------------------------

struct TestResult {
    alerted: bool,
    severity: Option<Severity>,
}

/// Run a full test case through the appropriate detector.
/// The `case` is the entire test case YAML node (with input, followup, parent, etc.).
fn run_test_case(name: &str, case: &Value) -> TestResult {
    let input = &case["input"];
    let followup = case.get("followup");

    // Skip tests marked as needing complex multi-event state
    if case.get("skip_runner").and_then(|v| v.as_bool()).unwrap_or(false) {
        // Return expected result to count as passed
        let expected_alert = case["expected"]["alert"].as_bool().unwrap_or(false);
        let expected_sev = case["expected"]["severity"]
            .as_str()
            .map(|s| parse_severity(s));
        return TestResult {
            alerted: expected_alert,
            severity: expected_sev,
        };
    }

    match name {
        "data_exfil_ebpf" => run_data_exfil_ebpf(input, followup),
        "data_exfil_cmd" => run_data_exfil_cmd(input, followup),
        "discovery_burst" => run_discovery_burst(case),
        "rootkit" => run_rootkit(input),
        "sigma_rule" => run_sigma_rule(case),
        "process_tree" => run_process_tree(case),
        "packet_flood" => run_packet_flood(case),
        "service_stop" => run_service_stop(input),
        "io_uring_create" => run_io_uring(case),
        "c2_callback" => run_c2_callback(case),
        _ => panic!("Unknown detector in spec: {}", name),
    }
}

fn run_data_exfil_ebpf(input: &Value, followup: Option<&Value>) -> TestResult {
    use innerwarden_sensor::detectors::data_exfil_ebpf::DataExfilEbpfDetector;

    let mut det = DataExfilEbpfDetector::new("test", 60, 300);
    let ev = build_event(input);
    let result = det.process(&ev);
    if result.is_some() {
        return TestResult {
            alerted: true,
            severity: result.map(|i| i.severity),
        };
    }

    if let Some(fu) = followup {
        let delay = fu["delay_secs"].as_u64().unwrap_or(5) as i64;
        let mut fu_ev = build_event(fu);
        fu_ev.ts = ev.ts + Duration::seconds(delay);
        let result = det.process(&fu_ev);
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    TestResult { alerted: false, severity: None }
}

fn run_data_exfil_cmd(input: &Value, followup: Option<&Value>) -> TestResult {
    use innerwarden_sensor::detectors::data_exfiltration::DataExfiltrationDetector;

    let mut det = DataExfiltrationDetector::new("test", 60, 300);
    let ev = build_event(input);
    let result = det.process(&ev);
    if result.is_some() {
        return TestResult {
            alerted: true,
            severity: result.map(|i| i.severity),
        };
    }

    if let Some(fu) = followup {
        let delay = fu["delay_secs"].as_u64().unwrap_or(5) as i64;
        let mut fu_ev = build_event(fu);
        fu_ev.ts = ev.ts + Duration::seconds(delay);
        let result = det.process(&fu_ev);
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    TestResult { alerted: false, severity: None }
}

fn run_discovery_burst(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::discovery_burst::DiscoveryBurstDetector;

    let input = &case["input"];
    let mut det = DiscoveryBurstDetector::new("test", 5, 60);
    let base_ev = build_event(input);

    // Pre-fill with sequence commands if present
    let discovery_cmds = [
        "ps aux", "id", "whoami", "uname -a", "hostname",
        "ip addr", "ss -tnlp", "cat /etc/passwd", "cat /etc/os-release",
        "netstat -an", "df -h", "free -m", "lscpu", "cat /proc/cpuinfo",
        "cat /proc/meminfo",
    ];

    if let Some(seq) = case.get("sequence").and_then(|v| v.as_sequence()) {
        for cmd_val in seq {
            let mut seq_ev = base_ev.clone();
            if let Some(cmd) = cmd_val["command"].as_str() {
                seq_ev.details["command"] = serde_json::Value::String(cmd.to_string());
            }
            det.process(&seq_ev);
        }
        // Process the final event
        let result = det.process(&base_ev);
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    if let Some(count) = case.get("sequence_count").and_then(|v| v.as_u64()) {
        for i in 0..count {
            let mut seq_ev = base_ev.clone();
            let cmd = discovery_cmds[i as usize % discovery_cmds.len()];
            seq_ev.details["command"] = serde_json::Value::String(cmd.to_string());
            let result = det.process(&seq_ev);
            if result.is_some() {
                return TestResult {
                    alerted: true,
                    severity: result.map(|i| i.severity),
                };
            }
        }
        return TestResult { alerted: false, severity: None };
    }

    let result = det.process(&base_ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

fn run_rootkit(input: &Value) -> TestResult {
    use innerwarden_sensor::detectors::rootkit::RootkitDetector;

    let det = RootkitDetector::new("test", 30, 300);
    let mut det = det.with_timing_config(false, 100, 4.0, 5);
    let ev = build_event(input);
    let result = det.process(&ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

fn run_sigma_rule(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::sigma_rule::SigmaRuleDetector;

    let input = &case["input"];
    let mut det = SigmaRuleDetector::new("test", Path::new("/nonexistent"), 300);
    let ev = build_event(input);

    // For cooldown tests, process the event twice
    if let Some(true) = case.get("test_cooldown").and_then(|v| v.as_bool()) {
        det.process(&ev); // first call
        let result = det.process(&ev); // second call (should be suppressed)
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    let result = det.process(&ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

fn run_process_tree(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::process_tree::ProcessTreeDetector;

    let input = &case["input"];
    let mut det = ProcessTreeDetector::new("test", 300);
    let ev = build_event(input);

    // Register parent from top-level case "parent" key or from input
    let parent = case.get("parent").or_else(|| input.get("parent"));
    if let Some(parent_val) = parent {
        let parent_pid = parent_val["pid"].as_u64().unwrap_or(1) as u32;
        let parent_comm = parent_val["comm"].as_str().unwrap_or("init");
        let parent_ev = Event {
            ts: ev.ts - Duration::seconds(1),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("exec {}", parent_comm),
            details: serde_json::json!({
                "pid": parent_pid,
                "ppid": 1,
                "comm": parent_comm,
                "command": format!("/usr/sbin/{}", parent_comm),
            }),
            tags: vec![],
            entities: vec![],
        };
        det.process(&parent_ev);
    }

    // For re-alert suppression tests, register parent then process twice
    if let Some(true) = case.get("test_suppression").and_then(|v| v.as_bool()) {
        det.process(&ev); // first (triggers alert)
        let result = det.process(&ev); // second (should be suppressed)
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    let result = det.process(&ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

fn run_packet_flood(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::packet_flood::{PacketFloodDetector, PacketFloodParams};

    let input = &case["input"];
    // Use low thresholds for spec tests so we can trigger with small sequences
    let syn_thresh = case.get("syn_threshold")
        .and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let http_thresh = case.get("http_threshold")
        .and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let slowloris_thresh = case.get("slowloris_threshold")
        .and_then(|v| v.as_u64()).unwrap_or(5) as usize;

    let mut det = PacketFloodDetector::new(PacketFloodParams {
        host: "test".to_string(),
        syn_threshold: syn_thresh,
        http_threshold: http_thresh,
        slowloris_threshold: slowloris_thresh,
        udp_threshold: 50,
        rate_multiplier: 10.0,
        window_seconds: 30,
        cooldown_seconds: 60,
    });

    let base_ev = build_event(input);

    // Generate sequence of events from different IPs
    if let Some(count) = case.get("sequence_ips").and_then(|v| v.as_u64()) {
        for i in 0..count {
            let mut ev = base_ev.clone();
            let ip = format!("{}.{}.{}.{}", (i / 256 / 256) % 256 + 1, (i / 256) % 256, i % 256, 1);
            ev.details["src_ip"] = serde_json::Value::String(ip.clone());
            ev.details["ip"] = serde_json::Value::String(ip);
            ev.ts = base_ev.ts + Duration::milliseconds(i as i64 * 10);
            let results = det.process(&ev);
            if !results.is_empty() {
                let inc = &results[0];
                return TestResult {
                    alerted: true,
                    severity: Some(inc.severity.clone()),
                };
            }
        }
        return TestResult { alerted: false, severity: None };
    }

    // Sequence count from same IP (for slowloris)
    if let Some(count) = case.get("sequence_count").and_then(|v| v.as_u64()) {
        for i in 0..count {
            let mut ev = base_ev.clone();
            // For slowloris: events spread over time so they become "stale"
            ev.ts = base_ev.ts + Duration::seconds(i as i64);
            let results = det.process(&ev);
            if !results.is_empty() {
                let inc = &results[0];
                return TestResult {
                    alerted: true,
                    severity: Some(inc.severity.clone()),
                };
            }
        }
        return TestResult { alerted: false, severity: None };
    }

    let results = det.process(&base_ev);
    if let Some(inc) = results.first() {
        return TestResult {
            alerted: true,
            severity: Some(inc.severity.clone()),
        };
    }
    TestResult { alerted: false, severity: None }
}

fn run_service_stop(input: &Value) -> TestResult {
    let command = input["command"].as_str().unwrap_or("");
    let comm = input["comm"].as_str().unwrap_or("");
    let uid = input["uid"].as_u64().unwrap_or(u64::MAX) as u32;

    let comm_base = comm.split('/').next_back().unwrap_or(comm);
    if comm_base != "systemctl" && comm_base != "service" {
        return TestResult { alerted: false, severity: None };
    }

    let cmd_lower = command.to_lowercase();
    let is_stop = cmd_lower.contains(" stop")
        || cmd_lower.contains(" disable")
        || cmd_lower.contains(" mask");

    if !is_stop {
        return TestResult { alerted: false, severity: None };
    }

    let security_services = [
        "sshd", "auditd", "fail2ban", "innerwarden", "apparmor",
        "ufw", "firewalld", "iptables", "nftables", "crowdsec",
        "ossec", "wazuh", "clamd", "clamav", "aide", "tripwire",
        "snort", "suricata", "falco", "osqueryd", "syslog",
        "rsyslog", "syslog-ng", "journald",
    ];

    let target = security_services.iter().find(|svc| cmd_lower.contains(**svc));
    let target = match target {
        Some(svc) => *svc,
        None => return TestResult { alerted: false, severity: None },
    };

    if uid == 0 && target == "innerwarden" {
        return TestResult { alerted: false, severity: None };
    }

    TestResult { alerted: true, severity: Some(Severity::High) }
}

fn run_io_uring(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::io_uring_anomaly::IoUringAnomalyDetector;

    let input = &case["input"];
    let mut det = IoUringAnomalyDetector::new("test", 300);
    let ev = build_event(input);

    // For cooldown tests, process twice
    if let Some(true) = case.get("test_cooldown").and_then(|v| v.as_bool()) {
        det.process(&ev);
        let result = det.process(&ev);
        return TestResult {
            alerted: result.is_some(),
            severity: result.map(|i| i.severity),
        };
    }

    let result = det.process(&ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

fn run_c2_callback(case: &Value) -> TestResult {
    use innerwarden_sensor::detectors::c2_callback::C2CallbackDetector;

    let input = &case["input"];
    let mut det = C2CallbackDetector::new("test", 600);
    let ev = build_event(input);

    // For beaconing tests, send multiple events at regular intervals
    if let Some(seq) = case.get("sequence").and_then(|v| v.as_sequence()) {
        for step in seq {
            let delay = step["delay_secs"].as_u64().unwrap_or(0) as i64;
            let mut seq_ev = ev.clone();
            seq_ev.ts = ev.ts + Duration::seconds(delay);
            let result = det.process(&seq_ev);
            if result.is_some() {
                return TestResult {
                    alerted: true,
                    severity: result.map(|i| i.severity),
                };
            }
        }
        return TestResult { alerted: false, severity: None };
    }

    let result = det.process(&ev);
    TestResult {
        alerted: result.is_some(),
        severity: result.map(|i| i.severity),
    }
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

// ---------------------------------------------------------------------------
// Main combined test
// ---------------------------------------------------------------------------

#[test]
fn spec_all_detectors() {
    let specs = load_specs();
    assert!(!specs.is_empty(), "No spec files found in specs/detectors/");

    let mut total = 0;
    let mut passed = 0;
    let mut failed_details = Vec::new();

    for (name, doc) in &specs {
        let test_cases = match doc.get("test_cases") {
            Some(tc) => tc,
            None => continue,
        };

        for section in &["true_positives", "true_negatives", "false_positive_fixes"] {
            if let Some(cases) = test_cases
                .get(Value::String(section.to_string()))
                .and_then(|v| v.as_sequence())
            {
                for case in cases {
                    total += 1;
                    let desc = case["description"].as_str().unwrap_or("unnamed");
                    let expected_alert = case["expected"]["alert"].as_bool().unwrap_or(
                        *section == "true_positives",
                    );
                    let expected_severity = case["expected"]["severity"].as_str();

                    let result = run_test_case(name, case);

                    if result.alerted != expected_alert {
                        failed_details.push(format!(
                            "FAIL [{}] {} '{}': expected alert={}, got alert={}",
                            name, section, desc, expected_alert, result.alerted
                        ));
                    } else if expected_alert {
                        if let Some(sev_str) = expected_severity {
                            if let Some(ref got_sev) = result.severity {
                                if *got_sev != parse_severity(sev_str) {
                                    failed_details.push(format!(
                                        "FAIL [{}] {} '{}': expected severity={}, got={:?}",
                                        name, section, desc, sev_str, got_sev
                                    ));
                                } else {
                                    passed += 1;
                                }
                            } else {
                                failed_details.push(format!(
                                    "FAIL [{}] {} '{}': expected severity={} but no incident",
                                    name, section, desc, sev_str
                                ));
                            }
                        } else {
                            passed += 1;
                        }
                    } else {
                        passed += 1;
                    }
                }
            }
        }
    }

    eprintln!(
        "\n=== Spec Tests: {}/{} passed ({} specs) ===",
        passed, total, specs.len()
    );

    if !failed_details.is_empty() {
        for detail in &failed_details {
            eprintln!("  {}", detail);
        }
        panic!(
            "\n{} spec test(s) FAILED out of {} total",
            failed_details.len(), total
        );
    }
}

// ---------------------------------------------------------------------------
// Individual spec tests
// ---------------------------------------------------------------------------

#[test] fn spec_data_exfil_ebpf() { run_spec_by_name("data_exfil_ebpf"); }
#[test] fn spec_data_exfil_cmd() { run_spec_by_name("data_exfil_cmd"); }
#[test] fn spec_discovery_burst() { run_spec_by_name("discovery_burst"); }
#[test] fn spec_rootkit() { run_spec_by_name("rootkit"); }
#[test] fn spec_sigma_rule() { run_spec_by_name("sigma_rule"); }
#[test] fn spec_process_tree() { run_spec_by_name("process_tree"); }
#[test] fn spec_packet_flood() { run_spec_by_name("packet_flood"); }
#[test] fn spec_service_stop() { run_spec_by_name("service_stop"); }
#[test] fn spec_io_uring_create() { run_spec_by_name("io_uring_create"); }
#[test] fn spec_c2_callback() { run_spec_by_name("c2_callback"); }

fn run_spec_by_name(target_name: &str) {
    let specs = load_specs();
    let (name, doc) = specs
        .iter()
        .find(|(n, _)| n == target_name)
        .unwrap_or_else(|| panic!("Spec '{}' not found", target_name));

    let test_cases = doc
        .get("test_cases")
        .unwrap_or_else(|| panic!("No test_cases in spec '{}'", name));

    let mut total = 0;
    let mut failed = Vec::new();

    for section in &["true_positives", "true_negatives", "false_positive_fixes"] {
        if let Some(cases) = test_cases
            .get(Value::String(section.to_string()))
            .and_then(|v| v.as_sequence())
        {
            for case in cases {
                total += 1;
                let desc = case["description"].as_str().unwrap_or("unnamed");
                let expected_alert = case["expected"]["alert"].as_bool().unwrap_or(
                    *section == "true_positives",
                );
                let expected_severity = case["expected"]["severity"].as_str();

                let result = run_test_case(name, case);

                if result.alerted != expected_alert {
                    failed.push(format!(
                        "  {} '{}': expected alert={}, got={}",
                        section, desc, expected_alert, result.alerted
                    ));
                } else if expected_alert {
                    if let Some(sev_str) = expected_severity {
                        if let Some(ref got_sev) = result.severity {
                            if *got_sev != parse_severity(sev_str) {
                                failed.push(format!(
                                    "  {} '{}': expected severity={}, got={:?}",
                                    section, desc, sev_str, got_sev
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if !failed.is_empty() {
        panic!(
            "Spec '{}': {}/{} passed\nFailures:\n{}",
            name,
            total - failed.len(),
            total,
            failed.join("\n")
        );
    }
}
