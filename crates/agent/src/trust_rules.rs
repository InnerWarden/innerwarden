use std::collections::HashSet;
use std::path::Path;

use tracing::warn;

const TRUST_RULES_FILE: &str = "trust-rules.json";

/// Load trust rules from data_dir/trust-rules.json.
/// Returns a HashSet of "detector:action" keys. Fail-open: returns empty on any error.
pub(crate) fn load_trust_rules(data_dir: &Path) -> HashSet<String> {
    let path = data_dir.join(TRUST_RULES_FILE);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return HashSet::new();
    };
    let rules: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap_or_default();
    rules
        .into_iter()
        .filter_map(|r| {
            let d = r["detector"].as_str()?.to_string();
            let a = r["action"].as_str()?.to_string();
            Some(format!("{d}:{a}"))
        })
        .collect()
}

/// Append a trust rule to data_dir/trust-rules.json and update the in-memory set.
/// Fail-open: logs a warning on I/O errors.
pub(crate) fn append_trust_rule(
    data_dir: &Path,
    trust_rules: &mut HashSet<String>,
    detector: &str,
    action: &str,
) {
    let key = format!("{detector}:{action}");
    if trust_rules.contains(&key) {
        return; // already trusted
    }
    trust_rules.insert(key);

    let path = data_dir.join(TRUST_RULES_FILE);
    let mut rules: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_default();
    rules.push(serde_json::json!({ "detector": detector, "action": action }));

    match serde_json::to_string_pretty(&rules) {
        Ok(content) => {
            if let Err(e) = std::fs::write(&path, content) {
                warn!("failed to write trust-rules.json: {e:#}");
            }
        }
        Err(e) => warn!("failed to serialise trust rules: {e:#}"),
    }
}

/// Returns true if a (detector, action) pair has been trusted by the operator.
pub(crate) fn is_trusted(trust_rules: &HashSet<String>, detector: &str, action: &str) -> bool {
    trust_rules.contains(&format!("{detector}:{action}"))
        || trust_rules.contains(&format!("*:{action}"))
        || trust_rules.contains(&format!("{detector}:*"))
        || trust_rules.contains("*:*")
}

/// Returns true if an incident represents a high-severity execution threat
/// that warrants automatic LSM enforcement (blocking /tmp, /dev/shm execution).
pub(crate) fn should_auto_enable_lsm(incident: &innerwarden_core::incident::Incident) -> bool {
    use innerwarden_core::event::Severity;

    if !matches!(incident.severity, Severity::High | Severity::Critical) {
        return false;
    }

    let detector = incident.incident_id.split(':').next().unwrap_or("");
    let title_lower = incident.title.to_lowercase();
    let summary_lower = incident.summary.to_lowercase();

    if detector == "suspicious_execution" || detector == "execution_guard" {
        return title_lower.contains("reverse shell")
            || title_lower.contains("download")
            || summary_lower.contains("/tmp/")
            || summary_lower.contains("/dev/shm/")
            || summary_lower.contains("curl")
            || summary_lower.contains("wget");
    }

    if detector == "lsm" {
        return true;
    }

    if detector == "container_escape" {
        return summary_lower.contains("/tmp") || summary_lower.contains("/dev/shm");
    }

    false
}

/// Enable LSM enforcement by setting key 0 = 1 in the pinned policy map.
pub(crate) async fn enable_lsm_enforcement() -> Result<(), String> {
    const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";

    let output = tokio::process::Command::new("sudo")
        .args([
            "bpftool",
            "map",
            "update",
            "pinned",
            LSM_POLICY_PIN,
            "key",
            "0",
            "0",
            "0",
            "0",
            "value",
            "1",
            "0",
            "0",
            "0",
            "any",
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run bpftool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
