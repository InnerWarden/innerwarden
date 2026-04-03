use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{config, AgentState};

/// Load suppressed incident IDs from file (one pattern per line).
/// Users can add patterns via `innerwarden suppress <pattern>`.
pub(crate) fn load_suppressed_ids(data_dir: &Path) -> HashSet<String> {
    let path = data_dir.join("suppressed-incidents.txt");
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(_) => HashSet::new(),
    }
}

/// Detect if running inside a virtual machine.
fn is_virtual_machine() -> bool {
    // Check common VM indicators
    if Path::new("/sys/hypervisor/type").exists() {
        return true;
    }
    if let Ok(dmi) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let lower = dmi.to_lowercase();
        if lower.contains("virtual")
            || lower.contains("kvm")
            || lower.contains("qemu")
            || lower.contains("vmware")
            || lower.contains("xen")
            || lower.contains("oracle")
            || lower.contains("hyper-v")
        {
            return true;
        }
    }
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("hypervisor") {
            return true;
        }
    }
    false
}

/// Periodic firmware audit. Runs innerwarden-smm's full_audit(), compares
/// against baseline, and emits incidents when trust degrades or threats correlate.
pub(crate) async fn process_firmware_tick(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    use innerwarden_core::incident::Incident;
    use std::io::Write;

    // Run the full firmware audit (blocking I/O — spawn_blocking).
    let data_dir_owned = data_dir.to_path_buf();
    let report = match tokio::task::spawn_blocking(move || {
        // Override baseline path to use agent's data_dir.
        let baseline_path = data_dir_owned.join("firmware_baseline.json");
        if !baseline_path.exists() {
            // Auto-capture baseline on first run.
            let baseline = innerwarden_smm::baseline::FirmwareBaseline::capture();
            if let Err(e) = baseline.save(&baseline_path) {
                tracing::warn!(error = %e, "firmware: failed to save initial baseline");
            } else {
                tracing::info!("firmware: initial baseline captured");
            }
        }
        innerwarden_smm::full_audit()
    })
    .await
    {
        Ok(report) => report,
        Err(e) => {
            warn!(error = %e, "firmware tick: audit task panicked");
            return;
        }
    };

    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");

    let mut incidents = Vec::new();

    // Check trust score degradation.
    if report.trust_score < cfg.firmware.trust_score_threshold {
        let incident_id = format!(
            "firmware:trust_degraded:{}",
            (report.trust_score * 100.0) as u32
        );

        // --- Cooldown: don't emit same firmware incident more than once per 24h ---
        if let Some(last) = state.last_firmware_incident_at {
            let hours_since = (chrono::Utc::now() - last).num_hours();
            if hours_since < 24 {
                tracing::debug!(
                    hours_since,
                    "firmware: trust_degraded cooldown active, skipping"
                );
                return;
            }
        }

        // --- Suppression: check if user suppressed this incident type ---
        if state
            .suppressed_incident_ids
            .iter()
            .any(|pat| incident_id.contains(pat))
        {
            tracing::debug!(incident_id, "firmware: incident suppressed by user");
            return;
        }

        // --- VM detection: reduce severity on VMs where firmware is inaccessible ---
        let on_vm = is_virtual_machine();
        let severity = if on_vm {
            // On VMs, firmware checks are unreliable — downgrade to Info
            tracing::debug!("firmware: running on VM, downgrading severity to Info");
            innerwarden_core::event::Severity::Info
        } else if report.trust_score < 0.3 {
            innerwarden_core::event::Severity::Critical
        } else if report.trust_score < 0.6 {
            innerwarden_core::event::Severity::High
        } else {
            innerwarden_core::event::Severity::Medium
        };

        // On VMs with Info severity, skip generating an incident entirely
        if on_vm && severity == innerwarden_core::event::Severity::Info {
            tracing::debug!(
                trust_score = format!("{:.0}%", report.trust_score * 100.0),
                "firmware: VM detected, skipping trust_degraded incident"
            );
            return;
        }
        let critical_checks: Vec<String> = report
            .checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Critical)
            .map(|c| format!("[{}] {}", c.id, c.name))
            .collect();

        // Update cooldown timestamp
        state.last_firmware_incident_at = Some(chrono::Utc::now());

        incidents.push(Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: incident_id.clone(),
            severity,
            title: format!(
                "Firmware trust score degraded to {:.0}%",
                report.trust_score * 100.0
            ),
            summary: format!(
                "Trust score {:.0}% (threshold: {:.0}%). Critical checks: {}",
                report.trust_score * 100.0,
                cfg.firmware.trust_score_threshold * 100.0,
                if critical_checks.is_empty() {
                    "none".to_string()
                } else {
                    critical_checks.join(", ")
                },
            ),
            evidence: serde_json::json!({
                "trust_score": report.trust_score,
                "threshold": cfg.firmware.trust_score_threshold,
                "checks": report.checks.iter()
                    .filter(|c| c.status != innerwarden_smm::CheckStatus::Unavailable)
                    .map(|c| serde_json::json!({
                        "id": c.id,
                        "name": c.name,
                        "status": format!("{:?}", c.status),
                        "confidence": c.confidence,
                    }))
                    .collect::<Vec<_>>(),
            }),
            recommended_checks: vec![
                "Review firmware audit: innerwarden-smm".into(),
                "Check for unauthorized firmware modifications".into(),
            ],
            tags: vec!["firmware".to_string(), "ring-minus-2".to_string()],
            entities: vec![],
        });
    }

    // Emit incidents for correlated threats.
    for threat in &report.correlated_threats {
        incidents.push(Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: format!("firmware:corr:{}", threat.id),
            severity: if threat.confidence >= 0.9 {
                innerwarden_core::event::Severity::Critical
            } else if threat.confidence >= 0.7 {
                innerwarden_core::event::Severity::High
            } else {
                innerwarden_core::event::Severity::Medium
            },
            title: threat.name.clone(),
            summary: threat.detail.clone(),
            evidence: serde_json::json!({
                "correlation_id": threat.id,
                "confidence": threat.confidence,
                "evidence": threat.evidence,
            }),
            recommended_checks: vec!["Run innerwarden-smm for full report".into()],
            tags: vec![
                "firmware".to_string(),
                "correlated".to_string(),
                "ring-minus-2".to_string(),
            ],
            entities: vec![],
        });
    }

    if incidents.is_empty() {
        let secure = report
            .checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Secure)
            .count();
        tracing::debug!(
            trust_score = format!("{:.0}%", report.trust_score * 100.0),
            secure_checks = secure,
            "firmware tick: all clear"
        );
        return;
    }

    // Write incidents to JSONL.
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in &incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        Err(e) => warn!(error = %e, "firmware tick: failed to write incidents"),
    }

    info!(
        count = incidents.len(),
        trust_score = format!("{:.0}%", report.trust_score * 100.0),
        "firmware tick: emitted incidents"
    );

    // Telegram notification for firmware incidents.
    if let Some(ref tg) = state.telegram_client {
        for inc in &incidents {
            let sev = match inc.severity {
                innerwarden_core::event::Severity::Critical => "🔴 CRITICAL",
                innerwarden_core::event::Severity::High => "🟠 HIGH",
                _ => "🟡 MEDIUM",
            };
            let msg = format!(
                "🔧 <b>Firmware Alert</b>\n\n\
                 {sev}\n\
                 <b>{}</b>\n\
                 {}\n\n\
                 Trust Score: {:.0}%",
                inc.title,
                inc.summary,
                report.trust_score * 100.0,
            );
            let tg = tg.clone();
            let msg_owned = msg;
            tokio::spawn(async move {
                let _ = tg.send_raw_html(&msg_owned).await;
            });
        }
    }
}
