use std::path::Path;

use tracing::info;

use crate::AgentState;

/// Process autoencoder anomalies and baseline+autoencoder fused incidents.
pub(crate) fn process_anomalies(
    data_dir: &Path,
    today: &str,
    events_entries: &[innerwarden_core::event::Event],
    state: &mut AgentState,
) {
    // ── Autoencoder anomaly detection ────────────────────────────────────
    // Feed every event to the autoencoder. It builds a sliding window and
    // scores each window against the trained model. Until the model is
    // trained (maturity > 0), observe() returns None -- safe no-op.
    for ev in events_entries {
        if let Some((score, weighted)) = state.anomaly_engine.observe(ev) {
            state.last_autoencoder_anomaly_ts = Some(chrono::Utc::now());
            info!(
                score = format!("{:.3}", score),
                weighted = format!("{:.3}", weighted),
                maturity = format!("{:.2}", state.anomaly_engine.maturity),
                kind = %ev.kind,
                "autoencoder anomaly detected"
            );
            let incident = innerwarden_core::incident::Incident {
                ts: ev.ts,
                host: ev.host.clone(),
                incident_id: format!(
                    "neural_anomaly:{}:{}",
                    (score * 100.0) as u32,
                    ev.ts.format("%Y-%m-%dT%H:%MZ")
                ),
                severity: if score > 0.9 {
                    innerwarden_core::event::Severity::Critical
                } else if score > 0.8 {
                    innerwarden_core::event::Severity::High
                } else {
                    innerwarden_core::event::Severity::Medium
                },
                title: format!(
                    "Neural anomaly: {:.0}% anomaly score (maturity {:.0}%)",
                    score * 100.0,
                    state.anomaly_engine.maturity * 100.0
                ),
                summary: format!(
                    "Autoencoder flagged unusual event pattern. \
                     Trigger: {} | Score: {:.3} | Weighted: {:.3} | \
                     Training cycles: {}",
                    ev.kind, score, weighted, state.anomaly_engine.training_cycles
                ),
                evidence: serde_json::json!({
                    "score": score,
                    "weighted": weighted,
                    "maturity": state.anomaly_engine.maturity,
                    "training_cycles": state.anomaly_engine.training_cycles,
                    "model": "autoencoder-48f",
                    "trigger_event": ev.kind,
                }),
                recommended_checks: vec![
                    "Review recent events for unusual patterns".to_string(),
                    "Check if rule-based detectors also flagged this".to_string(),
                ],
                tags: vec!["neural_model".to_string(), "autoencoder".to_string()],
                entities: ev.entities.clone(),
            };
            let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&incidents_path)
            {
                use std::io::Write;
                if let Ok(json) = serde_json::to_string(&incident) {
                    let _ = writeln!(f, "{json}");
                }
            }
        }
    }

    // ── Baseline + Autoencoder score fusion ─────────────────────────────
    // When both baseline and autoencoder flag anomalies within 60 seconds
    // of each other, emit a combined high-confidence incident.
    if let (Some(baseline_ts), Some(autoencoder_ts)) = (
        state.last_baseline_anomaly_ts,
        state.last_autoencoder_anomaly_ts,
    ) {
        let gap = (baseline_ts - autoencoder_ts).num_seconds().unsigned_abs();
        if gap <= 60 {
            info!(
                baseline_ts = %baseline_ts,
                autoencoder_ts = %autoencoder_ts,
                gap_secs = gap,
                "correlated anomaly: baseline + autoencoder convergence"
            );
            let host = events_entries
                .first()
                .map(|e| e.host.clone())
                .unwrap_or_default();
            let now = chrono::Utc::now();
            let fused_incident = innerwarden_core::incident::Incident {
                ts: now,
                host,
                incident_id: format!(
                    "correlated_anomaly:baseline_neural:{}",
                    now.format("%Y-%m-%dT%H:%MZ")
                ),
                severity: innerwarden_core::event::Severity::High,
                title: "Correlated anomaly: baseline + neural model convergence".to_string(),
                summary: format!(
                    "Both baseline statistical model and neural autoencoder flagged \
                     unusual activity within {gap}s of each other. \
                     High confidence that this is genuine anomalous behavior."
                ),
                evidence: serde_json::json!({
                    "baseline_anomaly_ts": baseline_ts.to_rfc3339(),
                    "autoencoder_anomaly_ts": autoencoder_ts.to_rfc3339(),
                    "gap_seconds": gap,
                    "autoencoder_maturity": state.anomaly_engine.maturity,
                }),
                recommended_checks: vec![
                    "Investigate events in the flagged timeframe".to_string(),
                    "Cross-reference with rule-based detector incidents".to_string(),
                    "Check for lateral movement or exfiltration patterns".to_string(),
                ],
                tags: vec![
                    "correlated_anomaly".to_string(),
                    "baseline".to_string(),
                    "neural_model".to_string(),
                ],
                entities: vec![],
            };
            let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&incidents_path)
            {
                use std::io::Write;
                if let Ok(json) = serde_json::to_string(&fused_incident) {
                    let _ = writeln!(f, "{json}");
                }
            }
            // Reset timestamps to avoid emitting duplicate fused incidents
            state.last_baseline_anomaly_ts = None;
            state.last_autoencoder_anomaly_ts = None;
        }
    }
}
