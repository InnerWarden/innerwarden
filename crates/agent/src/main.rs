mod collectors;
mod config;
mod detectors;
mod sinks;

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use clap::Parser;
use collectors::{auth_log::AuthLogCollector, integrity::IntegrityCollector};
use detectors::ssh_bruteforce::SshBruteforceDetector;
use sinks::{jsonl::JsonlWriter, state::State};
use tokio::sync::mpsc;
use tracing::info;

#[derive(Parser)]
#[command(name = "innerwarden", version, about = "Lightweight host observability agent")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = data_dir.join("state.json");

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let mut writer = JsonlWriter::new(data_dir, cfg.output.write_events)?;
    let (tx, mut rx) = mpsc::channel(1024);

    // SSH brute force detector (stateful, lives in main loop)
    let mut ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(threshold = d.threshold, window_seconds = d.window_seconds, "ssh_bruteforce detector enabled");
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state.get_cursor("auth_log").and_then(|v| v.as_u64()).unwrap_or(0);
        let collector = AuthLogCollector::new(
            &cfg.collectors.auth_log.path,
            &cfg.agent.host_id,
            offset,
        );
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if cfg.collectors.integrity.enabled && !cfg.collectors.integrity.paths.is_empty() {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let paths = ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        let collector = IntegrityCollector::new(paths, &cfg.agent.host_id, ic.poll_seconds, known_hashes);
        info!(paths = ic.paths.len(), poll_secs = ic.poll_seconds, "starting integrity collector");
        let tx3 = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Drop the original tx — each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);

    // Main loop: drain events, run detectors, write output
    let mut events_written = 0u64;
    let mut incidents_written = 0u64;
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(ev) => {
                        info!(kind = %ev.kind, summary = %ev.summary, "event");
                        writer.write_event(&ev)?;
                        events_written += 1;

                        if let Some(ref mut det) = ssh_detector {
                            if let Some(incident) = det.process(&ev) {
                                info!(
                                    incident_id = %incident.incident_id,
                                    severity = ?incident.severity,
                                    title = %incident.title,
                                    "INCIDENT"
                                );
                                writer.write_incident(&incident)?;
                                incidents_written += 1;
                            }
                        }
                    }
                    None => {
                        info!("all collectors stopped");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
        }
    }

    writer.flush()?;
    info!(events_written, incidents_written, "flushed output");

    state.set_cursor("auth_log", serde_json::json!(0));
    state.save(&state_path)?;
    info!("state saved — check data/ for output files");

    Ok(())
}
