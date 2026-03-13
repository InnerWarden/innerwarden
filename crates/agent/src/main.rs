mod ai;
mod config;
mod decisions;
mod narrative;
mod reader;
mod skills;
mod webhook;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "innerwarden-agent", version, about = "Interpretive layer — reads sensor JSONL, generates narratives, and auto-responds to incidents")]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Poll interval in seconds for the narrative/webhook slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    /// Wrapped in Arc so we can clone a handle for use within a loop iteration
    /// without holding a borrow of `state` across async calls that need `&mut state`.
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    decision_writer: Option<decisions::DecisionWriter>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Load config (optional — all fields have sensible defaults)
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Build shared agent state
    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        },
        ai_provider: if cfg.ai.enabled {
            Some(Arc::from(ai::build_provider(&cfg.ai)))
        } else {
            None
        },
        decision_writer: if cfg.ai.enabled {
            match decisions::DecisionWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create decision writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
    };

    let state_path = cli.data_dir.join("agent-state.json");
    let mut cursor = reader::AgentCursor::load(&state_path)?;

    if cli.once {
        // In once mode: run AI tick first (fast path), then narrative tick
        let ai_count = process_ai_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
        let stats = process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await?;
        if let Some(w) = &mut state.decision_writer { w.flush(); }
        cursor.save(&state_path)?;
        info!(
            new_events = stats.new_events,
            new_incidents = stats.new_incidents,
            ai_analyzed = ai_count,
            "run complete"
        );
    } else {
        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            ai_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut ai_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                // Fast AI loop
                _ = ai_ticker.tick() => {
                    process_ai_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    false
                }
                // Slow narrative + webhook loop
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await {
                        Ok(stats) => {
                            if stats.new_events > 0 || stats.new_incidents > 0 {
                                info!(new_events = stats.new_events, "narrative tick");
                            }
                        }
                        Err(e) => warn!("narrative tick error: {e:#}"),
                    }
                    cursor.save(&state_path)?;
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received — shutting down");
                    true
                }
            };

            #[cfg(not(unix))]
            let shutdown = tokio::select! {
                _ = ai_ticker.tick() => {
                    process_ai_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await {
                        Ok(stats) => {
                            if stats.new_events > 0 || stats.new_incidents > 0 {
                                info!(new_events = stats.new_events, "narrative tick");
                            }
                        }
                        Err(e) => warn!("narrative tick error: {e:#}"),
                    }
                    cursor.save(&state_path)?;
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
            };

            if shutdown {
                if let Some(w) = &mut state.decision_writer { w.flush(); }
                cursor.save(&state_path)?;
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Fast AI tick — runs every 2s, processes only new incidents through AI
// ---------------------------------------------------------------------------

/// Returns the number of incidents analyzed.
async fn process_ai_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> usize {
    if !cfg.ai.enabled || state.ai_provider.is_none() {
        return 0;
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    let new_incidents = match reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        cursor.incidents_offset(&today),
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("ai tick: failed to read incidents: {e:#}");
            return 0;
        }
    };

    if new_incidents.entries.is_empty() {
        return 0;
    }

    // Advance the incident cursor
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    // Load recent events for context (up to N, from today's event file)
    let all_events = reader::read_new_entries::<innerwarden_core::event::Event>(
        &events_path,
        0,
    )
    .map(|r| r.entries)
    .unwrap_or_default();

    let skill_infos = state.skill_registry.infos();
    // Clone the Arc so we own a handle that doesn't borrow `state`. This lets us
    // call execute_decision (which needs &mut state) in the same loop iteration.
    let provider: Arc<dyn ai::AiProvider> = state.ai_provider.as_ref().unwrap().clone();
    let provider_name = provider.name();
    let already_blocked = state.blocklist.as_vec();
    let blocked_set: HashSet<String> = already_blocked.iter().cloned().collect();

    let mut analyzed = 0;

    for incident in &new_incidents.entries {
        // Algorithm gate — skip before spending any API credits
        if !ai::should_invoke_ai(incident, &blocked_set) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (low severity / private IP / already blocked)"
            );
            continue;
        }

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            "sending incident to AI for analysis"
        );

        // Build context — filter recent events to the same entity
        let entity_ips: HashSet<&str> = incident
            .entities
            .iter()
            .filter(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str())
            .collect();

        let recent: Vec<&innerwarden_core::event::Event> = all_events
            .iter()
            .filter(|ev| {
                ev.entities
                    .iter()
                    .any(|e| entity_ips.contains(e.value.as_str()))
            })
            .rev() // most recent first
            .take(cfg.ai.context_events)
            .collect();

        let ctx = ai::DecisionContext {
            incident,
            recent_events: recent,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos.iter().map(|s| ai::SkillInfo {
                id: s.id.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
                tier: match s.tier {
                    skills::SkillTier::Open => "open".to_string(),
                    skills::SkillTier::Premium => "premium".to_string(),
                },
            }).collect(),
        };

        let decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                warn!(incident_id = %incident.incident_id, "AI decision failed: {e:#}");
                analyzed += 1;
                continue;
            }
        };

        info!(
            incident_id = %incident.incident_id,
            action = ?decision.action,
            confidence = decision.confidence,
            auto_execute = decision.auto_execute,
            reason = %decision.reason,
            "AI decision"
        );

        // Execute if auto_execute AND confidence above threshold AND responder enabled
        let execution_result = if decision.auto_execute
            && decision.confidence >= cfg.ai.confidence_threshold
            && cfg.responder.enabled
        {
            execute_decision(&decision, incident, cfg, state).await
        } else {
            if !cfg.responder.enabled {
                "skipped: responder disabled".to_string()
            } else if !decision.auto_execute {
                "skipped: AI did not recommend auto-execution".to_string()
            } else {
                format!(
                    "skipped: confidence {:.2} below threshold {:.2}",
                    decision.confidence, cfg.ai.confidence_threshold
                )
            }
        };

        // Write to audit trail
        if let Some(writer) = &mut state.decision_writer {
            let entry = decisions::build_entry(
                &incident.incident_id,
                &incident.host,
                provider_name,
                &decision,
                cfg.responder.dry_run,
                &execution_result,
            );
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write decision entry: {e:#}");
            }
        }

        analyzed += 1;
    }

    analyzed
}

/// Execute an AI decision by finding and running the appropriate skill.
async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> String {
    use ai::AiAction;

    match &decision.action {
        AiAction::BlockIp { ip, skill_id } => {
            // Honour the allowed_skills whitelist
            if !cfg.responder.allowed_skills.contains(skill_id) {
                // Fall back to the configured backend's default skill
                let fallback_id = format!("block-ip-{}", cfg.responder.block_backend);
                if !cfg.responder.allowed_skills.contains(&fallback_id) {
                    return format!("skipped: skill '{skill_id}' not in allowed_skills");
                }
            }

            // Prefer the skill ID the AI chose; fall back to configured backend
            let skill = state.skill_registry.get(skill_id)
                .or_else(|| state.skill_registry.block_skill_for_backend(&cfg.responder.block_backend));

            match skill {
                Some(skill) => {
                    let ctx = skills::SkillContext {
                        incident: incident.clone(),
                        target_ip: Some(ip.clone()),
                        host: incident.host.clone(),
                    };
                    let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    if result.success && !cfg.responder.dry_run {
                        state.blocklist.insert(ip.clone());
                    }
                    result.message
                }
                None => format!("skipped: skill '{skill_id}' not found"),
            }
        }
        AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    host: incident.host.clone(),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: monitor-ip skill not available".to_string()
            }
        }
        AiAction::Honeypot { ip } => {
            if let Some(skill) = state.skill_registry.get("honeypot") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    host: incident.host.clone(),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: honeypot skill not available".to_string()
            }
        }
        AiAction::RequestConfirmation { summary } => {
            // Send a special webhook payload asking for human confirmation
            if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
                let payload = serde_json::json!({
                    "type": "confirmation_required",
                    "incident_id": incident.incident_id,
                    "summary": summary,
                    "decision_reason": decision.reason,
                });
                let client = reqwest::Client::new();
                match client.post(&cfg.webhook.url).json(&payload).send().await {
                    Ok(_) => "confirmation request sent via webhook".to_string(),
                    Err(e) => format!("confirmation webhook failed: {e}"),
                }
            } else {
                "confirmation requested (no webhook configured)".to_string()
            }
        }
        AiAction::Ignore { reason } => {
            format!("ignored: {reason}")
        }
    }
}

// ---------------------------------------------------------------------------
// Slow narrative tick — runs every 30s, generates narrative + webhook
// ---------------------------------------------------------------------------

struct NarrativeStats {
    new_events: usize,
    new_incidents: usize,
}

async fn process_narrative_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
) -> Result<NarrativeStats> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let events_path = data_dir.join(format!("events-{today}.jsonl"));
    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

    // Read new events (for webhook filtering)
    let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
        &events_path,
        cursor.events_offset(&today),
    )?;

    let events_count = new_events.entries.len();
    cursor.set_events_offset(&today, new_events.new_offset);

    // Webhook: notify for each new event's incident counterpart
    if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        // Read new incidents from the current cursor position (may have been advanced by AI tick)
        let new_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
            &incidents_path,
            cursor.incidents_offset(&today),
        )?;
        let min_rank = webhook::severity_rank(&cfg.webhook.parsed_min_severity());
        for incident in &new_incidents.entries {
            if webhook::severity_rank(&incident.severity) >= min_rank {
                if let Err(e) =
                    webhook::send_incident(&cfg.webhook.url, cfg.webhook.timeout_secs, incident)
                        .await
                {
                    warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
                }
            }
        }
    }

    // Narrative: regenerate daily summary from all events/incidents today
    if cfg.narrative.enabled && events_count > 0 {
        let all_events =
            reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)?;
        let all_incidents =
            reader::read_new_entries::<innerwarden_core::incident::Incident>(&incidents_path, 0)?;

        let host = all_events
            .entries
            .first()
            .map(|e| e.host.as_str())
            .or_else(|| all_incidents.entries.first().map(|i| i.host.as_str()))
            .unwrap_or("unknown");

        let md = narrative::generate(&today, host, &all_events.entries, &all_incidents.entries);
        if let Err(e) = narrative::write(data_dir, &today, &md) {
            warn!("failed to write daily summary: {e:#}");
        } else {
            info!(date = today, "daily summary updated");
        }
    }

    Ok(NarrativeStats {
        new_events: events_count,
        new_incidents: 0, // tracked by AI tick
    })
}
