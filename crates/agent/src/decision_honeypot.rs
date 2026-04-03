use std::path::Path;

use tracing::warn;

use crate::{config, skills, AgentState};

/// Execute honeypot action, including post-session tasks and marker event write.
pub(crate) async fn execute_honeypot_decision(
    ip: &str,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    if let Some(skill) = state.skill_registry.get("honeypot") {
        let mut runtime = crate::honeypot_runtime(cfg);
        // Thread the AI provider into the runtime so llm_shell interaction works.
        runtime.ai_provider = state.ai_provider.clone();
        let ctx = skills::SkillContext {
            incident: incident.clone(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: incident.host.clone(),
            data_dir: data_dir.to_path_buf(),
            honeypot: runtime.clone(),
            ai_provider: state.ai_provider.clone(),
        };
        let result = skill.execute(&ctx, cfg.responder.dry_run).await;
        if result.success {
            // Extract session_id from the skill result message for post-session tasks.
            let session_id =
                crate::honeypot_post_session::extract_session_id_from_message(&result.message)
                    .unwrap_or_else(|| {
                        format!("unknown-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
                    });

            // Spawn post-session tasks in the background (non-blocking).
            let post_ip = ip.to_string();
            let post_session_id = session_id.clone();
            let post_data_dir = data_dir.to_path_buf();
            let post_ai = state.ai_provider.clone();
            let post_tg = state.telegram_client.clone();
            let post_responder_enabled = cfg.responder.enabled;
            let post_dry_run = cfg.responder.dry_run;
            let post_block_backend = cfg.responder.block_backend.clone();
            let post_allowed_skills = cfg.responder.allowed_skills.clone();
            let post_blocklist_has = state.blocklist.contains(ip);
            tokio::spawn(async move {
                crate::honeypot_post_session::spawn_post_session_tasks(
                    &post_ip,
                    &post_session_id,
                    &post_data_dir,
                    post_ai,
                    post_tg,
                    post_responder_enabled,
                    post_dry_run,
                    &post_block_backend,
                    &post_allowed_skills,
                    post_blocklist_has,
                )
                .await;
            });

            match crate::append_honeypot_marker_event(
                data_dir,
                incident,
                ip,
                cfg.responder.dry_run,
                &runtime,
            )
            .await
            {
                Ok(path) => (
                    format!(
                        "{} | honeypot marker written to {}",
                        result.message,
                        path.display()
                    ),
                    false,
                ),
                Err(e) => {
                    state.telemetry.observe_error("honeypot_marker_writer");
                    warn!("failed to write honeypot marker event: {e:#}");
                    (
                        format!(
                            "{} | warning: failed to write honeypot marker event: {e}",
                            result.message
                        ),
                        false,
                    )
                }
            }
        } else {
            (result.message, false)
        }
    } else {
        ("skipped: honeypot skill not available".to_string(), false)
    }
}
