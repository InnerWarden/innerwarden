use std::path::Path;

use crate::{ai, config, skills, AgentState};

/// Execute simple skill-backed AI actions.
/// Returns `Some(result)` when the action is handled here; `None` otherwise.
pub(crate) async fn execute_simple_action(
    action: &ai::AiAction,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Option<(String, bool)> {
    match action {
        ai::AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some(("skipped: monitor-ip skill not available".to_string(), false))
            }
        }
        ai::AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return Some((
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                ));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: suspend-user-sudo skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::KillProcess {
            user,
            duration_secs,
        } => {
            let skill_id = "kill-process";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return Some((
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                ));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: kill-process skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::BlockContainer {
            container_id,
            action: _,
        } => {
            let skill_id = "block-container";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return Some((
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                ));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: Some(container_id.clone()),
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: block-container skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::KillChainResponse { .. } => {
            let skill_id = "kill-chain-response";
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_provider.clone(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: kill-chain-response skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::Ignore { reason } => Some((format!("ignored: {reason}"), false)),
        _ => None,
    }
}
