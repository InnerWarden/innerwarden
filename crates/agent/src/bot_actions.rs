use std::path::Path;

use tracing::{debug, info, warn};

use crate::{
    append_honeypot_marker_event, append_trust_rule, config, decisions, execute_decision,
    honeypot_runtime, skills, telegram, AgentState,
};

/// Handle Telegram action callbacks that execute responder skills.
/// Returns true when a callback was matched and handled.
pub(crate) async fn handle_telegram_action_callback(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // Quick-block sentinel: "quick:block:<ip>" - initiated from the inline keyboard on T.1 alerts
    if let Some(ip) = result.incident_id.strip_prefix("__quick_block__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        info!(ip = %ip, operator = %operator, "Telegram quick-block received");

        if !cfg.responder.enabled {
            tg_reply(
                state,
                "⚠️ Responder is disabled. Enable it in agent.toml to allow blocking.\n\
                 Run: <code>innerwarden configure responder</code>"
                    .to_string(),
            );
            return true;
        }

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        if !cfg.responder.allowed_skills.contains(&skill_id) {
            tg_reply(
                state,
                format!(
                    "⚠️ Skill <code>{skill_id}</code> is not in allowed_skills. \
                     Add it to agent.toml under [responder] allowed_skills."
                ),
            );
            return true;
        }

        let skill = state.skill_registry.get(&skill_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        });

        let Some(skill) = skill else {
            tg_reply(
                state,
                format!("⚠️ Skill <code>{skill_id}</code> not found in registry."),
            );
            return true;
        };

        // Build a minimal incident for the skill context
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let inc = {
            use innerwarden_core::event::Severity;
            innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id: format!("telegram:quick_block:{ip}"),
                severity: Severity::High,
                title: format!("Quick block of {ip} via Telegram"),
                summary: format!("Telegram operator requested immediate block of {ip}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["telegram".to_string(), "manual".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip.clone())],
            }
        };

        let ctx = skills::SkillContext {
            incident: inc.clone(),
            target_ip: Some(ip.clone()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: inc.host.clone(),
            data_dir: data_dir.to_path_buf(),
            honeypot: honeypot_runtime(cfg),
            ai_provider: state.ai_provider.clone(),
        };

        let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;

        if exec_result.success {
            state.blocklist.insert(ip.clone());
        }

        // Audit trail
        if let Some(writer) = &mut state.decision_writer {
            let provider = "telegram".to_string();
            let entry = decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: inc.incident_id.clone(),
                host: inc.host.clone(),
                ai_provider: provider,
                action_type: "block_ip".to_string(),
                target_ip: Some(ip.clone()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: true,
                dry_run: cfg.responder.dry_run,
                reason: "Quick block requested by Telegram operator".to_string(),
                estimated_threat: "manual".to_string(),
                execution_result: exec_result.message.clone(),
                prev_hash: None,
            };
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write quick-block decision entry: {e:#}");
            }
        }

        let reply = if cfg.responder.dry_run {
            format!(
                "🧪 Simulated - would've dropped {ip} at the firewall. Enable live mode to make it real."
            )
        } else if exec_result.success {
            format!("🛡 Threat actor {ip} neutralized - dropped at the firewall. They won't pivot from there.")
        } else {
            format!("❌ Failed to contain {ip}: {}", exec_result.message)
        };
        tg_reply(state, reply);
        return true;
    }

    // Honeypot operator-in-the-loop: "hpot:{action}:{ip}" via send_honeypot_suggestion
    if let Some(ip) = result.incident_id.strip_prefix("__hpot__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        let chosen = result.chosen_action.as_str();
        info!(ip = %ip, operator = %operator, action = %chosen, "Telegram honeypot choice received");

        let Some(choice) = state.pending_honeypot_choices.remove(&ip) else {
            info!(
                ip = %ip,
                "Telegram honeypot choice for unknown or expired IP"
            );
            tg_reply(
                state,
                format!(
                    "⏳ That choice for {ip} expired or was already handled. If the threat is still active, it'll show up again."
                ),
            );
            return true;
        };

        let host = choice.incident.host.clone();
        let provider_label = "operator:telegram".to_string();

        match chosen {
            "honeypot" => {
                // Build SkillContext and execute the honeypot skill
                if let Some(skill) = state.skill_registry.get("honeypot") {
                    let mut runtime = honeypot_runtime(cfg);
                    runtime.ai_provider = state.ai_provider.clone();
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: runtime.clone(),
                        ai_provider: state.ai_provider.clone(),
                    };
                    let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    let msg = if exec_result.success {
                        match append_honeypot_marker_event(
                            data_dir,
                            &choice.incident,
                            &ip,
                            cfg.responder.dry_run,
                            &runtime,
                        )
                        .await
                        {
                            Ok(path) => format!(
                                "{} | honeypot marker written to {}",
                                exec_result.message,
                                path.display()
                            ),
                            Err(e) => {
                                warn!("failed to write honeypot marker: {e:#}");
                                exec_result.message.clone()
                            }
                        }
                    } else {
                        exec_result.message.clone()
                    };
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "honeypot".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some("honeypot".to_string()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: "Telegram operator chose honeypot".to_string(),
                            estimated_threat: "high".to_string(),
                            execution_result: msg.clone(),
                            prev_hash: None,
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!(
                            "🧪 Dry run - {ip} would be sent to the honeypot. Enable live mode to execute for real."
                        )
                    } else if exec_result.success {
                        format!("🍯 {ip} sent to honeypot. Now let's see what they try to do.")
                    } else {
                        format!(
                            "❌ Failed to activate honeypot for {ip}: {}",
                            exec_result.message
                        )
                    };
                    tg_reply(state, reply);
                } else {
                    tg_reply(state, format!("⚠️ Honeypot skill not available for {ip}."));
                }
            }
            "block" => {
                // Execute block_ip skill
                let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
                let skill = state.skill_registry.get(&skill_id).or_else(|| {
                    state
                        .skill_registry
                        .block_skill_for_backend(&cfg.responder.block_backend)
                });
                if let Some(skill) = skill {
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: honeypot_runtime(cfg),
                        ai_provider: state.ai_provider.clone(),
                    };
                    let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    if exec_result.success {
                        state.blocklist.insert(ip.clone());
                    }
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "block_ip".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some(skill_id.clone()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: "Telegram operator chose block".to_string(),
                            estimated_threat: "high".to_string(),
                            execution_result: exec_result.message.clone(),
                            prev_hash: None,
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot-block decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!("🧪 Dry run - {ip} would be blocked in the firewall.")
                    } else if exec_result.success {
                        format!("🛡 {ip} blocked in the firewall. Done with this one.")
                    } else {
                        format!("❌ Failed to block {ip}: {}", exec_result.message)
                    };
                    tg_reply(state, reply);
                } else {
                    tg_reply(state, format!("⚠️ Block skill not available for {ip}."));
                }
            }
            "monitor" => {
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "monitor".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: "Telegram operator chose monitor".to_string(),
                        estimated_threat: "medium".to_string(),
                        execution_result: "monitoring: no active action taken".to_string(),
                        prev_hash: None,
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write monitor decision entry: {e:#}");
                    }
                }
                tg_reply(
                    state,
                    format!("👁 Silent monitoring active on {ip} - collecting intel."),
                );
            }
            _ => {
                // "ignore" or anything else
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "ignore".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: "Telegram operator chose ignore".to_string(),
                        estimated_threat: "low".to_string(),
                        execution_result: "ignored by operator".to_string(),
                        prev_hash: None,
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write ignore decision entry: {e:#}");
                    }
                }
                tg_reply(
                    state,
                    format!("👍 Anotado. {ip} marcado como falso positivo. Mantendo olho aberto."),
                );
            }
        }
        return true;
    }

    false
}

/// Handle standard pending confirmations (approve/reject/always) that come from
/// Telegram inline approval buttons.
/// Returns true when a pending confirmation entry was found and processed.
pub(crate) async fn handle_pending_confirmation(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some((pending, decision, incident)) =
        state.pending_confirmations.remove(&result.incident_id)
    else {
        debug!(
            incident_id = %result.incident_id,
            "Telegram approval for unknown or expired incident - ignoring"
        );
        return false;
    };

    // If "Always" - save trust rule before executing
    if result.always {
        info!(
            detector = %pending.detector,
            action = %pending.action_name,
            operator = %result.operator_name,
            "operator added trust rule via Telegram"
        );
        append_trust_rule(
            data_dir,
            &mut state.trust_rules,
            &pending.detector,
            &pending.action_name,
        );
    }

    // Acknowledge in Telegram: remove inline keyboard and add follow-up message
    let tg = state.telegram_client.clone();
    if let Some(ref tg) = tg {
        let _ = tg
            .resolve_confirmation(
                pending.telegram_message_id,
                result.approved,
                result.always,
                &result.operator_name,
            )
            .await;
    }

    let (exec_result, _cf_pushed) = if result.approved {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            always = result.always,
            "operator approved action via Telegram"
        );
        execute_decision(&decision, &incident, data_dir, cfg, state).await
    } else {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            "operator rejected action via Telegram"
        );
        (
            format!("rejected by operator {}", result.operator_name),
            false,
        )
    };

    // Audit trail with ai_provider = "telegram:<operator>"
    if let Some(writer) = &mut state.decision_writer {
        let provider = format!("telegram:{}", result.operator_name);
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            &provider,
            &decision,
            cfg.responder.dry_run,
            &exec_result,
        );
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write Telegram decision entry: {e:#}");
        }
    }

    true
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}
