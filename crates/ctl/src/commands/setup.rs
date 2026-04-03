use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::commands::ai::{fetch_models, prompt_ollama_api_key, WIZARD_PROVIDERS};
use crate::commands::notify::cmd_configure_telegram;
use crate::{
    am_root, cmd_agent, cmd_enable, config_editor, load_env_file, prompt, reexec_with_sudo,
    resolve_dashboard_url, restart_agent, scan, systemd, write_env_key, AgentCommand,
    CapabilityRegistry, Cli,
};

#[derive(Debug, Clone)]
struct SetupCapabilityPlan {
    id: String,
    params: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct SetupPreconfigPlan {
    essential_capabilities: Vec<SetupCapabilityPlan>,
    set_telegram_min_severity: bool,
    set_webhook_min_severity: bool,
}

impl SetupPreconfigPlan {
    fn is_empty(&self) -> bool {
        self.essential_capabilities.is_empty()
            && !self.set_telegram_min_severity
            && !self.set_webhook_min_severity
    }
}

#[derive(Debug, Clone)]
enum SetupAiKey {
    None,
    Env { var: String, value: String },
    Config { value: String },
}

#[derive(Debug, Clone)]
struct SetupAiPlan {
    label: String,
    provider: String,
    model: String,
    base_url: Option<String>,
    key: SetupAiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupNotificationPlan {
    DashboardOnly,
    Telegram,
    TelegramAndDashboard,
}

impl SetupNotificationPlan {
    fn label(&self) -> &'static str {
        match self {
            Self::DashboardOnly => "Dashboard",
            Self::Telegram => "Telegram",
            Self::TelegramAndDashboard => "Telegram + Dashboard",
        }
    }

    fn needs_telegram(&self) -> bool {
        matches!(self, Self::Telegram | Self::TelegramAndDashboard)
    }
}

#[derive(Debug, Clone, Copy)]
struct SetupResponderPlan {
    dry_run: bool,
}

impl SetupResponderPlan {
    fn label(&self) -> &'static str {
        if self.dry_run {
            "Watch only"
        } else {
            "Auto-protect"
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SetupCheck {
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) ok: bool,
    pub(crate) critical: bool,
}

fn read_agent_doc(path: &Path) -> Option<toml_edit::DocumentMut> {
    std::fs::read_to_string(path).ok()?.parse().ok()
}

fn agent_bool(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> bool {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn agent_str(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> Option<String> {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn env_has(env_vars: &HashMap<String, String>, key: &str) -> bool {
    env_vars.get(key).is_some_and(|v| !v.trim().is_empty())
        || std::env::var(key).is_ok_and(|v| !v.trim().is_empty())
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

fn parse_setup_capability_hint(hint: &str) -> Option<SetupCapabilityPlan> {
    let parts: Vec<&str> = hint.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "innerwarden" || parts[1] != "enable" {
        return None;
    }

    let mut params = HashMap::new();
    let mut i = 3;
    while i < parts.len() {
        if parts[i] == "--param" && i + 1 < parts.len() {
            if let Some((k, v)) = parts[i + 1].split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Some(SetupCapabilityPlan {
        id: parts[2].to_string(),
        params,
    })
}

fn collect_setup_preconfig_plan(agent_doc: Option<&toml_edit::DocumentMut>) -> SetupPreconfigPlan {
    let probes = scan::run_probes();
    let recs = scan::score_modules(&probes);

    let essential_capabilities = recs
        .iter()
        .filter(|r| matches!(r.tier, scan::Tier::Essential))
        .filter_map(|r| parse_setup_capability_hint(&r.enable_hint))
        .collect();

    let set_telegram_min_severity = agent_doc
        .and_then(|d| d.get("telegram"))
        .and_then(|t| t.get("min_severity"))
        .is_none();
    let set_webhook_min_severity = agent_doc
        .and_then(|d| d.get("webhook"))
        .and_then(|t| t.get("min_severity"))
        .is_none();

    SetupPreconfigPlan {
        essential_capabilities,
        set_telegram_min_severity,
        set_webhook_min_severity,
    }
}

pub(crate) fn ai_provider_defaults(provider: &str) -> (String, Option<String>, Option<String>) {
    match provider {
        "openai" => (
            "gpt-4o-mini".to_string(),
            Some("OPENAI_API_KEY".to_string()),
            None,
        ),
        "anthropic" => (
            "claude-haiku-4-5-20251001".to_string(),
            Some("ANTHROPIC_API_KEY".to_string()),
            None,
        ),
        "ollama" => ("llama3.2".to_string(), None, None),
        "groq" => (
            "llama-3.3-70b-versatile".to_string(),
            Some("GROQ_API_KEY".to_string()),
            Some("https://api.groq.com/openai".to_string()),
        ),
        "deepseek" => (
            "deepseek-chat".to_string(),
            Some("DEEPSEEK_API_KEY".to_string()),
            Some("https://api.deepseek.com".to_string()),
        ),
        "together" => (
            "meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string(),
            Some("TOGETHER_API_KEY".to_string()),
            Some("https://api.together.xyz".to_string()),
        ),
        "minimax" => (
            "MiniMax-Text-01".to_string(),
            Some("MINIMAX_API_KEY".to_string()),
            Some("https://api.minimaxi.chat".to_string()),
        ),
        "mistral" => (
            "mistral-small-latest".to_string(),
            Some("MISTRAL_API_KEY".to_string()),
            Some("https://api.mistral.ai".to_string()),
        ),
        "xai" => (
            "grok-3-mini-fast".to_string(),
            Some("XAI_API_KEY".to_string()),
            Some("https://api.x.ai".to_string()),
        ),
        "fireworks" => (
            "accounts/fireworks/models/llama-v3p3-70b-instruct".to_string(),
            Some("FIREWORKS_API_KEY".to_string()),
            Some("https://api.fireworks.ai/inference".to_string()),
        ),
        "openrouter" => (
            "meta-llama/llama-3.3-70b-instruct".to_string(),
            Some("OPENROUTER_API_KEY".to_string()),
            Some("https://openrouter.ai/api".to_string()),
        ),
        "gemini" => (
            "gemini-2.0-flash".to_string(),
            Some("GEMINI_API_KEY".to_string()),
            Some("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
        ),
        _ => (
            "gpt-4o-mini".to_string(),
            Some(format!("{}_API_KEY", provider.to_uppercase())),
            None,
        ),
    }
}

fn build_setup_ai_plan(
    provider: &str,
    label: &str,
    key: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
) -> SetupAiPlan {
    let (default_model, key_var, default_base_url) = ai_provider_defaults(provider);
    let effective_model = model.unwrap_or(default_model);
    let effective_base_url = base_url.or(default_base_url);
    let key = match key {
        None => SetupAiKey::None,
        Some(value)
            if provider == "ollama"
                && effective_base_url.as_deref() == Some("https://api.ollama.com") =>
        {
            SetupAiKey::Config { value }
        }
        Some(value) => SetupAiKey::Env {
            var: key_var.unwrap_or_else(|| format!("{}_API_KEY", provider.to_uppercase())),
            value,
        },
    };

    SetupAiPlan {
        label: label.to_string(),
        provider: provider.to_string(),
        model: effective_model,
        base_url: effective_base_url,
        key,
    }
}

fn prompt_setup_other_ai_plan() -> Result<Option<SetupAiPlan>> {
    let other_providers = [
        "groq",
        "deepseek",
        "together",
        "minimax",
        "mistral",
        "xai",
        "fireworks",
        "openrouter",
        "gemini",
    ];

    println!("  Other provider\n");
    for (idx, provider_name) in other_providers.iter().enumerate() {
        let provider = WIZARD_PROVIDERS
            .iter()
            .find(|p| p.name == *provider_name)
            .expect("wizard provider exists");
        println!("  {}. {}", idx + 1, provider.label);
    }
    let custom_idx = other_providers.len() + 1;
    println!("  {custom_idx}. Custom OpenAI-compatible\n");

    let choice = prompt(&format!("  Choose [1-{custom_idx}]"))?;
    let trimmed = choice.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let idx = trimmed.parse::<usize>().unwrap_or(0);
    if (1..=other_providers.len()).contains(&idx) {
        let provider_name = other_providers[idx - 1];
        let provider = WIZARD_PROVIDERS
            .iter()
            .find(|p| p.name == provider_name)
            .expect("wizard provider exists");
        let key = prompt(&format!("  {} API key", provider.label))?;
        if key.is_empty() {
            return Ok(None);
        }
        return Ok(Some(build_setup_ai_plan(
            provider.name,
            provider.label,
            Some(key),
            None,
            None,
        )));
    }

    if idx == custom_idx {
        let provider = prompt("  Provider name")?;
        let base_url = prompt("  Base URL")?;
        let key = prompt("  API key")?;
        let model = prompt("  Model")?;

        if provider.is_empty() || base_url.is_empty() || key.is_empty() || model.is_empty() {
            return Ok(None);
        }

        return Ok(Some(build_setup_ai_plan(
            &provider,
            &provider,
            Some(key),
            Some(model),
            Some(base_url),
        )));
    }

    Ok(None)
}

fn prompt_setup_ai_plan() -> Result<Option<SetupAiPlan>> {
    println!("  [2/4] AI\n");
    println!("  1. Ollama Local");
    println!("  2. OpenAI");
    println!("  3. Anthropic");
    println!("  4. Ollama Cloud");
    println!("  5. Other\n");

    let choice = prompt("  Choose [1-5]")?;
    println!();

    match choice.trim() {
        "1" => {
            let local_models = fetch_models("http://localhost:11434", "", "ollama");
            if local_models.is_empty() {
                println!("  No local Ollama model found.");
                println!("  Use Ollama Cloud or another provider.\n");
                return Ok(None);
            }

            for (i, model) in local_models.iter().enumerate() {
                println!("  {}. {}", i + 1, model);
            }
            println!();
            let model_choice = prompt(&format!("  Model [1-{}, default=1]", local_models.len()))?;
            let idx = model_choice
                .trim()
                .parse::<usize>()
                .unwrap_or(1)
                .saturating_sub(1)
                .min(local_models.len() - 1);

            Ok(Some(build_setup_ai_plan(
                "ollama",
                "Ollama Local",
                None,
                Some(local_models[idx].clone()),
                None,
            )))
        }
        "2" => {
            let key = prompt("  OpenAI API key")?;
            if key.is_empty() {
                Ok(None)
            } else {
                Ok(Some(build_setup_ai_plan(
                    "openai",
                    "OpenAI",
                    Some(key),
                    None,
                    None,
                )))
            }
        }
        "3" => {
            let key = prompt("  Anthropic API key")?;
            if key.is_empty() {
                Ok(None)
            } else {
                Ok(Some(build_setup_ai_plan(
                    "anthropic",
                    "Anthropic",
                    Some(key),
                    None,
                    None,
                )))
            }
        }
        "4" => {
            let key = prompt_ollama_api_key()?;
            Ok(Some(build_setup_ai_plan(
                "ollama",
                "Ollama Cloud",
                Some(key),
                Some("qwen3-coder:480b".to_string()),
                Some("https://api.ollama.com".to_string()),
            )))
        }
        "5" => prompt_setup_other_ai_plan(),
        _ => Ok(None),
    }
}

fn apply_setup_ai_plan(cli: &Cli, env_file: &Path, plan: &SetupAiPlan) -> Result<()> {
    match &plan.key {
        SetupAiKey::None => {}
        SetupAiKey::Env { var, value } => write_env_key(env_file, var, value)?,
        SetupAiKey::Config { value } => {
            config_editor::write_str(&cli.agent_config, "ai", "api_key", value)?;
        }
    }

    config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
    config_editor::write_str(&cli.agent_config, "ai", "provider", &plan.provider)?;
    config_editor::write_str(&cli.agent_config, "ai", "model", &plan.model)?;
    if let Some(base_url) = &plan.base_url {
        config_editor::write_str(&cli.agent_config, "ai", "base_url", base_url)?;
    }

    Ok(())
}

fn setup_current_ai_summary(agent_doc: Option<&toml_edit::DocumentMut>) -> String {
    let provider = agent_str(agent_doc, "ai", "provider").unwrap_or_else(|| "configured".into());
    let model = agent_str(agent_doc, "ai", "model").unwrap_or_default();
    if model.is_empty() {
        provider
    } else {
        format!("{provider} ({model})")
    }
}

pub(crate) fn count_failed_setup_checks(checks: &[SetupCheck]) -> usize {
    checks
        .iter()
        .filter(|check| check.critical && !check.ok)
        .count()
}

fn collect_setup_checks(
    cli: &Cli,
    env_file: &Path,
    notification_plan: SetupNotificationPlan,
    responder_plan: SetupResponderPlan,
    expect_mesh: bool,
    detected_agents: usize,
) -> Vec<SetupCheck> {
    let agent_doc = read_agent_doc(&cli.agent_config);
    let env_vars = load_env_file(env_file);
    let is_macos = std::env::consts::OS == "macos";
    let dashboard_url = resolve_dashboard_url(cli);
    let dashboard_status_url = format!("{dashboard_url}/api/status");
    let dashboard_ok = ureq::get(&dashboard_status_url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .call()
        .map(|resp| resp.status().as_u16() < 500)
        .unwrap_or(false);
    let agent_running = if is_macos {
        std::process::Command::new("launchctl")
            .args(["list", "com.innerwarden.agent"])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\""))
            .unwrap_or(false)
    } else {
        systemd::is_service_active("innerwarden-agent")
    };

    let ai_ready = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let telegram_ready = env_has(&env_vars, "TELEGRAM_BOT_TOKEN")
        && env_has(&env_vars, "TELEGRAM_CHAT_ID")
        && agent_bool(agent_doc.as_ref(), "telegram", "enabled");
    let responder_ready = agent_bool(agent_doc.as_ref(), "responder", "enabled")
        && agent_bool(agent_doc.as_ref(), "responder", "dry_run") == responder_plan.dry_run;
    let mesh_ready = if expect_mesh {
        agent_bool(agent_doc.as_ref(), "mesh", "enabled")
    } else {
        true
    };
    let notifications_ready = match notification_plan {
        SetupNotificationPlan::DashboardOnly => dashboard_ok,
        SetupNotificationPlan::Telegram | SetupNotificationPlan::TelegramAndDashboard => {
            telegram_ready
        }
    };

    vec![
        SetupCheck {
            label: "AI".to_string(),
            detail: if ai_ready {
                setup_current_ai_summary(agent_doc.as_ref())
            } else {
                "not configured".to_string()
            },
            ok: ai_ready,
            critical: true,
        },
        SetupCheck {
            label: "Alerts".to_string(),
            detail: if notifications_ready {
                notification_plan.label().to_string()
            } else {
                format!("{} not ready", notification_plan.label())
            },
            ok: notifications_ready,
            critical: true,
        },
        SetupCheck {
            label: "Protection".to_string(),
            detail: responder_plan.label().to_string(),
            ok: responder_ready,
            critical: true,
        },
        SetupCheck {
            label: "Agent service".to_string(),
            detail: if agent_running {
                "running".to_string()
            } else {
                "not running".to_string()
            },
            ok: agent_running,
            critical: true,
        },
        SetupCheck {
            label: "Dashboard".to_string(),
            detail: if dashboard_ok {
                dashboard_url
            } else {
                "not reachable".to_string()
            },
            ok: dashboard_ok,
            critical: false,
        },
        SetupCheck {
            label: "Mesh".to_string(),
            detail: if expect_mesh {
                "enabled".to_string()
            } else {
                "not enabled".to_string()
            },
            ok: mesh_ready,
            critical: false,
        },
        SetupCheck {
            label: "AI agents".to_string(),
            detail: if detected_agents == 0 {
                "none detected".to_string()
            } else if detected_agents == 1 {
                "1 detected".to_string()
            } else {
                format!("{detected_agents} detected")
            },
            ok: detected_agents > 0,
            critical: false,
        },
    ]
}

pub(crate) fn cmd_setup(cli: &Cli) -> Result<()> {
    if !am_root() {
        return reexec_with_sudo();
    }

    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);
    let agent_doc = read_agent_doc(&cli.agent_config);

    let ai_ok = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let telegram_ok =
        env_has(&env_vars, "TELEGRAM_BOT_TOKEN") && env_has(&env_vars, "TELEGRAM_CHAT_ID");
    let responder_ok = agent_bool(agent_doc.as_ref(), "responder", "enabled");
    let mesh_ok = agent_bool(agent_doc.as_ref(), "mesh", "enabled");

    println!();
    println!("  Setup  (4 quick steps)\n");

    let preconfig_plan = collect_setup_preconfig_plan(agent_doc.as_ref());
    let apply_preconfig = if preconfig_plan.is_empty() {
        false
    } else {
        println!("  Safe defaults\n");
        for capability in &preconfig_plan.essential_capabilities {
            println!("  - Enable {}", capability.id);
        }
        if preconfig_plan.set_telegram_min_severity {
            println!("  - Telegram alerts: High + Critical");
        }
        if preconfig_plan.set_webhook_min_severity {
            println!("  - Webhook alerts: High + Critical");
        }
        println!();
        prompt_yes_no("  Apply these during setup? [Y/n] ", true)?
    };

    println!();

    let profile_already_set = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("telegram"))
        .and_then(|t| t.get("user_profile"))
        .is_some();
    let current_profile = agent_str(agent_doc.as_ref(), "telegram", "user_profile")
        .unwrap_or_else(|| "simple".to_string());
    let profile_plan = if profile_already_set {
        println!("  [1/4] Experience         OK ({current_profile})");
        None
    } else {
        println!("  [1/4] Experience\n");
        println!("  1. Simple");
        println!("  2. Technical\n");
        let profile_choice = prompt("  Choose [1/2, default=1]")?;
        println!();
        Some(match profile_choice.trim() {
            "2" => "technical".to_string(),
            _ => "simple".to_string(),
        })
    };

    let ai_plan = if ai_ok {
        println!(
            "  [2/4] AI                 OK ({})",
            setup_current_ai_summary(agent_doc.as_ref())
        );
        None
    } else {
        let plan = prompt_setup_ai_plan()?;
        if let Some(plan) = &plan {
            println!("  Ready: {} ({})", plan.label, plan.model);
        } else {
            println!("  AI not set yet");
        }
        plan
    };

    println!();
    let notification_plan = if telegram_ok {
        println!("  [3/4] Alerts             OK (Telegram + Dashboard)");
        SetupNotificationPlan::TelegramAndDashboard
    } else {
        println!("  [3/4] Alerts\n");
        println!("  1. Telegram");
        println!("  2. Dashboard");
        println!("  3. Both\n");
        let choice = prompt("  Choose [1/2/3, default=1]")?;
        println!();
        match choice.trim() {
            "2" => SetupNotificationPlan::DashboardOnly,
            "3" => SetupNotificationPlan::TelegramAndDashboard,
            _ => SetupNotificationPlan::Telegram,
        }
    };

    let responder_plan = if responder_ok {
        let current = SetupResponderPlan {
            dry_run: agent_bool(agent_doc.as_ref(), "responder", "dry_run"),
        };
        println!("  [4/4] Protection         OK ({})", current.label());
        current
    } else {
        println!("  [4/4] Protection\n");
        println!("  1. Watch only");
        println!("  2. Auto-protect\n");
        let choice = prompt("  Choose [1/2, default=1]")?;
        println!();
        if choice.trim() == "2" {
            print!("  Type 'yes' to enable auto-protect: ");
            std::io::stdout().flush()?;
            let mut confirm = String::new();
            std::io::stdin().read_line(&mut confirm)?;
            if confirm.trim() == "yes" {
                SetupResponderPlan { dry_run: false }
            } else {
                SetupResponderPlan { dry_run: true }
            }
        } else {
            SetupResponderPlan { dry_run: true }
        }
    };

    println!();
    let enable_mesh = if mesh_ok {
        println!("  Mesh                OK (enabled)");
        true
    } else {
        let enabled = prompt_yes_no(
            "  Share threat blocks with your other InnerWarden nodes? [y/N] ",
            false,
        )?;
        println!();
        enabled
    };

    let review_profile = profile_plan
        .clone()
        .unwrap_or_else(|| current_profile.clone());
    let review_ai = ai_plan
        .as_ref()
        .map(|plan| format!("{} ({})", plan.label, plan.model))
        .unwrap_or_else(|| setup_current_ai_summary(agent_doc.as_ref()));

    println!("  Review\n");
    println!("  - Experience: {review_profile}");
    println!("  - AI: {review_ai}");
    println!("  - Alerts: {}", notification_plan.label());
    println!("  - Protection: {}", responder_plan.label());
    println!(
        "  - Mesh: {}",
        if enable_mesh {
            "enabled"
        } else {
            "not enabled"
        }
    );
    if apply_preconfig {
        if preconfig_plan.essential_capabilities.is_empty() {
            println!("  - Safe defaults: alert thresholds");
        } else {
            println!(
                "  - Safe defaults: {} capability change(s)",
                preconfig_plan.essential_capabilities.len()
            );
        }
    }
    println!(
        "  - Files: {} and {}",
        cli.agent_config.display(),
        env_file.display()
    );
    if !telegram_ok && notification_plan.needs_telegram() {
        println!("  - Telegram: guided setup will run after apply");
    }
    println!();

    if !prompt_yes_no("  Apply now? [Y/n] ", true)? {
        println!("\n  Setup cancelled. Nothing changed.");
        return Ok(());
    }

    println!();

    let registry = CapabilityRegistry::default_all();
    if apply_preconfig {
        for capability in &preconfig_plan.essential_capabilities {
            if let Err(err) = cmd_enable(
                cli,
                &registry,
                &capability.id,
                capability.params.clone(),
                true,
            ) {
                println!("  [warn] Could not enable {}: {err:#}", capability.id);
            }
        }
        if preconfig_plan.set_telegram_min_severity {
            let _ = config_editor::write_str(&cli.agent_config, "telegram", "min_severity", "high");
        }
        if preconfig_plan.set_webhook_min_severity {
            let _ = config_editor::write_str(&cli.agent_config, "webhook", "min_severity", "high");
        }
    }

    if let Some(profile) = &profile_plan {
        config_editor::write_str(&cli.agent_config, "telegram", "user_profile", profile)?;
    }

    if let Some(plan) = &ai_plan {
        apply_setup_ai_plan(cli, &env_file, plan)?;
    }

    config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
    config_editor::write_bool(
        &cli.agent_config,
        "responder",
        "dry_run",
        responder_plan.dry_run,
    )?;
    let mut restart_needed = true;

    if enable_mesh && !mesh_ok {
        config_editor::write_bool(&cli.agent_config, "mesh", "enabled", true)?;
        if agent_doc.as_ref().and_then(|doc| doc.get("mesh")).is_none() {
            config_editor::write_str(&cli.agent_config, "mesh", "bind", "0.0.0.0:8790")?;
            config_editor::write_int(&cli.agent_config, "mesh", "poll_secs", 30)?;
            config_editor::write_bool(&cli.agent_config, "mesh", "auto_broadcast", true)?;
        }
    }

    let needs_telegram_setup = !telegram_ok && notification_plan.needs_telegram();
    if needs_telegram_setup {
        println!("  Telegram\n");
        if let Err(err) = cmd_configure_telegram(cli, None, None, false) {
            println!("  [warn] Telegram setup did not finish: {err:#}");
        } else {
            restart_needed = false;
        }
    }

    if restart_needed {
        restart_agent(cli);
    }

    let detected_agents = {
        use innerwarden_agent_guard::detect;
        use innerwarden_agent_guard::signatures::SignatureIndex;

        let index = SignatureIndex::new();
        detect::scan_processes(&index).len()
    };

    if detected_agents > 0 {
        println!();
        let prompt = if detected_agents == 1 {
            "  We found 1 running AI agent. Connect it now? [Y/n] "
        } else {
            "  We found running AI agents. Connect them now? [Y/n] "
        };
        if prompt_yes_no(prompt, true)? {
            let connect_command = AgentCommand::Connect {
                pid: None,
                name: None,
                label: None,
            };
            let _ = cmd_agent(cli, Some(&connect_command));
        }
    } else {
        println!();
        println!("  No supported AI agents detected right now.");
    }

    let checks = collect_setup_checks(
        cli,
        &env_file,
        notification_plan,
        responder_plan,
        enable_mesh,
        detected_agents,
    );
    let critical_failures = count_failed_setup_checks(&checks);

    println!();
    if critical_failures == 0 {
        println!("  Ready to use\n");
    } else if critical_failures == 1 {
        println!("  Setup finished with 1 item to fix\n");
    } else {
        println!("  Setup finished with {critical_failures} items to fix\n");
    }

    for check in &checks {
        let status = if check.ok { "OK" } else { "FIX" };
        println!("  {:<14} {:<4} {}", check.label, status, check.detail);
    }

    println!();
    if critical_failures == 0 {
        println!("  Dashboard: {}", resolve_dashboard_url(cli));
        println!("  Re-run anytime: innerwarden setup");
    } else {
        println!("  Run innerwarden setup again after fixing the items above.");
    }

    Ok(())
}
