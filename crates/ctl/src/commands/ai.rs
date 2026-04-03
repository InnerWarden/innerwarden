use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use crate::{
    cmd_ai_install, config_editor, prompt, require_sudo, restart_agent, write_env_key, Cli,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct WizardProvider {
    pub(crate) name: &'static str,
    pub(crate) label: &'static str,
    pub(crate) signup_url: &'static str,
    pub(crate) models_url: &'static str,
    pub(crate) api_style: &'static str,
}

pub(crate) const WIZARD_PROVIDERS: &[WizardProvider] = &[
    WizardProvider {
        name: "openai",
        label: "OpenAI",
        signup_url: "platform.openai.com",
        models_url: "https://api.openai.com",
        api_style: "openai",
    },
    WizardProvider {
        name: "anthropic",
        label: "Anthropic",
        signup_url: "console.anthropic.com",
        models_url: "https://api.anthropic.com",
        api_style: "anthropic",
    },
    WizardProvider {
        name: "groq",
        label: "Groq",
        signup_url: "console.groq.com",
        models_url: "https://api.groq.com/openai",
        api_style: "openai",
    },
    WizardProvider {
        name: "deepseek",
        label: "DeepSeek",
        signup_url: "platform.deepseek.com",
        models_url: "https://api.deepseek.com",
        api_style: "openai",
    },
    WizardProvider {
        name: "together",
        label: "Together",
        signup_url: "api.together.ai",
        models_url: "https://api.together.xyz",
        api_style: "openai",
    },
    WizardProvider {
        name: "minimax",
        label: "MiniMax",
        signup_url: "platform.minimaxi.com",
        models_url: "https://api.minimaxi.chat",
        api_style: "openai",
    },
    WizardProvider {
        name: "mistral",
        label: "Mistral",
        signup_url: "console.mistral.ai",
        models_url: "https://api.mistral.ai",
        api_style: "openai",
    },
    WizardProvider {
        name: "xai",
        label: "xAI / Grok",
        signup_url: "console.x.ai",
        models_url: "https://api.x.ai",
        api_style: "openai",
    },
    WizardProvider {
        name: "fireworks",
        label: "Fireworks",
        signup_url: "fireworks.ai",
        models_url: "https://api.fireworks.ai/inference",
        api_style: "openai",
    },
    WizardProvider {
        name: "openrouter",
        label: "OpenRouter",
        signup_url: "openrouter.ai",
        models_url: "https://openrouter.ai/api",
        api_style: "openai",
    },
    WizardProvider {
        name: "gemini",
        label: "Google Gemini",
        signup_url: "aistudio.google.com",
        models_url: "https://generativelanguage.googleapis.com",
        api_style: "gemini",
    },
];

pub(crate) fn fetch_models(base_url: &str, api_key: &str, api_style: &str) -> Vec<String> {
    let url = match api_style {
        "anthropic" => format!("{base_url}/v1/models"),
        "ollama" => format!("{base_url}/api/tags"),
        "gemini" => format!("{base_url}/v1beta/models?key={api_key}"),
        _ => format!("{base_url}/v1/models"),
    };

    let resp = match api_style {
        "anthropic" => ureq::get(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .call(),
        "gemini" => ureq::get(&url).call(),
        _ => ureq::get(&url)
            .header("Authorization", &format!("Bearer {api_key}"))
            .call(),
    };

    let resp = match resp {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let body: serde_json::Value = match resp.into_body().read_json() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let models: Vec<String> = if api_style == "gemini" {
        body.get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.strip_prefix("models/").unwrap_or(s).to_string())
                    })
                    .filter(|m| {
                        let l = m.to_lowercase();
                        l.contains("gemini") && !l.contains("embed") && !l.contains("aqa")
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else if api_style == "ollama" {
        body.get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        body.get("data")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("id")
                            .and_then(|id| id.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut filtered: Vec<String> = models
        .into_iter()
        .filter(|m| {
            let l = m.to_lowercase();
            !l.contains("embed")
                && !l.contains("tts")
                && !l.contains("whisper")
                && !l.contains("dall-e")
                && !l.contains("davinci")
                && !l.contains("babbage")
                && !l.contains("moderation")
                && !l.contains("search")
        })
        .collect();
    filtered.sort();
    filtered
}

fn ask_key_and_model(
    provider: &WizardProvider,
    custom_base_url: Option<&str>,
) -> Result<(String, Option<String>)> {
    println!(
        "{} - enter your API key (get one at {})",
        provider.label, provider.signup_url
    );
    let key = prompt("API key")?;
    if key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }

    let base_url = custom_base_url.unwrap_or(provider.models_url);
    print!("\n  Fetching available models...");
    std::io::stdout().flush().ok();
    let models = fetch_models(base_url, &key, provider.api_style);

    if models.is_empty() {
        println!(" could not fetch model list.");
        println!("  Enter a model name manually, or press Enter for the provider default.\n");
        let model = prompt("Model")?;
        let model = if model.is_empty() { None } else { Some(model) };
        return Ok((key, model));
    }

    println!(" found {} models.\n", models.len());
    let show = models.len().min(20);
    for (i, m) in models.iter().take(show).enumerate() {
        println!("  {:>2}. {}", i + 1, m);
    }
    if models.len() > show {
        println!(
            "  ... and {} more (type the name to use any)",
            models.len() - show
        );
    }
    println!();
    let model_choice = prompt(&format!("Model [1-{show}, or type name, default=1]"))?;
    let trimmed = model_choice.trim();

    let model = if trimmed.is_empty() {
        models[0].clone()
    } else if let Ok(idx) = trimmed.parse::<usize>() {
        let idx = idx.saturating_sub(1).min(models.len() - 1);
        models[idx].clone()
    } else {
        trimmed.to_string()
    };

    Ok((key, Some(model)))
}

pub(crate) fn cmd_configure_ai_interactive(cli: &Cli) -> Result<()> {
    println!("InnerWarden - AI provider setup\n");
    println!("InnerWarden uses AI to evaluate threats and decide how to respond.");
    println!("Choose a provider - any one works. Pick what you already have:\n");
    for (i, p) in WIZARD_PROVIDERS.iter().enumerate() {
        println!("  {}. {}", i + 1, p.label);
    }
    let ollama_idx = WIZARD_PROVIDERS.len() + 1;
    let other_idx = WIZARD_PROVIDERS.len() + 2;
    println!("  {ollama_idx}. Ollama       - local, no API key needed");
    println!("  {other_idx}. Other        - any OpenAI-compatible API");
    println!("  s. Skip for now\n");

    let choice = prompt(&format!("Choose provider [1-{other_idx}/s]"))?;
    println!();

    let trimmed = choice.trim().to_lowercase();
    if trimmed == "s" {
        println!("Skipped. Run later:  innerwarden configure ai <provider> --key <key>");
        return Ok(());
    }

    let num: usize = trimmed.parse().unwrap_or(0);

    if num >= 1 && num <= WIZARD_PROVIDERS.len() {
        let provider = &WIZARD_PROVIDERS[num - 1];
        let (key, model) = ask_key_and_model(provider, None)?;
        cmd_configure_ai(cli, provider.name, Some(&key), model.as_deref(), None)
    } else if num == ollama_idx {
        let local_models = fetch_models("http://localhost:11434", "", "ollama");
        if local_models.is_empty() {
            println!("Ollama not running locally. Installing...\n");
            cmd_ai_install(cli, "qwen3-coder:480b", None, false)
        } else {
            println!("Found {} local Ollama models:\n", local_models.len());
            for (i, m) in local_models.iter().enumerate() {
                println!("  {}. {}", i + 1, m);
            }
            println!();
            let mc = prompt(&format!("Model [1-{}, default=1]", local_models.len()))?;
            let idx = mc
                .trim()
                .parse::<usize>()
                .unwrap_or(1)
                .saturating_sub(1)
                .min(local_models.len() - 1);
            cmd_configure_ai(cli, "ollama", None, Some(&local_models[idx]), None)
        }
    } else if num == other_idx {
        println!("Any provider with an OpenAI-compatible API works.\n");
        let name = prompt("Provider name (e.g. fireworks, openrouter, together)")?;
        let base_url = prompt("Base URL (e.g. https://api.example.com)")?;
        if base_url.is_empty() {
            anyhow::bail!("Base URL is required");
        }
        println!("\n{name} - enter your API key");
        let key = prompt("API key")?;
        if key.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }
        print!("\n  Fetching available models...");
        std::io::stdout().flush().ok();
        let models = fetch_models(&base_url, &key, "openai");
        let model = if models.is_empty() {
            println!(" could not fetch model list.");
            let m = prompt("Model name")?;
            if m.is_empty() {
                None
            } else {
                Some(m)
            }
        } else {
            println!(" found {} models.\n", models.len());
            let show = models.len().min(20);
            for (i, m) in models.iter().take(show).enumerate() {
                println!("  {:>2}. {}", i + 1, m);
            }
            println!();
            let mc = prompt(&format!("Model [1-{show}, default=1]"))?;
            let trimmed = mc.trim();
            Some(if trimmed.is_empty() {
                models[0].clone()
            } else if let Ok(idx) = trimmed.parse::<usize>() {
                models[idx.saturating_sub(1).min(models.len() - 1)].clone()
            } else {
                trimmed.to_string()
            })
        };
        cmd_configure_ai(cli, &name, Some(&key), model.as_deref(), Some(&base_url))
    } else {
        println!("Skipped. Run later:  innerwarden configure ai <provider> --key <key>");
        Ok(())
    }
}

pub(crate) fn cmd_configure_ai(
    cli: &Cli,
    provider: &str,
    key: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let (default_model, key_var, default_base_url) =
        crate::commands::setup::ai_provider_defaults(provider);
    let model = model.unwrap_or(&default_model);

    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    if let Some(var) = key_var {
        let k = key.ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' requires an API key.\nRun:\n  innerwarden configure ai {} --key <your-key>",
                provider,
                provider
            )
        })?;

        if cli.dry_run {
            println!(
                "  [dry-run] would write {}=<redacted> to {}",
                var,
                env_file.display()
            );
        } else {
            write_env_key(&env_file, &var, k)?;
            println!("  [ok] {var} saved to {}", env_file.display());
        }
    }

    let base_url = base_url.or(default_base_url.as_deref());

    if cli.dry_run {
        match base_url {
            Some(url) => println!(
                "  [dry-run] would set [ai] enabled=true provider={provider} model={model} base_url={url} in {}",
                cli.agent_config.display()
            ),
            None => println!(
                "  [dry-run] would set [ai] enabled=true provider={provider} model={model} in {}",
                cli.agent_config.display()
            ),
        }
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", provider)?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        if let Some(url) = base_url {
            config_editor::write_str(&cli.agent_config, "ai", "base_url", url)?;
        }
        println!("  [ok] agent.toml updated (provider={provider}, model={model})");
    }

    restart_agent(cli);
    println!("AI configured. Run 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn prompt_ollama_api_key() -> Result<String> {
    println!("Ollama API key required.");
    println!();
    println!("  1. Create a free account at https://ollama.com");
    println!("  2. Go to https://ollama.com/settings/api-keys");
    println!("  3. Click 'New API Key', copy the key, and paste it below.");
    println!();
    print!("Ollama API key: ");
    std::io::stdout().flush()?;
    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        anyhow::bail!(
            "No API key provided.\n\
             You can also set the OLLAMA_API_KEY environment variable and re-run."
        );
    }
    Ok(key)
}
