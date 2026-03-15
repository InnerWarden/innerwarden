use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use super::{AiDecision, AiProvider, DecisionContext};
use crate::ai::openai::{build_prompt_pub, parse_decision_pub, system_prompt};

// ---------------------------------------------------------------------------
// Ollama provider — local LLM via http://localhost:11434 (or configurable)
// ---------------------------------------------------------------------------
//
// Ollama exposes an OpenAI-compatible /api/chat endpoint.
// Key differences from the hosted APIs:
//   - No API key required for local instances
//   - Response schema: `message.content` instead of `choices[0].message.content`
//   - JSON mode: `"format": "json"` (not `response_format`)
//   - Temperature/options live under `"options"` object
//   - Default endpoint: http://localhost:11434/api/chat
//
// Compatible models: llama3.2, llama3.1, mistral, gemma2, qwen2.5, etc.
// Install a model: `ollama pull llama3.2`

pub struct OllamaProvider {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(base_url: String, model: String) -> Self {
        let client = reqwest::Client::builder()
            // Local inference can be slow depending on hardware
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("failed to build Ollama HTTP client");
        Self {
            base_url,
            model,
            client,
        }
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let prompt = build_prompt_pub(ctx);
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

        debug!(model = %self.model, url = %url, "calling Ollama API");

        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system_prompt() },
                { "role": "user",   "content": prompt }
            ],
            "stream": false,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "num_predict": 512,
            }
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Ollama request to {url} failed — is Ollama running? \
                     Start it with: ollama serve"
                )
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            // Surface a helpful message for the most common error: model not pulled
            if status.as_u16() == 404 || text.contains("model") {
                bail!(
                    "Ollama returned {status}: {}\n\
                     Hint: pull the model first with: ollama pull {}",
                    text.chars().take(200).collect::<String>(),
                    self.model
                );
            }
            bail!(
                "Ollama returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }

        let completion: OllamaResponse = resp
            .json()
            .await
            .context("failed to parse Ollama response")?;

        let content = completion.message.content;
        if content.is_empty() {
            bail!("Ollama returned an empty response for model {}", self.model);
        }

        // Some models wrap the JSON in prose despite format:json.
        // extract_json handles that gracefully.
        let json_str = extract_json(&content)
            .with_context(|| format!("Ollama response contained no JSON object: {content}"))?;

        parse_decision_pub(json_str)
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Deserialize)]
struct OllamaMessage {
    content: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the first `{...}` JSON object from text that may contain prose.
fn extract_json(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end >= start {
        Some(&text[start..=end])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_bare_object() {
        let s = r#"{"action":"ignore","confidence":0.5}"#;
        assert_eq!(extract_json(s), Some(s));
    }

    #[test]
    fn extract_json_strips_prose() {
        let s = r#"Sure! Here is my answer: {"action":"ignore","confidence":0.5} Hope that helps."#;
        assert_eq!(
            extract_json(s),
            Some(r#"{"action":"ignore","confidence":0.5}"#)
        );
    }

    #[test]
    fn extract_json_returns_none_for_no_braces() {
        assert_eq!(extract_json("no json here"), None);
    }

    #[test]
    fn new_uses_supplied_values() {
        let p = OllamaProvider::new("http://192.168.1.10:11434".into(), "mistral".into());
        assert_eq!(p.base_url, "http://192.168.1.10:11434");
        assert_eq!(p.model, "mistral");
    }

    #[test]
    fn url_construction_strips_trailing_slash() {
        let p = OllamaProvider::new("http://localhost:11434/".into(), "llama3.2".into());
        let url = format!("{}/api/chat", p.base_url.trim_end_matches('/'));
        assert_eq!(url, "http://localhost:11434/api/chat");
    }
}
