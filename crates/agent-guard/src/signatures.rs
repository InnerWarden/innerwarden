//! AI agent and tool signatures for auto-detection.
//!
//! Distinction:
//! - **Agent**: autonomous, persistent memory, runs 24/7 (OpenClaw, ZeroClaw)
//!   → installable via `innerwarden agent add`
//! - **Tool**: CLI/editor, no persistent memory, runs per-task (Claude Code, Aider)
//!   → auto-detected and monitored, not installed by us

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Kind {
    /// Autonomous agent with persistent memory — installable via `innerwarden agent add`
    Agent,
    /// CLI tool / coding assistant — auto-detected, monitored
    Tool,
    /// LLM runtime — auto-detected, API monitored
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum IntegrationLevel {
    /// Tested, validated, full integration (MCP wrap, command validation)
    Official,
    /// eBPF monitoring only (process, file, network)
    Monitored,
}

pub struct Signature {
    pub name: &'static str,
    pub vendor: &'static str,
    pub kind: Kind,
    pub integration: IntegrationLevel,
    pub process_names: &'static [&'static str],
    pub install_cmd: Option<&'static str>,
}

pub static KNOWN: &[Signature] = &[
    // ═══════════════════════════════════════════════════════════
    // AGENTS — autonomous, persistent memory, `innerwarden agent add`
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "OpenClaw",
        vendor: "Peter Steinberger",
        kind: Kind::Agent,
        integration: IntegrationLevel::Official,
        process_names: &["openclaw", "moltbot", "clawdbot", "molty"],
        install_cmd: Some("npm install -g @anthropic-ai/openclaw"),
    },
    Signature {
        name: "ZeroClaw",
        vendor: "ZeroClaw Labs",
        kind: Kind::Agent,
        integration: IntegrationLevel::Official,
        process_names: &["zeroclaw", "zeroclaw-agent"],
        install_cmd: Some("cargo install zeroclaw"),
    },
    // ═══════════════════════════════════════════════════════════
    // TOOLS — CLI / coding assistants, auto-detected
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "Claude Code",
        vendor: "Anthropic",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["claude", "claude-code"],
        install_cmd: None,
    },
    Signature {
        name: "Codex CLI",
        vendor: "OpenAI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["codex", "openai-codex"],
        install_cmd: None,
    },
    Signature {
        name: "Gemini CLI",
        vendor: "Google",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["gemini", "gemini-cli"],
        install_cmd: None,
    },
    Signature {
        name: "Aider",
        vendor: "Aider-AI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["aider"],
        install_cmd: None,
    },
    Signature {
        name: "Goose",
        vendor: "Block",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["goose"],
        install_cmd: None,
    },
    Signature {
        name: "Cursor",
        vendor: "Anysphere",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["cursor", "Cursor"],
        install_cmd: None,
    },
    Signature {
        name: "Windsurf",
        vendor: "Codeium",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["windsurf", "Windsurf"],
        install_cmd: None,
    },
    Signature {
        name: "Cline",
        vendor: "Community",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["cline"],
        install_cmd: None,
    },
    Signature {
        name: "GitHub Copilot",
        vendor: "GitHub",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["copilot-agent", "copilot", "copilot-language-server"],
        install_cmd: None,
    },
    Signature {
        name: "Devin",
        vendor: "Cognition",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["devin", "devin-agent"],
        install_cmd: None,
    },
    Signature {
        name: "OpenHands",
        vendor: "All Hands AI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["openhands", "opendevin"],
        install_cmd: None,
    },
    Signature {
        name: "SWE-agent",
        vendor: "Princeton NLP",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["swe-agent", "sweagent"],
        install_cmd: None,
    },
    Signature {
        name: "AutoGPT",
        vendor: "Significant Gravitas",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["autogpt", "auto-gpt"],
        install_cmd: None,
    },
    Signature {
        name: "MetaGPT",
        vendor: "DeepWisdom",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["metagpt"],
        install_cmd: None,
    },
    // ═══════════════════════════════════════════════════════════
    // RUNTIMES — LLM servers, API monitored
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "Ollama",
        vendor: "Ollama",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["ollama", "ollama_llama_server"],
        install_cmd: None,
    },
    Signature {
        name: "vLLM",
        vendor: "vLLM Project",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["vllm", "vllm-server"],
        install_cmd: None,
    },
    Signature {
        name: "llama.cpp",
        vendor: "ggerganov",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["llama-server", "llama-cli"],
        install_cmd: None,
    },
    Signature {
        name: "LM Studio",
        vendor: "LM Studio",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["lm-studio", "lms"],
        install_cmd: None,
    },
];

pub struct SignatureIndex {
    by_process: HashMap<String, usize>,
}

impl SignatureIndex {
    pub fn new() -> Self {
        let mut by_process = HashMap::new();
        for (i, sig) in KNOWN.iter().enumerate() {
            for name in sig.process_names {
                by_process.insert(name.to_lowercase(), i);
            }
        }
        Self { by_process }
    }

    pub fn identify(&self, process_name: &str) -> Option<&'static Signature> {
        let lower = process_name.to_lowercase();
        if let Some(&idx) = self.by_process.get(&lower) {
            return Some(&KNOWN[idx]);
        }
        for (key, &idx) in &self.by_process {
            if lower.starts_with(key.as_str()) {
                return Some(&KNOWN[idx]);
            }
        }
        None
    }

    pub fn is_known(&self, process_name: &str) -> bool {
        self.identify(process_name).is_some()
    }

    /// Agents that can be installed via `innerwarden agent add`.
    pub fn installable_agents() -> Vec<&'static Signature> {
        KNOWN
            .iter()
            .filter(|s| s.kind == Kind::Agent && s.install_cmd.is_some())
            .collect()
    }
}

impl Default for SignatureIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_agents() {
        let idx = SignatureIndex::new();
        let oc = idx.identify("openclaw").unwrap();
        assert_eq!(oc.kind, Kind::Agent);
        let zc = idx.identify("zeroclaw").unwrap();
        assert_eq!(zc.kind, Kind::Agent);
    }

    #[test]
    fn identifies_tools() {
        let idx = SignatureIndex::new();
        let cc = idx.identify("claude").unwrap();
        assert_eq!(cc.kind, Kind::Tool);
    }

    #[test]
    fn identifies_runtimes() {
        let idx = SignatureIndex::new();
        let ol = idx.identify("ollama").unwrap();
        assert_eq!(ol.kind, Kind::Runtime);
    }

    #[test]
    fn installable_agents_exist() {
        let agents = SignatureIndex::installable_agents();
        assert!(agents.len() >= 2);
        assert!(agents.iter().any(|a| a.name == "OpenClaw"));
        assert!(agents.iter().any(|a| a.name == "ZeroClaw"));
    }

    #[test]
    fn unknown_not_found() {
        let idx = SignatureIndex::new();
        assert!(!idx.is_known("nginx"));
    }
}
