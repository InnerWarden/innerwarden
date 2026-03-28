//! AI agent process signatures for auto-detection.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AgentCategory {
    CodingAssistant,
    CliAgent,
    Autonomous,
    DesktopApp,
    Framework,
    LocalLlm,
    BrowserAgent,
    DevSecOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum IntegrationLevel {
    /// Tested, validated, MCP auto-wrap, command validation
    Official,
    /// eBPF monitoring only (process, file, network)
    Monitored,
}

pub struct AgentSignature {
    pub name: &'static str,
    pub vendor: &'static str,
    pub category: AgentCategory,
    pub integration: IntegrationLevel,
    pub process_names: &'static [&'static str],
    pub mcp_config_paths: &'static [&'static str],
}

pub static KNOWN_AGENTS: &[AgentSignature] = &[
    // ── Official integrations ──────────────────────────────────
    AgentSignature {
        name: "Claude Code",
        vendor: "Anthropic",
        category: AgentCategory::CliAgent,
        integration: IntegrationLevel::Official,
        process_names: &["claude", "claude-code"],
        mcp_config_paths: &[".claude/.mcp.json", ".claude/mcp.json"],
    },
    AgentSignature {
        name: "OpenClaw",
        vendor: "Community",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Official,
        process_names: &["openclaw", "moltbot", "clawdbot"],
        mcp_config_paths: &[".openclaw/mcp.json"],
    },
    AgentSignature {
        name: "Aider",
        vendor: "Aider-AI",
        category: AgentCategory::CliAgent,
        integration: IntegrationLevel::Official,
        process_names: &["aider"],
        mcp_config_paths: &[".config/aider/mcp.json"],
    },
    AgentSignature {
        name: "Goose",
        vendor: "Block",
        category: AgentCategory::CliAgent,
        integration: IntegrationLevel::Official,
        process_names: &["goose"],
        mcp_config_paths: &[".config/goose/mcp.json"],
    },
    AgentSignature {
        name: "Codex CLI",
        vendor: "OpenAI",
        category: AgentCategory::CliAgent,
        integration: IntegrationLevel::Official,
        process_names: &["codex", "openai-codex"],
        mcp_config_paths: &[".codex/mcp.json"],
    },
    AgentSignature {
        name: "Gemini CLI",
        vendor: "Google",
        category: AgentCategory::CliAgent,
        integration: IntegrationLevel::Official,
        process_names: &["gemini", "gemini-cli"],
        mcp_config_paths: &[".gemini/mcp.json"],
    },
    AgentSignature {
        name: "Cursor",
        vendor: "Anysphere",
        category: AgentCategory::CodingAssistant,
        integration: IntegrationLevel::Official,
        process_names: &["cursor", "Cursor"],
        mcp_config_paths: &[".cursor/mcp.json"],
    },
    AgentSignature {
        name: "CrewAI",
        vendor: "CrewAI",
        category: AgentCategory::Framework,
        integration: IntegrationLevel::Official,
        process_names: &["crewai"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "LangChain",
        vendor: "LangChain",
        category: AgentCategory::Framework,
        integration: IntegrationLevel::Official,
        process_names: &["langchain", "langserve", "langgraph"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "Ollama",
        vendor: "Ollama",
        category: AgentCategory::LocalLlm,
        integration: IntegrationLevel::Official,
        process_names: &["ollama", "ollama_llama_server"],
        mcp_config_paths: &[],
    },
    // ── Monitored (eBPF only) ──────────────────────────────────
    AgentSignature {
        name: "Windsurf",
        vendor: "Codeium",
        category: AgentCategory::CodingAssistant,
        integration: IntegrationLevel::Monitored,
        process_names: &["windsurf", "Windsurf"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "GitHub Copilot",
        vendor: "GitHub",
        category: AgentCategory::CodingAssistant,
        integration: IntegrationLevel::Monitored,
        process_names: &["copilot-agent", "copilot", "copilot-language-server"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "Devin",
        vendor: "Cognition",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Monitored,
        process_names: &["devin", "devin-agent"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "OpenHands",
        vendor: "All Hands AI",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Monitored,
        process_names: &["openhands", "opendevin"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "SWE-agent",
        vendor: "Princeton NLP",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Monitored,
        process_names: &["swe-agent", "sweagent"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "AutoGPT",
        vendor: "Significant Gravitas",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Monitored,
        process_names: &["autogpt", "auto-gpt"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "MetaGPT",
        vendor: "DeepWisdom",
        category: AgentCategory::Autonomous,
        integration: IntegrationLevel::Monitored,
        process_names: &["metagpt"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "AutoGen",
        vendor: "Microsoft",
        category: AgentCategory::Framework,
        integration: IntegrationLevel::Monitored,
        process_names: &["autogen"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "vLLM",
        vendor: "vLLM Project",
        category: AgentCategory::LocalLlm,
        integration: IntegrationLevel::Monitored,
        process_names: &["vllm", "vllm-server"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "llama.cpp",
        vendor: "ggerganov",
        category: AgentCategory::LocalLlm,
        integration: IntegrationLevel::Monitored,
        process_names: &["llama-server", "llama-cli"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "n8n",
        vendor: "n8n.io",
        category: AgentCategory::Framework,
        integration: IntegrationLevel::Monitored,
        process_names: &["n8n"],
        mcp_config_paths: &[],
    },
    AgentSignature {
        name: "Dify",
        vendor: "LangGenius",
        category: AgentCategory::Framework,
        integration: IntegrationLevel::Monitored,
        process_names: &["dify"],
        mcp_config_paths: &[],
    },
];

pub struct AgentIndex {
    by_process: HashMap<String, usize>,
}

impl AgentIndex {
    pub fn new() -> Self {
        let mut by_process = HashMap::new();
        for (i, agent) in KNOWN_AGENTS.iter().enumerate() {
            for name in agent.process_names {
                by_process.insert(name.to_lowercase(), i);
            }
        }
        Self { by_process }
    }

    pub fn identify(&self, process_name: &str) -> Option<&'static AgentSignature> {
        let lower = process_name.to_lowercase();
        if let Some(&idx) = self.by_process.get(&lower) {
            return Some(&KNOWN_AGENTS[idx]);
        }
        for (key, &idx) in &self.by_process {
            if lower.starts_with(key.as_str()) {
                return Some(&KNOWN_AGENTS[idx]);
            }
        }
        None
    }

    pub fn is_agent(&self, process_name: &str) -> bool {
        self.identify(process_name).is_some()
    }

    pub fn official_count() -> usize {
        KNOWN_AGENTS
            .iter()
            .filter(|a| a.integration == IntegrationLevel::Official)
            .count()
    }

    pub fn total_count() -> usize {
        KNOWN_AGENTS.len()
    }
}

impl Default for AgentIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_official_agents() {
        let idx = AgentIndex::new();
        let claude = idx.identify("claude").unwrap();
        assert_eq!(claude.integration, IntegrationLevel::Official);
        let openclaw = idx.identify("openclaw").unwrap();
        assert_eq!(openclaw.integration, IntegrationLevel::Official);
    }

    #[test]
    fn identifies_monitored_agents() {
        let idx = AgentIndex::new();
        let devin = idx.identify("devin").unwrap();
        assert_eq!(devin.integration, IntegrationLevel::Monitored);
    }

    #[test]
    fn unknown_process_not_agent() {
        let idx = AgentIndex::new();
        assert!(!idx.is_agent("nginx"));
        assert!(!idx.is_agent("postgres"));
    }

    #[test]
    fn official_count_at_least_10() {
        assert!(AgentIndex::official_count() >= 10);
    }
}
