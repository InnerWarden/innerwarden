//! Auto-detection of AI agents running on the server.
//!
//! Scans /proc to find running processes that match known agent signatures.
//! Also scans home directories for MCP config files to discover which
//! MCP servers are configured (and can be auto-wrapped).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::signatures::{AgentIndex, AgentSignature, IntegrationLevel};

/// A detected AI agent running on the server.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedAgent {
    pub name: String,
    pub vendor: String,
    pub pid: u32,
    pub comm: String,
    pub integration: String,
    pub mcp_configs: Vec<PathBuf>,
}

/// Scan running processes for known AI agents.
pub fn scan_processes(index: &AgentIndex) -> Vec<DetectedAgent> {
    let mut found: HashMap<String, DetectedAgent> = HashMap::new();

    let proc = Path::new("/proc");
    if !proc.exists() {
        warn!("agent-guard: /proc not available, cannot scan processes");
        return vec![];
    }

    let entries = match std::fs::read_dir(proc) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "agent-guard: failed to read /proc");
            return vec![];
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric dirs (PIDs)
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read comm
        let comm_path = entry.path().join("comm");
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };

        if let Some(agent) = index.identify(&comm) {
            let key = agent.name.to_string();
            found.entry(key).or_insert_with(|| DetectedAgent {
                name: agent.name.to_string(),
                vendor: agent.vendor.to_string(),
                pid,
                comm: comm.clone(),
                integration: match agent.integration {
                    IntegrationLevel::Official => "official".to_string(),
                    IntegrationLevel::Monitored => "monitored".to_string(),
                },
                mcp_configs: vec![],
            });
        }
    }

    let mut results: Vec<DetectedAgent> = found.into_values().collect();
    results.sort_by(|a, b| a.name.cmp(&b.name));

    if results.is_empty() {
        info!("agent-guard: no AI agents detected");
    } else {
        for agent in &results {
            info!(
                name = %agent.name,
                pid = agent.pid,
                integration = %agent.integration,
                "agent-guard: detected AI agent"
            );
        }
    }

    results
}

/// Scan for MCP config files in user home directories.
pub fn scan_mcp_configs() -> Vec<PathBuf> {
    let mut configs = vec![];

    // Common MCP config locations
    let patterns = [
        ".claude/.mcp.json",
        ".claude/mcp.json",
        ".cursor/mcp.json",
        ".config/goose/mcp.json",
        ".config/aider/mcp.json",
        ".codex/mcp.json",
        ".gemini/mcp.json",
        ".openclaw/mcp.json",
    ];

    // Scan /home/*/
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            for pattern in &patterns {
                let path = entry.path().join(pattern);
                if path.exists() {
                    info!(path = %path.display(), "agent-guard: found MCP config");
                    configs.push(path);
                }
            }
        }
    }

    // Scan /root/
    for pattern in &patterns {
        let path = PathBuf::from("/root").join(pattern);
        if path.exists() {
            info!(path = %path.display(), "agent-guard: found MCP config");
            configs.push(path);
        }
    }

    configs
}

/// Full detection: scan processes + MCP configs, match them together.
pub fn detect_all(index: &AgentIndex) -> Vec<DetectedAgent> {
    let mut agents = scan_processes(index);
    let configs = scan_mcp_configs();

    // Associate MCP configs with detected agents
    for agent in &mut agents {
        if let Some(sig) = index.identify(&agent.comm) {
            for mcp_path in sig.mcp_config_paths {
                for config in &configs {
                    if config.to_string_lossy().contains(mcp_path) {
                        agent.mcp_configs.push(config.clone());
                    }
                }
            }
        }
    }

    let official = agents
        .iter()
        .filter(|a| a.integration == "official")
        .count();
    let monitored = agents.len() - official;

    info!(
        total = agents.len(),
        official,
        monitored,
        mcp_configs = configs.len(),
        "agent-guard: detection complete"
    );

    agents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_mcp_returns_vec() {
        // Just verify it doesn't panic
        let configs = scan_mcp_configs();
        assert!(configs.len() >= 0);
    }

    #[test]
    fn detect_all_returns_vec() {
        let index = AgentIndex::new();
        let agents = detect_all(&index);
        assert!(agents.len() >= 0);
    }
}
