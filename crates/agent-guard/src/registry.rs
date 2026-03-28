//! Agent registry — tracks connected agents and their sessions.
//!
//! Agents connect via API or are discovered via `innerwarden agent scan`.
//! Each connected agent gets an ID, a session tracker, and a policy.
//! Multiple instances of the same agent type are supported.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use crate::session::SessionTracker;
use crate::signatures::{Kind, SignatureIndex};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A connected agent instance.
pub struct ConnectedAgent {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: Kind,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub session: SessionTracker,
    pub policy: AgentPolicy,
    pub stats: AgentStats,
}

/// Policy applied to a connected agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentPolicy {
    /// warn = notify, guard = block dangerous, kill = block everything suspicious
    pub mode: String,
    /// Block access to sensitive paths (.ssh, .env, .aws)
    pub block_sensitive_paths: bool,
    /// Wrap MCP servers with inspection proxy
    pub wrap_mcp: bool,
    /// Max tool calls per minute (0 = unlimited)
    pub max_calls_per_minute: u32,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            mode: "warn".to_string(),
            block_sensitive_paths: true,
            wrap_mcp: true,
            max_calls_per_minute: 30,
        }
    }
}

/// Runtime stats for a connected agent.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentStats {
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
    pub files_accessed: u64,
}

/// The registry of all connected agents.
pub struct Registry {
    agents: HashMap<String, ConnectedAgent>,
    index: SignatureIndex,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            index: SignatureIndex::new(),
        }
    }

    /// Connect an agent by PID. Returns the agent ID.
    pub fn connect(
        &mut self,
        name: &str,
        pid: u32,
        instance_label: Option<&str>,
    ) -> Result<String, String> {
        // Check if this PID is already connected
        if self.agents.values().any(|a| a.pid == pid) {
            return Err(format!("pid {pid} already connected"));
        }

        let id = format!("ag-{:04x}", NEXT_ID.fetch_add(1, Ordering::Relaxed));

        let (kind, integration) = if let Some(sig) = self.index.identify(name) {
            (sig.kind, format!("{:?}", sig.integration).to_lowercase())
        } else {
            (Kind::Tool, "monitored".to_string())
        };

        let label = instance_label
            .unwrap_or(&format!("{name}-{pid}"))
            .to_string();

        let agent = ConnectedAgent {
            id: id.clone(),
            name: name.to_string(),
            instance_label: label,
            pid,
            kind,
            integration,
            connected_at: Utc::now(),
            session: SessionTracker::new(),
            policy: AgentPolicy::default(),
            stats: AgentStats::default(),
        };

        tracing::info!(
            agent_id = %id,
            name = %agent.name,
            pid,
            label = %agent.instance_label,
            kind = ?kind,
            "agent connected"
        );

        self.agents.insert(id.clone(), agent);
        Ok(id)
    }

    /// Disconnect an agent by ID.
    pub fn disconnect(&mut self, agent_id: &str) -> bool {
        if let Some(agent) = self.agents.remove(agent_id) {
            tracing::info!(
                agent_id,
                name = %agent.name,
                pid = agent.pid,
                tool_calls = agent.stats.tool_calls,
                blocked = agent.stats.blocked,
                "agent disconnected"
            );
            true
        } else {
            false
        }
    }

    /// Get a connected agent by ID (mutable, for recording events).
    pub fn get_mut(&mut self, agent_id: &str) -> Option<&mut ConnectedAgent> {
        self.agents.get_mut(agent_id)
    }

    /// Get a connected agent by PID.
    pub fn by_pid(&self, pid: u32) -> Option<&ConnectedAgent> {
        self.agents.values().find(|a| a.pid == pid)
    }

    /// Get a connected agent by PID (mutable).
    pub fn by_pid_mut(&mut self, pid: u32) -> Option<&mut ConnectedAgent> {
        self.agents.values_mut().find(|a| a.pid == pid)
    }

    /// List all connected agents.
    pub fn list(&self) -> Vec<AgentSummary> {
        self.agents
            .values()
            .map(|a| AgentSummary {
                id: a.id.clone(),
                name: a.name.clone(),
                instance_label: a.instance_label.clone(),
                pid: a.pid,
                kind: format!("{:?}", a.kind).to_lowercase(),
                integration: a.integration.clone(),
                connected_at: a.connected_at,
                tool_calls: a.stats.tool_calls,
                blocked: a.stats.blocked,
                warnings: a.stats.warnings,
            })
            .collect()
    }

    /// Count connected agents by kind.
    pub fn count_agents(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Agent)
            .count()
    }

    pub fn count_tools(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Tool)
            .count()
    }

    pub fn count_total(&self) -> usize {
        self.agents.len()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary for API/CLI output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: String,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_list() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, Some("work-agent")).unwrap();
        assert!(id.starts_with("ag-"));

        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "openclaw");
        assert_eq!(list[0].instance_label, "work-agent");
        assert_eq!(list[0].kind, "agent");
    }

    #[test]
    fn multiple_instances_same_agent() {
        let mut reg = Registry::new();
        let id1 = reg.connect("openclaw", 1000, Some("personal")).unwrap();
        let id2 = reg.connect("openclaw", 2000, Some("work")).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(reg.count_agents(), 2);
    }

    #[test]
    fn reject_duplicate_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.connect("zeroclaw", 1234, None).is_err());
    }

    #[test]
    fn disconnect() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, None).unwrap();
        assert_eq!(reg.count_total(), 1);
        assert!(reg.disconnect(&id));
        assert_eq!(reg.count_total(), 0);
    }

    #[test]
    fn by_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.by_pid(1234).is_some());
        assert!(reg.by_pid(9999).is_none());
    }

    #[test]
    fn unknown_agent_connects_as_tool() {
        let mut reg = Registry::new();
        reg.connect("my-custom-agent", 5555, None).unwrap();
        let list = reg.list();
        assert_eq!(list[0].kind, "tool");
        assert_eq!(list[0].integration, "monitored");
    }

    #[test]
    fn mixed_agents_and_tools() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1000, None).unwrap();
        reg.connect("claude", 2000, None).unwrap();
        reg.connect("ollama", 3000, None).unwrap();
        assert_eq!(reg.count_agents(), 1); // only openclaw
        assert_eq!(reg.count_tools(), 1); // claude
        assert_eq!(reg.count_total(), 3);
    }
}
