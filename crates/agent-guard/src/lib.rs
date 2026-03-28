//! InnerWarden Agent Guard — AI agent protection module.
//!
//! Auto-detects AI agents running on the server and applies protection:
//! - MCP protocol inspection (tool calls, descriptions, responses)
//! - Session tracking (rate limiting, exfil chain detection)
//! - Process monitoring via eBPF integration
//!
//! Official integrations: Claude Code, OpenClaw, Aider, Goose, Codex CLI,
//! CrewAI, LangChain, Ollama, and more.

pub mod detect;
pub mod mcp;
pub mod registry;
pub mod rules;
pub mod session;
pub mod signatures;
pub mod threats;
