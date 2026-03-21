//! Fail2ban integration — DEPRECATED.
//!
//! Inner Warden's native detectors + XDP firewall supersede fail2ban.
//! This module is kept as a no-op stub for config compatibility.

#[derive(Debug, Clone)]
pub struct Fail2BanState {
    _private: (),
}

impl Fail2BanState {
    pub fn new(_cfg: &crate::config::Fail2BanConfig) -> Self {
        tracing::info!("Fail2ban integration is deprecated — InnerWarden's native detectors + XDP firewall are superior");
        Self { _private: () }
    }
}

/// No-op sync tick — fail2ban integration is deprecated.
#[allow(clippy::too_many_arguments)]
pub async fn sync_tick(
    _state: &mut Fail2BanState,
    _blocklist: &mut crate::skills::Blocklist,
    _skill_registry: &crate::skills::SkillRegistry,
    _cfg: &crate::config::AgentConfig,
    _decision_writer: &mut Option<crate::decisions::DecisionWriter>,
    _decision_cooldowns: &mut std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    _host: &str,
    _telegram: Option<&std::sync::Arc<crate::telegram::TelegramClient>>,
) {
    // No-op: fail2ban sync is deprecated
}
