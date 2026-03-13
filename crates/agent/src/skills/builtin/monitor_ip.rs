use std::future::Future;
use std::pin::Pin;

use tracing::info;

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Premium skill: shadow-monitor an IP without blocking.
///
/// Full implementation would:
/// - Enable enhanced logging for all traffic from this IP
/// - Track connection patterns, ports, payloads
/// - Feed a dedicated monitoring JSONL for the agent to analyse
///
/// Community contributions welcome: https://github.com/maiconburn/innerwarden
pub struct MonitorIp;

impl ResponseSkill for MonitorIp {
    fn id(&self) -> &'static str { "monitor-ip" }
    fn name(&self) -> &'static str { "Shadow-monitor IP (Premium)" }
    fn description(&self) -> &'static str {
        "Enables enhanced logging for all traffic from the target IP without blocking. \
         Useful when you need more data before deciding to block. \
         [PREMIUM] Full implementation coming soon."
    }
    fn tier(&self) -> SkillTier { SkillTier::Premium }
    fn applicable_to(&self) -> &'static [&'static str] { &[] }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        _dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = ctx.target_ip.as_deref().unwrap_or("unknown");
            info!(
                ip,
                "🔒 [PREMIUM] monitor-ip skill is not yet implemented. \
                 Enhanced monitoring for {ip} would be enabled here. \
                 Contributions welcome: https://github.com/maiconburn/innerwarden"
            );
            SkillResult {
                success: true,
                message: format!(
                    "[PREMIUM stub] Would shadow-monitor {ip}. \
                     Full implementation coming in a future release."
                ),
            }
        })
    }
}
