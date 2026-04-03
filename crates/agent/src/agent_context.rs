use std::path::Path;

use crate::{bot_helpers, config, telegram};

pub(crate) fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

/// Returns the current guardian mode based on responder configuration.
pub(crate) fn guardian_mode(cfg: &config::AgentConfig) -> telegram::GuardianMode {
    if !cfg.responder.enabled {
        telegram::GuardianMode::Watch
    } else if cfg.responder.dry_run {
        telegram::GuardianMode::DryRun
    } else {
        telegram::GuardianMode::Guard
    }
}

/// Builds a rich system-state context string injected into every AI chat call.
/// The AI uses this to answer self-awareness questions accurately and give
/// correct configuration advice.
pub(crate) fn build_agent_context(cfg: &config::AgentConfig, data_dir: &Path) -> String {
    let mode = guardian_mode(cfg);
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let incident_count =
        bot_helpers::count_jsonl_lines(data_dir, &format!("incidents-{today}.jsonl"));
    let decision_count =
        bot_helpers::count_jsonl_lines(data_dir, &format!("decisions-{today}.jsonl"));
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let skills_list = cfg.responder.allowed_skills.join(", ");
    let block_backend = &cfg.responder.block_backend;
    let ai_status = if cfg.ai.enabled {
        format!(
            "ENABLED - provider={}, model={}",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        "DISABLED".to_string()
    };
    let responder_status = if !cfg.responder.enabled {
        "DISABLED (watch-only mode)".to_string()
    } else if cfg.responder.dry_run {
        "ENABLED - dry-run (simulates actions, no real execution)".to_string()
    } else {
        format!("ENABLED - live mode (backend={block_backend})")
    };
    let telegram_status = if cfg.telegram.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let abuseipdb_status = if cfg.abuseipdb.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let geoip_status = if cfg.geoip.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let fail2ban_status = if cfg.fail2ban.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let slack_status = if cfg.slack.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let cloudflare_status = if cfg.cloudflare.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "=== INNERWARDEN SYSTEM STATE ===\n\
         Host: {host}\n\
         Version: {version}\n\
         Mode: {mode_label} - {mode_desc}\n\
         Data dir: {data_dir}\n\
         \n\
         Today ({today}): {incident_count} intrusion attempts, {decision_count} actions taken\n\
         \n\
         === ACTIVE CONFIGURATION ===\n\
         Responder: {responder_status}\n\
         Allowed skills: {skills_list}\n\
         AI analysis: {ai_status}\n\
         Telegram bot: {telegram_status}\n\
         AbuseIPDB enrichment: {abuseipdb_status}\n\
         GeoIP enrichment: {geoip_status}\n\
         Fail2ban integration: {fail2ban_status}\n\
         Slack notifications: {slack_status}\n\
         Cloudflare edge blocking: {cloudflare_status}\n\
         \n\
         === AVAILABLE CAPABILITIES (innerwarden enable/disable <id>) ===\n\
         - ai: AI-powered incident analysis (params: provider=openai|anthropic|ollama, model=...)\n\
         - block-ip: Firewall blocking of attacking IPs (params: backend=ufw|iptables|nftables|pf)\n\
         - sudo-protection: Detect sudo abuse + auto-suspend attacker privileges\n\
         - shell-audit: Audit shell command execution (privacy gate required)\n\
         - search-protection: Protect search/API endpoints from scraping bots\n\
         \n\
         === AVAILABLE SKILLS (agent execution layer) ===\n\
         Open tier: block-ip-ufw, block-ip-iptables, block-ip-nftables, block-ip-pf, suspend-user-sudo, rate-limit-nginx\n\
         Premium tier: monitor-ip (packet capture), honeypot (attacker trap)\n\
         \n\
         === CLI REFERENCE ===\n\
         innerwarden enable <capability>         # activate a capability\n\
         innerwarden disable <capability>        # deactivate a capability\n\
         innerwarden status                      # full system overview\n\
         innerwarden doctor                      # health check with fix hints\n\
         innerwarden scan                        # detect installed tools, recommend modules\n\
         innerwarden list                        # list all capabilities with status\n\
         innerwarden configure responder         # set GUARD/WATCH/DRY-RUN mode\n\
         innerwarden notify telegram             # setup Telegram bot\n\
         innerwarden notify slack                # setup Slack webhook\n\
         innerwarden integrate abuseipdb         # IP reputation enrichment\n\
         innerwarden integrate geoip             # GeoIP enrichment (free)\n\
         innerwarden integrate fail2ban          # sync with fail2ban bans\n\
         innerwarden block <ip> --reason <r>     # manual IP block\n\
         innerwarden unblock <ip>                # remove IP block\n\
         innerwarden incidents --days 7          # list recent incidents\n\
         innerwarden decisions --days 7          # list recent decisions\n\
         innerwarden report                      # show operational report\n\
         innerwarden tune                        # auto-tune detector thresholds\n\
         ",
        host = host,
        version = env!("CARGO_PKG_VERSION"),
        mode_label = mode.label(),
        mode_desc = mode.description(),
        data_dir = data_dir.display(),
    )
}
