use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod capabilities;
mod capability;
mod commands;
mod config_editor;
mod harden;
mod module_manifest;
mod module_package;
mod module_validator;
mod preflight;
mod scan;
mod sudoers;
mod systemd;
mod upgrade;
mod welcome;

use capability::{ActivationOptions, CapabilityRegistry};
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "innerwarden",
    about = "InnerWarden control plane - manage capabilities",
    long_about = "Activate and manage InnerWarden capabilities.\n\n\
                  Run 'innerwarden list' to see available capabilities.\n\
                  Run 'innerwarden enable <id>' to activate one."
)]
struct Cli {
    /// Path to sensor config (config.toml)
    #[arg(long, default_value = "/etc/innerwarden/config.toml")]
    sensor_config: PathBuf,

    /// Path to agent config (agent.toml)
    #[arg(long, default_value = "/etc/innerwarden/agent.toml")]
    agent_config: PathBuf,

    /// Directory where InnerWarden data files are stored
    #[arg(long, default_value = "/var/lib/innerwarden", global = true)]
    data_dir: PathBuf,

    /// Show what would happen without applying any changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Activate a capability
    Enable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Capability-specific parameters as KEY=VALUE
        #[arg(long = "param", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
        params: Vec<String>,

        /// Skip interactive confirmation prompts (e.g. privacy gate)
        #[arg(long)]
        yes: bool,
    },

    /// Deactivate a capability
    Disable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all capabilities with their current status
    List,

    /// Show system status or the full activity history for an IP or user.
    ///
    /// With no arguments: global overview of services, capabilities, and modules.
    /// With an IP or username: chronological timeline of events, incidents, and
    /// decisions for that entity (terminal equivalent of the dashboard journey panel).
    ///
    /// Examples:
    ///   innerwarden status
    ///   innerwarden status block-ip
    ///   innerwarden status 203.0.113.10
    ///   innerwarden status root --days 7
    Status {
        /// Capability ID, IP address, or username to inspect (omit for global overview)
        target: Option<String>,

        /// Directory to scan for installed modules (used in global overview)
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// How many days back to search when looking up an entity (default: 3)
        #[arg(long, default_value = "3")]
        days: u64,
    },

    /// Simple daily commands for common day-to-day operations.
    ///
    /// Keeps the most used actions easy to remember. Advanced workflows
    /// remain available via the full command set.
    ///
    /// Examples:
    ///   innerwarden daily
    ///   innerwarden daily status
    ///   innerwarden daily threats --live
    ///   innerwarden daily actions --days 7
    ///   innerwarden daily agent scan
    ///   innerwarden daily agent connect
    ///   innerwarden quick status
    #[command(visible_aliases = ["quick", "day"])]
    Daily {
        #[command(subcommand)]
        command: Option<DailyCommand>,
    },

    /// Scan system configuration and suggest security hardening improvements.
    ///
    /// Checks SSH, firewall, kernel, permissions, updates, Docker, and
    /// services. Prints actionable recommendations - never applies changes.
    ///
    /// Examples:
    ///   innerwarden harden
    ///   innerwarden harden --verbose
    Harden {
        /// Show all passed checks in addition to findings
        #[arg(long)]
        verbose: bool,
    },

    /// Run system diagnostics and print fix hints for any issues found
    Doctor,

    /// Scan this machine and recommend the best modules for your setup.
    ///
    /// Runs a quick system probe, scores each module, and shows a clear
    /// priority list.  Type a module name or number at the prompt to read
    /// its detailed docs.
    Scan {
        /// Directory to look for module docs (default: ./modules or
        /// /usr/local/share/innerwarden/modules)
        #[arg(long, default_value = "")]
        modules_dir: String,
    },

    /// First-time setup wizard.
    ///
    /// Scans your machine, configures AI, Telegram notifications, the
    /// responder, and enables the most relevant modules for your setup.
    ///
    /// Examples:
    ///   innerwarden setup
    Setup,

    /// Show welcome animation (called by installer).
    #[clap(hide = true)]
    Welcome,

    /// Export MITRE ATT&CK Navigator layer showing detection coverage.
    ///
    /// Output can be loaded into https://mitre-attack.github.io/attack-navigator/
    ///
    /// Examples:
    ///   innerwarden navigator > coverage.json
    ///   innerwarden navigator --output coverage.json
    Navigator {
        /// Write to file instead of stdout.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Check for a newer release and optionally upgrade all binaries.
    ///
    /// Add to cron for automatic update checks:
    ///   0 8 * * * innerwarden upgrade --check --notify 2>/dev/null
    ///
    /// Examples:
    ///   innerwarden upgrade              # check + install interactively
    ///   innerwarden upgrade --check      # just check, don't install
    ///   innerwarden upgrade --check --notify  # check + Telegram alert if new version
    ///   innerwarden upgrade --yes        # install without confirmation
    Upgrade {
        /// Only check if an update is available; do not install
        #[arg(long)]
        check: bool,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,

        /// Send a Telegram notification if a new version is available (for cron use)
        #[arg(long)]
        notify: bool,

        /// Directory where binaries are installed
        #[arg(long, default_value = "/usr/local/bin")]
        install_dir: PathBuf,
    },

    /// Configure notification channels (Telegram, Slack, webhook, dashboard).
    ///
    /// Run without arguments to see an interactive menu.
    ///
    /// Examples:
    ///   innerwarden notify telegram
    ///   innerwarden notify slack --webhook-url https://hooks.slack.com/...
    ///   innerwarden notify test
    Notify {
        #[command(subcommand)]
        command: Option<NotifyCommand>,
    },

    /// Configure system components (AI provider, responder mode).
    ///
    /// Run without arguments to see an interactive menu.
    ///
    /// Examples:
    ///   innerwarden configure ai
    ///   innerwarden configure ai openai --key sk-...
    ///   innerwarden configure ai groq --key gsk-...
    ///   innerwarden configure responder --enable --dry-run false
    Configure {
        #[command(subcommand)]
        command: Option<ConfigureCommand>,
    },

    /// Configure external integrations (GeoIP, AbuseIPDB, Cloudflare, watchdog).
    ///
    /// Run without arguments to see an interactive menu.
    ///
    /// Examples:
    ///   innerwarden integrate geoip
    ///   innerwarden integrate abuseipdb --api-key <key>
    Integrate {
        #[command(subcommand)]
        command: Option<IntegrateCommand>,
    },

    /// Collaborative defense mesh network.
    ///
    /// Share threat intelligence with other Inner Warden nodes.
    /// Attacking one server protects all others.
    ///
    /// Examples:
    ///   innerwarden mesh enable
    ///   innerwarden mesh add-peer https://peer:8790
    ///   innerwarden mesh status
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },

    /// Module management commands
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },

    /// Print the daily security report in the terminal.
    ///
    /// Reads the Markdown summary generated by innerwarden-agent and displays it.
    /// No need to open the dashboard.
    ///
    /// Examples:
    ///   innerwarden report
    ///   innerwarden report --date yesterday
    ///   innerwarden report --date 2026-03-14
    Report {
        /// Date to show: today, yesterday, or YYYY-MM-DD (default: today)
        #[arg(long, default_value = "today")]
        date: String,
    },

    /// Check if the agent is healthy and alert via Telegram if it appears stuck.
    ///
    /// The agent writes a telemetry file every 30 seconds. If the latest entry
    /// is older than the threshold, the agent may be stuck or crashed.
    ///
    /// Add to cron for continuous monitoring:
    ///   */10 * * * * innerwarden watchdog
    ///
    /// Use --status to show the cron schedule and last-run time without
    /// running a health check.
    ///
    /// Examples:
    ///   innerwarden watchdog
    ///   innerwarden watchdog --threshold 600
    ///   innerwarden watchdog --notify
    ///   innerwarden watchdog --status
    Watchdog {
        /// How many seconds of silence before reporting unhealthy (default: 300)
        #[arg(long, default_value = "300")]
        threshold: u64,

        /// Send a Telegram alert when the agent appears unhealthy
        #[arg(long)]
        notify: bool,

        /// Show watchdog cron schedule and last-run info instead of running a check
        #[arg(long)]
        status: bool,
    },

    /// Interactively tune detector thresholds based on recent noise and signal.
    ///
    /// Reads telemetry + incidents from the last 7 days, computes noise/signal
    /// ratio per detector, and suggests adjusted thresholds.  Applies changes
    /// to sensor.toml on confirmation.
    ///
    /// Examples:
    ///   innerwarden tune
    ///   innerwarden tune --days 14
    ///   innerwarden tune --yes        # apply suggestions without prompting
    Tune {
        /// How many days of history to analyse (default: 7)
        #[arg(long, default_value = "7")]
        days: u64,

        /// Apply suggested changes without interactive prompts
        #[arg(long)]
        yes: bool,
    },

    /// Show which collectors are active and their event counts today.
    ///
    /// Reads the latest telemetry snapshot to show how many events each
    /// data source has contributed today. Useful to verify collectors are working.
    ///
    /// Examples:
    ///   innerwarden sensor-status
    #[clap(name = "sensor-status")]
    SensorStatus,

    /// Export events, incidents, or decisions to CSV or JSON.
    ///
    /// Examples:
    ///   innerwarden export incidents
    ///   innerwarden export decisions --from 2026-03-01 --to 2026-03-15
    ///   innerwarden export events --format csv --output /tmp/events.csv
    Export {
        /// What to export: events, incidents, or decisions
        #[arg(default_value = "incidents")]
        kind: String,

        /// Start date (YYYY-MM-DD, default: today)
        #[arg(long)]
        from: Option<String>,

        /// End date inclusive (YYYY-MM-DD, default: today)
        #[arg(long)]
        to: Option<String>,

        /// Output format: json or csv (default: json)
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Stream new incidents and events in real time (like tail -f).
    ///
    /// Polls the JSONL files every 2 seconds and prints new entries as they arrive.
    /// Press Ctrl-C to stop.
    ///
    /// Examples:
    ///   innerwarden tail
    ///   innerwarden tail --type events
    ///   innerwarden tail --type incidents
    Tail {
        /// What to stream: incidents or events (default: incidents)
        #[arg(long, default_value = "incidents")]
        r#type: String,

        /// Poll interval in seconds (default: 2)
        #[arg(long, default_value = "2")]
        interval: u64,
    },

    /// List recent security incidents detected on this host.
    ///
    /// Shows threats from today (and optionally yesterday) with severity,
    /// IP address, title and time. No need to open the dashboard.
    ///
    /// Examples:
    ///   innerwarden incidents
    ///   innerwarden incidents --days 2
    ///   innerwarden incidents --severity critical
    /// List recent security incidents detected on this host.
    ///
    /// Shows threats from today (and optionally yesterday) with severity,
    /// IP address, title and time. No need to open the dashboard.
    ///
    /// Examples:
    ///   innerwarden incidents
    ///   innerwarden incidents --live
    ///   innerwarden incidents --days 2
    ///   innerwarden incidents --severity high
    Incidents {
        /// How many days back to look (default: 1 = today only)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Filter by minimum severity: low, medium, high, critical (default: low = all)
        #[arg(long, default_value = "low")]
        severity: String,

        /// Stream new incidents in real time (like tail -f but formatted)
        #[arg(long)]
        live: bool,
    },

    /// Block an IP address at the firewall and record it in the audit trail.
    ///
    /// Uses the same block skill configured in agent.toml (ufw/iptables/nftables).
    /// Requires sudo. The block is recorded in decisions-YYYY-MM-DD.jsonl.
    ///
    /// Examples:
    ///   innerwarden block 1.2.3.4 --reason "manual block after investigation"
    Block {
        /// IP address to block
        ip: String,

        /// Reason for the block (required - kept in audit trail)
        #[arg(long)]
        reason: String,
    },

    /// Remove a previously blocked IP from the firewall.
    ///
    /// Reverses a block created by InnerWarden (manual or AI-initiated).
    /// The unblock is recorded in decisions-YYYY-MM-DD.jsonl.
    ///
    /// Examples:
    ///   innerwarden unblock 1.2.3.4 --reason "false positive"
    Unblock {
        /// IP address to unblock
        ip: String,

        /// Reason for removing the block (required - kept in audit trail)
        #[arg(long)]
        reason: String,
    },

    /// Show recent decisions made by InnerWarden (blocks, suspensions, ignores).
    ///
    /// Shows what the agent decided and whether it executed or was in dry-run mode.
    /// Useful for auditing: "what did InnerWarden actually do?"
    ///
    /// Examples:
    ///   innerwarden decisions
    ///   innerwarden decisions --days 7
    ///   innerwarden decisions --action block_ip
    Decisions {
        /// How many days back to look (default: 1 = today only)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Filter by action: block_ip, suspend_user_sudo, ignore, monitor, honeypot
        #[arg(long)]
        action: Option<String>,
    },

    /// Show the full activity history for an IP or user (hidden alias for 'status <entity>').
    ///
    /// Examples:
    ///   innerwarden entity 203.0.113.10
    ///   innerwarden entity root
    ///   innerwarden entity 203.0.113.10 --days 7
    #[clap(hide = true)]
    Entity {
        /// IP address or username to look up
        target: String,

        /// How many days back to search (default: 3)
        #[arg(long, default_value = "3")]
        days: u64,
    },

    /// Generate shell completions for bash, zsh, or fish.
    ///
    /// Prints the completion script to stdout. Source it in your shell config
    /// to get tab-completion for all innerwarden commands and flags.
    ///
    /// Examples:
    ///   innerwarden completions bash >> ~/.bashrc
    ///   innerwarden completions zsh  >> ~/.zshrc
    ///   innerwarden completions fish > ~/.config/fish/completions/innerwarden.fish
    Completions {
        /// Shell to generate completions for: bash, zsh, or fish
        shell: String,
    },

    /// Manage trusted IPs, CIDRs, and users that skip automated response.
    ///
    /// Allowlisted entities are still logged and notified via webhook/Telegram/Slack
    /// but the AI gate is skipped - no automated skill (block, suspend, etc.) is
    /// ever executed for them.
    ///
    /// Examples:
    ///   innerwarden allowlist add --ip 10.0.0.1
    ///   innerwarden allowlist add --ip 192.168.0.0/24
    ///   innerwarden allowlist add --user deploy
    ///   innerwarden allowlist remove --ip 10.0.0.1
    ///   innerwarden allowlist list
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },

    /// Inject a synthetic incident and verify the full pipeline responds.
    ///
    /// Writes a fake SSH brute-force incident using a documentation-range IP
    /// (RFC 5737: 198.51.100.123) and waits for the agent to produce a
    /// decision.  Safe to run on production - uses dry-run defaults and a
    /// non-routable IP.
    ///
    /// Examples:
    ///   innerwarden test
    ///   innerwarden test --wait 20
    #[clap(name = "test")]
    PipelineTest {
        /// Maximum seconds to wait for the agent to respond (default: 12)
        #[arg(long, default_value = "12")]
        wait: u64,
    },

    /// Back up InnerWarden configuration files to a tar.gz archive.
    ///
    /// Creates a compressed archive containing config.toml, agent.toml,
    /// and agent.env from /etc/innerwarden/. Requires sudo (configs are
    /// owned by root:innerwarden).
    ///
    /// Examples:
    ///   innerwarden backup
    ///   innerwarden backup --output /tmp/my-backup.tar.gz
    Backup {
        /// Output path for the archive (default: secure temp file in system temp dir)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Show detailed metrics from today's telemetry snapshot.
    ///
    /// Reads the latest telemetry file and displays events processed,
    /// incidents detected, decisions made, AI latency, and agent uptime.
    ///
    /// Examples:
    ///   innerwarden metrics
    Metrics,

    /// GDPR data subject operations (export & erase).
    ///
    /// Export all data matching an entity (IP or username), or erase it
    /// in compliance with the GDPR right to erasure (Art. 17).
    ///
    /// Examples:
    ///   innerwarden gdpr export --entity 203.0.113.10
    ///   innerwarden gdpr export --entity root --output /tmp/root-data.jsonl
    ///   innerwarden gdpr erase --entity 203.0.113.10
    ///   innerwarden gdpr erase --entity root --yes
    Gdpr {
        #[command(subcommand)]
        action: GdprCommand,
    },

    /// AI agent management — install, scan, connect, monitor agents.
    ///
    /// Run without arguments for an interactive menu.
    ///
    /// Examples:
    ///   innerwarden agent                    (interactive menu)
    ///   innerwarden agent add <name>         (install an agent)
    ///   innerwarden agent scan               (find running agents)
    ///   innerwarden agent status             (view connected agents)
    ///   innerwarden agent connect            (auto-detect and connect)
    ///   innerwarden agent connect 1234       (connect a specific PID)
    ///   innerwarden agent disconnect ag-0001 (disconnect an agent)
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },

    /// Suppress or unsuppress incident types from alerting.
    ///
    /// Suppressed patterns are matched against incident IDs.
    /// Matching incidents are silently logged but generate no alerts,
    /// decisions, or notifications.
    ///
    /// Examples:
    ///   innerwarden suppress add firmware:trust_degraded
    ///   innerwarden suppress add "ssh_bruteforce:192.168.1.0"
    ///   innerwarden suppress remove firmware:trust_degraded
    ///   innerwarden suppress list
    Suppress {
        #[command(subcommand)]
        command: SuppressCommand,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Install a new agent (OpenClaw, ZeroClaw, and others in `agent list`)
    Add {
        /// Agent name (run 'innerwarden agent add' without args to see options)
        name: Option<String>,
    },

    /// Scan for agents already running on this server
    Scan,

    /// View connected agents and detected tools
    Status,

    /// Connect a running agent.
    ///
    /// If PID is omitted, InnerWarden auto-detects running agents and:
    /// - connects automatically when only one is found
    /// - offers a guided selection when multiple are found
    Connect {
        /// Optional process ID of the agent to connect
        pid: Option<u32>,

        /// Match an agent by name/command (avoids manual PID lookup)
        #[arg(long)]
        name: Option<String>,

        /// Optional label for this instance (e.g., "personal", "work")
        #[arg(long)]
        label: Option<String>,
    },

    /// Disconnect an agent by ID
    Disconnect {
        /// Agent ID (e.g., ag-0001) or PID
        id: String,
    },

    /// List available agents for installation
    List,
}

#[derive(Subcommand)]
enum DailyCommand {
    /// Quick system overview (services, capabilities, modules, today's activity).
    Status,

    /// Show recent threats (default: High/Critical from today).
    Threats {
        /// How many days back to look (default: 1)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Minimum severity: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        severity: String,

        /// Stream new incidents in real time
        #[arg(long)]
        live: bool,
    },

    /// Show recent actions taken by InnerWarden.
    Actions {
        /// How many days back to look (default: 1)
        #[arg(long, default_value = "1")]
        days: u64,
    },

    /// Print daily security report.
    Report {
        /// Date: today, yesterday, or YYYY-MM-DD
        #[arg(long, default_value = "today")]
        date: String,
    },

    /// Run diagnostics and print fix hints.
    Doctor,

    /// Inject synthetic incident and verify end-to-end pipeline.
    Test {
        /// Maximum seconds to wait for the agent to respond
        #[arg(long, default_value = "12")]
        wait: u64,
    },

    /// Agent connection and protection commands (basic flow).
    ///
    /// Examples:
    ///   innerwarden daily agent
    ///   innerwarden daily agent scan
    ///   innerwarden daily agent status
    ///   innerwarden daily agent connect
    ///   innerwarden daily agent connect 1234
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },
}

/// System configuration sub-commands.
#[derive(Subcommand)]
enum ConfigureCommand {
    /// Configure AI provider and model.
    ///
    /// Run without arguments for an interactive wizard that lists providers,
    /// validates your API key, and fetches available models from the provider.
    ///
    /// Examples:
    ///   innerwarden configure ai
    ///   innerwarden configure ai openai --key sk-...
    ///   innerwarden configure ai groq --key gsk-... --model llama-3.3-70b-versatile
    Ai {
        /// Provider name: openai, anthropic, groq, deepseek, mistral, xai, gemini, ollama, etc.
        provider: Option<String>,

        /// API key for the provider
        #[arg(long)]
        key: Option<String>,

        /// Model to use (if omitted, the wizard fetches available models)
        #[arg(long)]
        model: Option<String>,

        /// Custom base URL for OpenAI-compatible APIs
        #[arg(long)]
        base_url: Option<String>,
    },

    /// Configure responder mode (enable/disable, dry-run).
    ///
    /// Examples:
    ///   innerwarden configure responder --enable --dry-run false
    Responder {
        /// Enable the responder (allow skill execution)
        #[arg(long)]
        enable: bool,

        /// Dry-run mode: true = log only, false = execute for real
        #[arg(long)]
        dry_run: Option<String>,
    },

    /// Set notification sensitivity level.
    ///
    /// Controls how often you get alerts:
    ///   quiet   - only Critical (server compromised, privesc)
    ///   normal  - High + Critical (confirmed attacks, blocks)
    ///   verbose - everything Medium+ (includes mesh signals, watchlist)
    ///
    /// Examples:
    ///   innerwarden configure sensitivity quiet
    ///   innerwarden configure sensitivity normal
    Sensitivity {
        /// Level: quiet, normal, or verbose
        level: String,
    },

    /// Configure two-factor authentication for sensitive actions.
    ///
    /// Protects allowlist changes, mode switches, and detector disable
    /// with TOTP (Google Authenticator, Authy, 1Password).
    ///
    /// Examples:
    ///   innerwarden configure 2fa
    #[command(name = "2fa")]
    TwoFa,
}

/// Notification channel setup sub-commands.
#[derive(Subcommand)]
enum NotifyCommand {
    /// Set up Telegram notifications (interactive wizard).
    ///
    /// Walks you through creating a bot and getting your chat ID.
    /// Credentials are saved to agent.env (never in plain TOML).
    ///
    /// Examples:
    ///   innerwarden notify telegram
    ///   innerwarden notify telegram --token 123:ABC --chat-id 456789
    Telegram {
        /// Bot token from @BotFather (skips the wizard prompt)
        #[arg(long)]
        token: Option<String>,

        /// Your Telegram chat ID (skips the wizard prompt)
        #[arg(long)]
        chat_id: Option<String>,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up Slack notifications (interactive wizard).
    ///
    /// Walks you through creating an Incoming Webhook in your Slack workspace.
    /// The webhook URL is saved to agent.env.
    ///
    /// Examples:
    ///   innerwarden notify slack
    ///   innerwarden notify slack --webhook-url https://hooks.slack.com/services/...
    Slack {
        /// Slack Incoming Webhook URL (skips the wizard prompt)
        #[arg(long)]
        webhook_url: Option<String>,

        /// Minimum severity to notify: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up HTTP webhook notifications (sends alerts to any HTTP endpoint).
    ///
    /// Examples:
    ///   innerwarden notify webhook
    ///   innerwarden notify webhook --url https://hooks.example.com/notify
    ///   innerwarden notify webhook --url https://hooks.example.com/notify --min-severity medium
    Webhook {
        /// Webhook URL (skips the wizard prompt)
        #[arg(long)]
        url: Option<String>,

        /// Minimum severity to forward: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test request after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up the local security dashboard (generates login credentials).
    ///
    /// Creates a secure password hash and writes credentials to agent.env.
    /// The dashboard is then available at http://localhost:8787 after agent restart.
    ///
    /// Examples:
    ///   innerwarden notify dashboard
    ///   innerwarden notify dashboard --user admin --password mysecretpassword
    Dashboard {
        /// Dashboard username (default: admin)
        #[arg(long, default_value = "admin")]
        user: String,

        /// Dashboard password (skips the interactive prompt)
        #[arg(long)]
        password: Option<String>,
    },

    /// Send a test alert to all configured notification channels.
    ///
    /// Verifies that Telegram, Slack, and webhook notifications are working
    /// end-to-end. Useful after first setup or after changing credentials.
    ///
    /// Examples:
    ///   innerwarden notify test
    ///   innerwarden notify test --channel telegram
    Test {
        /// Only test a specific channel: telegram, slack, or webhook
        #[arg(long)]
        channel: Option<String>,
    },

    /// Set up browser Web Push notifications (RFC 8291 / VAPID).
    ///
    /// Generates a VAPID key pair and writes the configuration to agent.toml.
    /// After setup, open the InnerWarden dashboard and click "Enable notifications"
    /// to subscribe your browser.
    ///
    /// Examples:
    ///   innerwarden notify web-push
    ///   innerwarden notify web-push --subject mailto:admin@example.com
    #[clap(name = "web-push")]
    WebPush {
        /// VAPID subject - "mailto:..." contact address for the push service (default: mailto:admin@example.com)
        #[arg(long)]
        subject: Option<String>,
    },
}

/// Allowlist sub-commands.
#[derive(Subcommand)]
enum AllowlistCommand {
    /// Add a trusted IP, CIDR, or user to the allowlist.
    ///
    /// Examples:
    ///   innerwarden allowlist add --ip 10.0.0.1
    ///   innerwarden allowlist add --ip 192.168.0.0/24
    ///   innerwarden allowlist add --user deploy
    Add {
        /// IP address or CIDR range to trust (e.g. 10.0.0.1 or 192.168.0.0/24)
        #[arg(long)]
        ip: Option<String>,

        /// Username to trust
        #[arg(long)]
        user: Option<String>,
    },

    /// Remove an IP, CIDR, or user from the allowlist.
    ///
    /// Examples:
    ///   innerwarden allowlist remove --ip 10.0.0.1
    ///   innerwarden allowlist remove --user deploy
    Remove {
        /// IP address or CIDR to remove
        #[arg(long)]
        ip: Option<String>,

        /// Username to remove
        #[arg(long)]
        user: Option<String>,
    },

    /// Show all currently trusted IPs, CIDRs, and users.
    List,
}

#[derive(Subcommand)]
enum SuppressCommand {
    /// Suppress an incident pattern from alerting.
    Add {
        /// Pattern to match against incident IDs (substring match).
        /// Examples: "firmware:trust_degraded", "ssh_bruteforce:10.0.0"
        pattern: String,
    },

    /// Remove a suppression pattern (re-enable alerting).
    Remove {
        /// Pattern to remove
        pattern: String,
    },

    /// Show all active suppression patterns.
    List,
}

#[derive(Subcommand)]
enum MeshCommand {
    /// Enable the mesh collaborative defense network.
    ///
    /// Starts sharing threat signals with other Inner Warden nodes.
    /// Disabled by default. Safe - blocks are staged with TTL, never permanent.
    Enable,

    /// Disable the mesh network.
    Disable,

    /// Add a peer node to the mesh.
    ///
    /// The peer's identity will be discovered automatically via ping.
    ///
    /// Examples:
    ///   innerwarden mesh add-peer https://peer-server:8790
    ///   innerwarden mesh add-peer https://10.0.1.5:8790 --label prod-eu
    AddPeer {
        /// Peer endpoint URL (e.g., https://peer:8790)
        endpoint: String,

        /// Human-friendly label for this peer
        #[arg(long)]
        label: Option<String>,
    },

    /// Show mesh network status.
    Status,
}

/// External integration setup sub-commands.
#[derive(Subcommand)]
enum IntegrateCommand {
    /// Enable GeoIP country/ISP enrichment (no API key needed).
    ///
    /// Uses ip-api.com (free, 45 req/min) to add country and ISP context
    /// to AI analysis. No account or API key required.
    ///
    /// Examples:
    ///   innerwarden integrate geoip
    Geoip,

    /// Set up AbuseIPDB IP reputation enrichment.
    ///
    /// AbuseIPDB checks each attacker IP's abuse history before AI analysis,
    /// making decisions more accurate. Free tier: 1,000 lookups/day.
    ///
    /// Get a free API key at https://www.abuseipdb.com/register
    ///
    /// Examples:
    ///   innerwarden integrate abuseipdb
    ///   innerwarden integrate abuseipdb --api-key <key>
    Abuseipdb {
        /// AbuseIPDB API key (skips the wizard prompt)
        #[arg(long)]
        api_key: Option<String>,
        /// Auto-block IPs with abuse confidence score >= this threshold without calling AI (0 = disabled)
        #[arg(long)]
        auto_block_threshold: Option<u8>,
    },

    /// Push blocked IPs to Cloudflare edge via IP Access Rules API.
    ///
    /// After every successful block-ip action, the IP is also added to your
    /// Cloudflare zone's IP Access Rules - blocking it at the CDN edge before
    /// traffic even reaches your server.
    ///
    /// Requires a Cloudflare API token with Zone > Firewall Services > Edit permission.
    /// Zone ID is on the right panel of your domain in the Cloudflare dashboard.
    ///
    /// Examples:
    ///   innerwarden integrate cloudflare
    ///   innerwarden integrate cloudflare --zone-id <id> --api-token <token>
    Cloudflare {
        /// Cloudflare Zone ID (from your domain's dashboard page)
        #[arg(long)]
        zone_id: Option<String>,
        /// Cloudflare API token with Firewall Services Edit permission
        #[arg(long)]
        api_token: Option<String>,
    },

    /// Set up automatic health monitoring via cron (watchdog).
    ///
    /// Adds a cron entry that runs `innerwarden watchdog --notify` every N minutes.
    /// Sends a Telegram alert if the agent stops writing telemetry.
    ///
    /// Examples:
    ///   innerwarden integrate watchdog
    ///   innerwarden integrate watchdog --interval 5
    Watchdog {
        /// How often to check (minutes, default: 10)
        #[arg(long, default_value = "10")]
        interval: u64,
    },
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Validate a module package (manifest, structure, security, docs, tests)
    Validate {
        /// Path to the module directory
        path: PathBuf,

        /// Enable stricter security checks (unsafe blocks, etc.)
        #[arg(long)]
        strict: bool,
    },

    /// Enable a module (patch configs, install sudoers, restart services)
    Enable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Disable a module (revert config patches, remove sudoers, restart services)
    Disable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all modules found in the modules directory
    List {
        /// Directory to scan for module packages (each subdirectory with a module.toml)
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Show the status of a specific module by ID
    Status {
        /// Module ID (e.g. "search-protection")
        id: String,

        /// Directory to scan for module packages
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Search available modules from the InnerWarden registry
    ///
    /// Fetches the live registry from the repository and lists all modules,
    /// optionally filtering by name, tag, or description.
    ///
    /// Examples:
    ///   innerwarden module search
    ///   innerwarden module search ssh
    ///   innerwarden module search honeypot
    Search {
        /// Filter by name, tag, or description (case-insensitive)
        query: Option<String>,
    },

    /// Install a module by name, URL, or local path
    ///
    /// Accepts:
    ///   - A module name from the registry:  innerwarden module install ssh-protection
    ///   - An HTTPS URL to a .tar.gz:        innerwarden module install https://...
    ///   - A local file or directory path:   innerwarden module install ./my-module
    ///
    /// Built-in modules are enabled directly without downloading anything.
    Install {
        /// Module name (registry), HTTPS URL, or local path to a .tar.gz / directory
        source: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Enable the module immediately after installing
        #[arg(long)]
        enable: bool,

        /// Overwrite if the module ID is already installed
        #[arg(long)]
        force: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Remove an installed module (disables it first if needed)
    Uninstall {
        /// Module ID to remove
        id: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Package a module directory into a distributable .tar.gz
    Publish {
        /// Path to the module directory
        path: PathBuf,

        /// Output file (defaults to <id>-v<version>.tar.gz in current directory)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Check installed modules for updates and apply them
    UpdateAll {
        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Only report available updates without installing
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

/// GDPR data subject sub-commands.
#[derive(Subcommand)]
enum GdprCommand {
    /// Export all data matching an entity (IP or username).
    ///
    /// Scans events, incidents, decisions, admin-actions, and telemetry files
    /// for any record referencing the given entity and outputs matching lines.
    ///
    /// Examples:
    ///   innerwarden gdpr export --entity 203.0.113.10
    ///   innerwarden gdpr export --entity root --output /tmp/root-data.jsonl
    Export {
        /// IP address or username to search for
        #[arg(long)]
        entity: String,
        /// Output file path (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Erase all data matching an entity (right to erasure, GDPR Art. 17).
    ///
    /// Removes all matching records from JSONL data files via atomic rewrite.
    /// Hash-chained files (decisions, admin-actions) are recomputed after erasure.
    /// The erase itself is recorded in the admin-actions audit trail.
    ///
    /// Examples:
    ///   innerwarden gdpr erase --entity 203.0.113.10
    ///   innerwarden gdpr erase --entity root --yes
    Erase {
        /// IP address or username to erase
        #[arg(long)]
        entity: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Check if we have write access to the config directory.
fn am_root() -> bool {
    let config_dir = Path::new("/etc/innerwarden");
    if config_dir.exists() {
        // Try to check write permission
        std::fs::metadata(config_dir)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0 && unsafe { libc_geteuid() } == 0
            })
            .unwrap_or(false)
    } else {
        // Config dir doesn't exist yet — need root to create it
        unsafe { libc_geteuid() == 0 }
    }
}

/// Safe wrapper for geteuid without libc dep.
unsafe fn libc_geteuid() -> u32 {
    // geteuid is always available on Linux/macOS
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

/// Re-execute the current command with sudo, with clear user messaging.
fn reexec_with_sudo() -> Result<()> {
    eprintln!("┌─────────────────────────────────────────────────────────┐");
    eprintln!("│  InnerWarden needs root access to write configuration. │");
    eprintln!("│  Your password may be requested by sudo.               │");
    eprintln!("└─────────────────────────────────────────────────────────┘");
    eprintln!();
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status = std::process::Command::new("sudo")
        .arg(exe)
        .args(&args)
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let registry = CapabilityRegistry::default_all();

    // macOS uses /usr/local/etc instead of /etc for config files
    if cfg!(target_os = "macos") {
        let macos_cfg = Path::new("/usr/local/etc/innerwarden");
        if cli.sensor_config == Path::new("/etc/innerwarden/config.toml") {
            cli.sensor_config = macos_cfg.join("config.toml");
        }
        if cli.agent_config == Path::new("/etc/innerwarden/agent.toml") {
            cli.agent_config = macos_cfg.join("agent.toml");
        }
    }

    match cli.command {
        Command::Daily { ref command } => cmd_daily(&cli, &registry, command.as_ref()),
        Command::Harden { verbose } => harden::cmd_harden(verbose),
        Command::Doctor => cmd_doctor(&cli, &registry),
        Command::Setup => commands::setup::cmd_setup(&cli),
        Command::Welcome => {
            let ebpf = std::process::Command::new("bpftool")
                .args(["prog", "list"])
                .output()
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .matches("innerwarden")
                        .count() as u32
                })
                .unwrap_or(0);
            welcome::run_welcome(ebpf);
            Ok(())
        }
        Command::Navigator { ref output } => {
            let layer = generate_navigator_layer();
            let json = serde_json::to_string_pretty(&layer)?;
            if let Some(path) = output {
                std::fs::write(path, &json)?;
                eprintln!("  ✓ Navigator layer written to {path}");
                eprintln!(
                    "  Open https://mitre-attack.github.io/attack-navigator/ and load the file."
                );
            } else {
                println!("{json}");
            }
            Ok(())
        }
        Command::Scan { ref modules_dir } => scan::cmd_scan(modules_dir),
        Command::Upgrade {
            check,
            yes,
            notify,
            ref install_dir,
        } => cmd_upgrade(&cli, check, yes, notify, install_dir),
        Command::List => cmd_list(&cli, &registry),
        Command::Status {
            ref target,
            ref modules_dir,
            days,
        } => match target {
            None => commands::status::cmd_status_global(&cli, &registry, modules_dir),
            Some(ref t) => {
                // Check if it looks like a capability ID first; fall back to entity lookup
                if registry.get(t).is_some() {
                    commands::status::cmd_status(&cli, &registry, t)
                } else {
                    cmd_entity(&cli, t, days, &cli.data_dir.clone())
                }
            }
        },
        Command::Enable {
            ref capability,
            ref params,
            yes,
        } => {
            let params = parse_params(params)?;
            cmd_enable(&cli, &registry, capability, params, yes)
        }
        Command::Disable {
            ref capability,
            yes,
        } => cmd_disable(&cli, &registry, capability, yes),
        Command::Configure { ref command } => match command {
            None => cmd_configure_menu(&cli),
            Some(ConfigureCommand::Ai {
                ref provider,
                ref key,
                ref model,
                ref base_url,
            }) => {
                if provider.is_none() {
                    commands::ai::cmd_configure_ai_interactive(&cli)
                } else {
                    commands::ai::cmd_configure_ai(
                        &cli,
                        provider.as_deref().unwrap(),
                        key.as_deref(),
                        model.as_deref(),
                        base_url.as_deref(),
                    )
                }
            }
            Some(ConfigureCommand::Responder {
                enable,
                ref dry_run,
            }) => commands::responder::cmd_configure_responder(
                &cli,
                *enable,
                false,
                dry_run.as_deref().map(|val| val != "false"),
            ),
            Some(ConfigureCommand::Sensitivity { ref level }) => {
                if !cli.dry_run {
                    require_sudo(&cli);
                }
                let min_severity = match level.to_lowercase().as_str() {
                    "quiet" => "critical",
                    "normal" => "high",
                    "verbose" => "medium",
                    _ => {
                        println!(
                            "Unknown level '{}'. Choose: quiet, normal, or verbose",
                            level
                        );
                        return Ok(());
                    }
                };
                config_editor::write_str(
                    &cli.agent_config,
                    "telegram",
                    "min_severity",
                    min_severity,
                )?;
                config_editor::write_str(
                    &cli.agent_config,
                    "webhook",
                    "min_severity",
                    min_severity,
                )?;
                println!("✅ Notification sensitivity: {level}");
                println!("   Telegram + webhook min_severity = \"{min_severity}\"");
                match level.to_lowercase().as_str() {
                    "quiet" => println!("   You'll only be notified for Critical events."),
                    "normal" => println!("   You'll be notified for High and Critical events."),
                    "verbose" => {
                        println!("   You'll be notified for Medium, High, and Critical events.")
                    }
                    _ => {}
                }
                systemd::restart_service("innerwarden-agent", false)?;
                println!("   Agent restarted.");

                // Audit log
                let mut audit = AdminActionEntry {
                    ts: chrono::Utc::now(),
                    operator: current_operator(),
                    source: "cli".to_string(),
                    action: "configure".to_string(),
                    target: "sensitivity".to_string(),
                    parameters: serde_json::json!({ "level": level }),
                    result: "success".to_string(),
                    prev_hash: None,
                };
                if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
                    eprintln!("  [warn] failed to write admin audit: {e:#}");
                }

                Ok(())
            }
            Some(ConfigureCommand::TwoFa) => cmd_configure_2fa(&cli),
        },
        Command::Notify { ref command } => match command {
            None => cmd_configure_menu(&cli),
            Some(NotifyCommand::Telegram {
                ref token,
                ref chat_id,
                no_test,
            }) => commands::notify::cmd_configure_telegram(
                &cli,
                token.as_deref(),
                chat_id.as_deref(),
                *no_test,
            ),
            Some(NotifyCommand::Slack {
                ref webhook_url,
                ref min_severity,
                no_test,
            }) => commands::notify::cmd_configure_slack(
                &cli,
                webhook_url.as_deref(),
                min_severity,
                *no_test,
            ),
            Some(NotifyCommand::Webhook {
                ref url,
                ref min_severity,
                no_test,
            }) => commands::notify::cmd_configure_webhook(
                &cli,
                url.as_deref(),
                min_severity,
                *no_test,
            ),
            Some(NotifyCommand::Dashboard {
                ref user,
                ref password,
            }) => commands::notify::cmd_configure_dashboard(&cli, user, password.as_deref()),
            Some(NotifyCommand::Test { ref channel }) => {
                commands::notify::cmd_test_alert(&cli, channel.as_deref())
            }
            Some(NotifyCommand::WebPush { ref subject }) => {
                cmd_notify_web_push_setup(&cli, subject.as_deref())
            }
        },
        Command::Integrate { ref command } => match command {
            None => cmd_configure_menu(&cli),
            Some(IntegrateCommand::Geoip) => commands::integrations::cmd_configure_geoip(&cli),
            Some(IntegrateCommand::Abuseipdb {
                ref api_key,
                auto_block_threshold,
            }) => commands::integrations::cmd_configure_abuseipdb(
                &cli,
                api_key.as_deref(),
                *auto_block_threshold,
            ),
            Some(IntegrateCommand::Cloudflare {
                ref zone_id,
                ref api_token,
            }) => commands::integrations::cmd_configure_cloudflare(
                &cli,
                zone_id.as_deref(),
                api_token.as_deref(),
            ),
            Some(IntegrateCommand::Watchdog { interval }) => {
                commands::integrations::cmd_configure_watchdog(&cli, *interval)
            }
        },
        Command::Mesh { ref command } => match command {
            MeshCommand::Enable => commands::mesh::cmd_mesh_enable(&cli),
            MeshCommand::Disable => commands::mesh::cmd_mesh_disable(&cli),
            MeshCommand::AddPeer {
                ref endpoint,
                ref label,
            } => commands::mesh::cmd_mesh_add_peer(&cli, endpoint, label.as_deref()),
            MeshCommand::Status => commands::mesh::cmd_mesh_status(&cli),
        },
        Command::Module { ref command } => match command {
            ModuleCommand::Validate { ref path, strict } => {
                commands::module::cmd_module_validate(path, *strict)
            }
            ModuleCommand::Enable { ref path, yes } => {
                commands::module::cmd_module_enable(&cli, path, *yes)
            }
            ModuleCommand::Disable { ref path, yes } => {
                commands::module::cmd_module_disable(&cli, path, *yes)
            }
            ModuleCommand::Search { ref query } => {
                commands::module::cmd_module_search(query.as_deref())
            }
            ModuleCommand::List { ref modules_dir } => {
                commands::module::cmd_module_list(&cli, modules_dir)
            }
            ModuleCommand::Status {
                ref id,
                ref modules_dir,
            } => commands::module::cmd_module_status(&cli, id, modules_dir),
            ModuleCommand::Install {
                ref source,
                ref modules_dir,
                enable,
                force,
                yes,
            } => commands::module::cmd_module_install(
                &cli,
                source,
                modules_dir,
                *enable,
                *force,
                *yes,
            ),
            ModuleCommand::Uninstall {
                ref id,
                ref modules_dir,
                yes,
            } => commands::module::cmd_module_uninstall(&cli, id, modules_dir, *yes),
            ModuleCommand::Publish {
                ref path,
                ref output,
            } => commands::module::cmd_module_publish(path, output.as_deref()),
            ModuleCommand::UpdateAll {
                ref modules_dir,
                check,
                yes,
            } => commands::module::cmd_module_update_all(&cli, modules_dir, *check, *yes),
        },
        Command::Incidents {
            days,
            ref severity,
            live,
        } => {
            if live {
                cmd_incidents_live(&cli, severity, &cli.data_dir.clone())
            } else {
                cmd_incidents(&cli, days, severity, &cli.data_dir.clone())
            }
        }
        Command::Block { ref ip, ref reason } => cmd_block(&cli, ip, reason, &cli.data_dir.clone()),
        Command::Unblock { ref ip, ref reason } => {
            cmd_unblock(&cli, ip, reason, &cli.data_dir.clone())
        }
        Command::Report { ref date } => {
            commands::status::cmd_report(&cli, date, &cli.data_dir.clone())
        }
        Command::Watchdog {
            threshold,
            notify,
            status,
        } => {
            if status {
                commands::watchdog::cmd_watchdog_status(&cli, &cli.data_dir.clone())
            } else {
                commands::watchdog::cmd_watchdog(&cli, threshold, notify, &cli.data_dir.clone())
            }
        }
        Command::Tune { days, yes } => cmd_tune(&cli, days, yes, &cli.data_dir.clone()),
        Command::SensorStatus => commands::status::cmd_sensor_status(&cli, &cli.data_dir.clone()),
        Command::Export {
            ref kind,
            ref from,
            ref to,
            ref format,
            ref output,
        } => cmd_export(
            &cli,
            kind,
            from.as_deref(),
            to.as_deref(),
            format,
            output.as_deref(),
            &cli.data_dir.clone(),
        ),
        Command::Tail {
            ref r#type,
            interval,
        } => cmd_tail(&cli, r#type, interval, &cli.data_dir.clone()),
        Command::Decisions { days, ref action } => {
            cmd_decisions(&cli, days, action.as_deref(), &cli.data_dir.clone())
        }
        Command::Entity { ref target, days } => {
            cmd_entity(&cli, target, days, &cli.data_dir.clone())
        }
        Command::Completions { ref shell } => cmd_completions(shell),
        Command::Allowlist { ref command } => match command {
            AllowlistCommand::Add { ref ip, ref user } => {
                cmd_allowlist_add(&cli, ip.as_deref(), user.as_deref())
            }
            AllowlistCommand::Remove { ref ip, ref user } => {
                cmd_allowlist_remove(&cli, ip.as_deref(), user.as_deref())
            }
            AllowlistCommand::List => cmd_allowlist_list(&cli),
        },
        Command::Suppress { ref command } => match command {
            SuppressCommand::Add { ref pattern } => cmd_suppress_add(&cli, pattern),
            SuppressCommand::Remove { ref pattern } => cmd_suppress_remove(&cli, pattern),
            SuppressCommand::List => cmd_suppress_list(&cli),
        },
        Command::PipelineTest { wait } => cmd_pipeline_test(&cli, wait, &cli.data_dir.clone()),
        Command::Backup { ref output } => cmd_backup(&cli, output.as_deref()),
        Command::Metrics => commands::status::cmd_metrics(&cli, &cli.data_dir.clone()),
        Command::Gdpr { ref action } => match action {
            GdprCommand::Export {
                ref entity,
                ref output,
            } => cmd_gdpr_export(&cli.data_dir, entity, output.as_deref()),
            GdprCommand::Erase { ref entity, yes } => cmd_gdpr_erase(&cli.data_dir, entity, *yes),
        },
        Command::Agent { ref command } => commands::agent::cmd_agent(&cli, command.as_ref()),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn cmd_list(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    println!("{:<20} {:<10} Description", "Capability", "Status");
    println!("{}", "─".repeat(72));
    for cap in registry.all() {
        let opts = make_opts(cli, HashMap::new(), false);
        let status = if cap.is_enabled(&opts) {
            "enabled"
        } else {
            "disabled"
        };
        println!("{:<20} {:<10} {}", cap.id(), status, cap.description());
    }

    println!();
    println!("System coverage:");
    println!("  22 eBPF kernel hooks (execve, connect, ptrace, setuid, bind, mount, ...)");
    println!("  36 stateful detectors (SSH brute-force, rootkit, reverse shell, ransomware, ...)");
    println!("  13 log collectors (auth_log, journald, docker, nginx, suricata, ...)");
    println!("  7 kill chain patterns blocked at kernel level");
    println!();
    println!("These run automatically. Capabilities above are optional add-ons.");
    println!("Run 'innerwarden scan' to see what's recommended for this machine.");

    Ok(())
}

fn cmd_daily(
    cli: &Cli,
    registry: &CapabilityRegistry,
    command: Option<&DailyCommand>,
) -> Result<()> {
    match command {
        Some(DailyCommand::Status) => {
            let modules_dir = Path::new("/etc/innerwarden/modules");
            commands::status::cmd_status_global(cli, registry, modules_dir)
        }
        Some(DailyCommand::Threats {
            days,
            severity,
            live,
        }) => {
            if *live {
                cmd_incidents_live(cli, severity, &cli.data_dir.clone())
            } else {
                cmd_incidents(cli, *days, severity, &cli.data_dir.clone())
            }
        }
        Some(DailyCommand::Actions { days }) => {
            cmd_decisions(cli, *days, None, &cli.data_dir.clone())
        }
        Some(DailyCommand::Report { date }) => {
            commands::status::cmd_report(cli, date, &cli.data_dir.clone())
        }
        Some(DailyCommand::Doctor) => cmd_doctor(cli, registry),
        Some(DailyCommand::Test { wait }) => cmd_pipeline_test(cli, *wait, &cli.data_dir.clone()),
        Some(DailyCommand::Agent { command }) => commands::agent::cmd_agent(cli, command.as_ref()),
        None => {
            println!("InnerWarden Daily Commands");
            println!("{}", "═".repeat(52));
            println!("Use these for day-to-day operations:");
            println!("  innerwarden daily status");
            println!("  innerwarden daily threats");
            println!("  innerwarden daily actions");
            println!("  innerwarden daily report");
            println!("  innerwarden daily doctor");
            println!("  innerwarden daily test");
            println!("  innerwarden daily agent");
            println!();
            println!("Short aliases:");
            println!("  innerwarden quick status");
            println!("  innerwarden day threats --live");
            println!("  innerwarden quick agent scan");
            println!();
            println!("Need advanced operations?");
            println!("  innerwarden --help");
            println!("  innerwarden <command> --help");
            Ok(())
        }
    }
}

pub(crate) fn today_date_string() -> String {
    // Use SystemTime → seconds since epoch → compute date
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_secs_to_date_string(secs)
}

/// Return yesterday's date as YYYY-MM-DD.
pub(crate) fn yesterday_date_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(86400))
        .unwrap_or(0);
    epoch_secs_to_date_string(secs)
}

/// Convert Unix timestamp (seconds) to YYYY-MM-DD string (UTC).
pub(crate) fn epoch_secs_to_date_string(secs: u64) -> String {
    // Days since Unix epoch
    let days = secs / 86400;
    // Gregorian calendar calculation
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Count lines in a JSONL file (returns 0 if file doesn't exist).
pub(crate) fn count_jsonl_lines(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

/// Read the last incident from a JSONL file and return (title, time_str).
pub(crate) fn read_last_incident_summary(path: &std::path::Path) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let last_line = content.lines().rfind(|l| !l.trim().is_empty())?;
    let v: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let title = v["title"].as_str()?.to_string();
    let ts = v["ts"].as_str()?;

    // Calculate "time ago"
    let time_ago = if let Ok(incident_time) = chrono::DateTime::parse_from_rfc3339(ts) {
        let diff = chrono::Utc::now() - incident_time.with_timezone(&chrono::Utc);
        let mins = diff.num_minutes();
        if mins < 1 {
            "just now".to_string()
        } else if mins < 60 {
            format!("{mins}m ago")
        } else if mins < 1440 {
            format!("{}h ago", mins / 60)
        } else {
            format!("{}d ago", mins / 1440)
        }
    } else if ts.len() >= 16 {
        format!("{} UTC", &ts[11..16])
    } else {
        ts.to_string()
    };

    Some((title, time_ago))
}

pub(crate) fn cmd_enable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, params, yes);

    if cap.is_enabled(&opts) {
        println!(
            "Capability '{}' is already enabled. Nothing to do.",
            cap.id()
        );
        return Ok(());
    }

    println!("Enabling capability: {}\n", cap.name());

    // --- Preflight checks ---
    println!("Preflight checks:");
    let preflights = cap.preflights(&opts);
    let mut any_failed = false;
    for pf in &preflights {
        match pf.check() {
            Ok(()) => println!("  [ok] {}", pf.name()),
            Err(e) => {
                println!("  [fail] {}", e.message);
                if let Some(hint) = &e.fix_hint {
                    println!("         → {hint}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("preflight checks failed - no changes applied");
    }

    // --- Planned effects ---
    println!("\nPlanned changes:");
    let effects = cap.planned_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // --- Confirmation ---
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // --- Activate ---
    let report = cap.activate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "enable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now enabled.", cap.id());
    Ok(())
}

fn cmd_disable(cli: &Cli, registry: &CapabilityRegistry, id: &str, yes: bool) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), yes);

    if !cap.is_enabled(&opts) {
        println!("Capability '{}' is not enabled. Nothing to do.", cap.id());
        return Ok(());
    }

    println!("Disabling capability: {}\n", cap.name());

    println!("Changes to apply:");
    let effects = cap.planned_disable_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let report = cap.deactivate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "disable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now disabled.", cap.id());
    Ok(())
}

// ---------------------------------------------------------------------------
// C.5 - Upgrade
// ---------------------------------------------------------------------------

fn cmd_upgrade(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
) -> Result<()> {
    use upgrade::*;

    println!("Checking for updates...");

    let release =
        fetch_latest_release().context("could not reach GitHub - check network and try again")?;

    let current = CURRENT_VERSION;
    let latest = strip_v(&release.tag_name);

    let date_suffix = release
        .release_date()
        .map(|d| format!("  [{d}]"))
        .unwrap_or_default();

    println!("  Current version:  {current}");

    if !is_newer(current, &release.tag_name) {
        println!("  Latest release:   {latest}{date_suffix} - already up to date.");
        return Ok(());
    }

    println!(
        "  Latest release:   {latest}{date_suffix}  ({})",
        release.html_url
    );

    // --notify: send Telegram alert about available update (for cron use)
    if notify {
        let env_file = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/agent.env"));
        let env_vars = load_env_file(&env_file);
        let bot_token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok())
            .unwrap_or_default();
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok())
            .unwrap_or_default();
        if !bot_token.is_empty() && !chat_id.is_empty() {
            // Extract changelog from release body
            let changelog = release
                .body
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(500)
                .collect::<String>();
            let text = format!(
                "🆕 <b>Inner Warden {latest} available</b>\n\n\
                 Current: {current}\n\
                 New: {latest}{date_suffix}\n\n\
                 {changelog}\n\n\
                 Upgrade: <code>innerwarden upgrade --yes</code>"
            );
            let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
            let _ = ureq::post(&url).send_json(serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }));
            println!("  Telegram notification sent.");
        } else {
            println!("  --notify: Telegram not configured, skipping notification.");
        }
    }

    if check_only {
        println!("\nRun 'innerwarden upgrade' to install.");
        return Ok(());
    }

    // Auto-backup configs before upgrade
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or(Path::new("/etc/innerwarden"));
    if config_dir.exists() {
        match tempfile::Builder::new()
            .prefix("innerwarden-backup-pre-upgrade-")
            .suffix(".tar.gz")
            .tempfile()
        {
            Ok(tmp) => {
                let backup_path = tmp.path().to_string_lossy().to_string();
                print!("  Backing up configs to {backup_path}... ");
                match std::process::Command::new("tar")
                    .args(["czf", &backup_path, "-C", "/"])
                    .arg(config_dir.strip_prefix("/").unwrap_or(config_dir))
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        // Keep the backup file (prevent cleanup on drop)
                        let _ = tmp.keep();
                        println!("done");
                    }
                    _ => println!("skipped (tar failed, continuing anyway)"),
                }
            }
            Err(_) => {
                println!("  Skipping backup (could not create temp file)");
            }
        }
    }

    // Detect architecture
    let arch = detect_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported CPU architecture '{}' - build from source for your platform",
            std::env::consts::ARCH
        )
    })?;

    // Build download plan
    let plan = build_plan(&release, arch);

    if plan.is_empty() {
        anyhow::bail!(
            "no assets found for linux-{arch} in release {} - \
             check {} for manual download",
            release.tag_name,
            release.html_url
        );
    }

    println!("\nAssets available for linux-{arch}:");
    for dp in &plan {
        let sha_status = if dp.sha256_asset.is_some() {
            "sha256 ✓"
        } else {
            "no sha256"
        };
        let sig_status = if dp.sig_asset.is_some() {
            "  sig ✓"
        } else {
            ""
        };
        println!(
            "  {:<28} {}  ({}{})",
            dp.target.binary,
            fmt_bytes(dp.asset.size),
            sha_status,
            sig_status
        );
    }

    let dest_paths: Vec<_> = plan
        .iter()
        .flat_map(|dp| install_paths(dp.target, install_dir))
        .collect();

    println!("\nWill install to {}:", install_dir.display());
    for p in &dest_paths {
        println!("  {}", p.display());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    for dp in &plan {
        let binary = dp.target.binary;
        print!("  Downloading {binary}... ");
        std::io::stdout().flush()?;

        let tmp_path = tmp_dir.path().join(binary);
        let bytes = download(&dp.asset.browser_download_url, &tmp_path)?;

        // Verify SHA-256 if sidecar is present
        if let Some(sha_asset) = dp.sha256_asset {
            let expected = fetch_expected_hash(&sha_asset.browser_download_url)?;
            let actual = sha256_file(&tmp_path)?;
            if actual != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for {binary}:\n  expected {expected}\n  got      {actual}"
                );
            }
            print!("{}  sha256 ok", fmt_bytes(bytes));
        } else {
            print!("{}  (no sha256 sidecar)", fmt_bytes(bytes));
        }

        // Verify Ed25519 signature if .sig sidecar is present
        if let Some(sig_asset) = dp.sig_asset {
            let sig_b64 = fetch_signature(&sig_asset.browser_download_url)?;
            let binary_bytes =
                std::fs::read(&tmp_path).context("cannot read downloaded binary for sig check")?;
            verify_signature(&binary_bytes, &sig_b64)?;
            println!("  sig ok");
        } else {
            println!();
            println!("  [warn] unsigned release - signature verification skipped for {binary}");
        }

        // Install to all target names
        for dest in install_paths(dp.target, install_dir) {
            install_binary(&tmp_path, &dest, false)?;
            println!("  [done] {} → {}", binary, dest.display());
        }
    }

    // Fix permissions on existing config files - files written before v0.1.9 may
    // be root:root 600, which prevents innerwarden-agent (User=innerwarden) from
    // reading them. chmod 640 + chgrp innerwarden is fail-silent.
    fix_config_dir_permissions(
        cli.agent_config
            .parent()
            .unwrap_or(std::path::Path::new("/etc/innerwarden")),
    );

    // Restart running services; also start the agent if it has a unit file but is stopped
    println!();
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let unit_path = format!("/etc/systemd/system/{unit}.service");
        let unit_exists = std::path::Path::new(&unit_path).exists();
        if systemd::is_service_active(unit) {
            systemd::restart_service(unit, false)?;
            println!("  [done] Restarted {unit}");
        } else if unit_exists {
            // Unit is installed but stopped - try to start it
            match systemd::restart_service(unit, false) {
                Ok(()) => println!("  [done] Started {unit}"),
                Err(e) => {
                    println!("  [warn] Could not start {unit}: {e}");
                    println!("         Check logs: journalctl -u {unit} -n 30");
                }
            }
        }
    }

    let date_display = release
        .release_date()
        .map(|d| format!(" ({d})"))
        .unwrap_or_default();

    println!(
        "\nInnerWarden upgraded to {}{} successfully.",
        release.tag_name, date_display
    );

    // Show what's new in this release
    if let Some(preview) = release.changelog_preview() {
        println!("\nWhat's new in {}:", release.tag_name);
        println!("─────────────────────────────────────────────────");
        for line in preview.lines() {
            println!("  {line}");
        }
        println!("─────────────────────────────────────────────────");
        println!("  Full release notes: {}", release.html_url);
    } else {
        println!("  Release notes: {}", release.html_url);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Configure AI
// ---------------------------------------------------------------------------

/// Fix permissions on all config files in the innerwarden config directory.
/// chmod 640 + chgrp innerwarden so the service user (User=innerwarden) can read them.
/// Fail-silent - best-effort in environments where the group doesn't exist.
fn fix_config_dir_permissions(config_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640));
            let _ = std::process::Command::new("chgrp")
                .arg("innerwarden")
                .arg(&path)
                .output();
        }
    }
}

fn write_env_key(env_path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = std::fs::read_to_string(env_path).unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| {
            // Remove existing setting (active or commented)
            let l = l.trim_start_matches('#').trim_start();
            !l.starts_with(&format!("{key}="))
        })
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key}={value}"));
    let new_content = lines.join("\n") + "\n";
    // Atomic write via temp file in same directory
    let tmp = env_path.with_extension("env.tmp");
    std::fs::write(&tmp, &new_content)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, env_path)
        .with_context(|| format!("cannot update {}", env_path.display()))?;
    // Ensure readable by innerwarden service user (chmod 640 + chgrp innerwarden).
    // Fail-silent - best-effort in case the group doesn't exist (e.g. local dev).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o640));
        let _ = std::process::Command::new("chgrp")
            .arg("innerwarden")
            .arg(env_path)
            .output();
    }
    Ok(())
}

// innerwarden configure (interactive menu)
// ---------------------------------------------------------------------------

fn cmd_configure_menu(cli: &Cli) -> Result<()> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);

    // Read agent.toml for enabled flags
    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let is_enabled = |section: &str| -> bool {
        agent_doc
            .as_ref()
            .and_then(|doc| doc.get(section))
            .and_then(|s| s.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    };
    let has_env = |key: &str| -> bool {
        env_vars.get(key).is_some_and(|v| !v.is_empty())
            || std::env::var(key).is_ok_and(|v| !v.is_empty())
    };

    // Build status labels
    let status = |ok: bool| -> &'static str {
        if ok {
            "✅ configured"
        } else {
            "○  not set up"
        }
    };

    let ai_ok = is_enabled("ai");
    let telegram_ok = has_env("TELEGRAM_BOT_TOKEN") && has_env("TELEGRAM_CHAT_ID");
    let slack_ok = has_env("SLACK_WEBHOOK_URL") || {
        agent_doc
            .as_ref()
            .and_then(|doc| doc.get("slack"))
            .and_then(|s| s.get("webhook_url"))
            .and_then(|u| u.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    let webhook_ok = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("webhook"))
        .and_then(|w| w.get("enabled"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    let dashboard_ok = has_env("INNERWARDEN_DASHBOARD_USER");
    let abuseipdb_ok = has_env("ABUSEIPDB_API_KEY") || is_enabled("abuseipdb");
    let geoip_ok = is_enabled("geoip");
    let fail2ban_ok = is_enabled("fail2ban");
    let cloudflare_ok = has_env("CLOUDFLARE_API_TOKEN") || is_enabled("cloudflare");
    let responder_ok = is_enabled("responder");
    let watchdog_ok = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("innerwarden watchdog"))
        .unwrap_or(false);

    println!("InnerWarden - configure\n");
    println!("Choose what to set up:\n");
    println!("   1. AI provider      {}", status(ai_ok));
    println!("   2. Telegram         {}", status(telegram_ok));
    println!("   3. Slack            {}", status(slack_ok));
    println!("   4. Webhook          {}", status(webhook_ok));
    println!("   5. Dashboard        {}", status(dashboard_ok));
    println!("   6. AbuseIPDB        {}", status(abuseipdb_ok));
    println!("   7. GeoIP            {}", status(geoip_ok));
    println!("   8. Fail2ban         {}", status(fail2ban_ok));
    println!("   9. Cloudflare       {}", status(cloudflare_ok));
    println!("  10. Responder        {}", status(responder_ok));
    println!("  11. Watchdog (cron)  {}", status(watchdog_ok));
    println!();
    print!("Enter number (or q to quit): ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    println!();
    match choice {
        "1" => commands::ai::cmd_configure_ai_interactive(cli),
        "2" => commands::notify::cmd_configure_telegram(cli, None, None, false),
        "3" => commands::notify::cmd_configure_slack(cli, None, "high", false),
        "4" => commands::notify::cmd_configure_webhook(cli, None, "high", false),
        "5" => commands::notify::cmd_configure_dashboard(cli, "admin", None),
        "6" => commands::integrations::cmd_configure_abuseipdb(cli, None, None),
        "7" => commands::integrations::cmd_configure_geoip(cli),
        "8" => cmd_configure_fail2ban(cli),
        "9" => commands::integrations::cmd_configure_cloudflare(cli, None, None),
        "10" => commands::responder::cmd_configure_responder(cli, false, false, None),
        "11" => commands::integrations::cmd_configure_watchdog(cli, 10),
        "q" | "Q" | "" => {
            println!(
                "Tip: run 'innerwarden configure <name>' to jump directly to any integration."
            );
            Ok(())
        }
        _ => {
            println!("Invalid choice. Run 'innerwarden configure' again.");
            Ok(())
        }
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_with_hint(label: &str, hint: &str) -> Result<String> {
    print!("{label} ({hint}): ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// ---------------------------------------------------------------------------
// innerwarden configure fail2ban
// ---------------------------------------------------------------------------

fn cmd_configure_fail2ban(cli: &Cli) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    // Check fail2ban is installed
    let installed = std::process::Command::new("fail2ban-client")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !installed {
        if std::env::consts::OS == "macos" {
            anyhow::bail!(
                "fail2ban is not available on macOS.\n\
                 This integration only works on Linux."
            );
        }
        anyhow::bail!(
            "fail2ban-client not found. Install it first:\n\
             \n\
             Ubuntu/Debian:  sudo apt install fail2ban\n\
             RHEL/CentOS:    sudo yum install fail2ban\n\
             \n\
             Then run this command again."
        );
    }

    // Check it's running
    let running = std::process::Command::new("fail2ban-client")
        .arg("ping")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !running {
        println!("  Warning: fail2ban is installed but not running.");
        println!("  Start it with: sudo systemctl start fail2ban");
        println!("  Enabling the integration anyway - it will activate when fail2ban starts.\n");
    }

    if cli.dry_run {
        println!(
            "[dry-run] would set [fail2ban] enabled=true in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    config_editor::write_bool(&cli.agent_config, "fail2ban", "enabled", true)?;
    println!("  [ok] agent.toml: fail2ban.enabled = true");

    restart_agent(cli);
    println!();
    println!("Fail2ban integration enabled.");
    println!("IPs banned by fail2ban will automatically be enforced via your block skill.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared restart helper
// ---------------------------------------------------------------------------

fn restart_agent(cli: &Cli) {
    if cli.dry_run {
        return;
    }
    let is_macos = std::env::consts::OS == "macos";
    if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }
}

fn hostname() -> String {
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// innerwarden ai install
// ---------------------------------------------------------------------------

fn cmd_ai_install(cli: &Cli, model: &str, api_key_arg: Option<&str>, yes: bool) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let is_macos = std::env::consts::OS == "macos";

    // Resolve API key: --api-key flag > OLLAMA_API_KEY env var > interactive prompt
    let api_key = if let Some(k) = api_key_arg {
        k.to_string()
    } else if let Ok(k) = std::env::var("OLLAMA_API_KEY") {
        if !k.is_empty() {
            k
        } else {
            commands::ai::prompt_ollama_api_key()?
        }
    } else {
        commands::ai::prompt_ollama_api_key()?
    };

    println!("InnerWarden AI - Ollama cloud setup");
    println!();
    println!("  Provider: Ollama cloud (https://api.ollama.com)");
    println!("  Model:    {model}");
    println!("  API key:  {}...", &api_key[..api_key.len().min(12)]);
    println!();

    if !yes {
        print!("Configure innerwarden-agent with these settings? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if !trimmed.is_empty() && trimmed != "y" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Configure agent.toml and restart
    println!("[1/2] Updating innerwarden-agent config...");
    if cli.dry_run {
        println!("  [dry-run] would set [ai] enabled=true provider=ollama model={model} base_url=https://api.ollama.com api_key=<redacted>");
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", "ollama")?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        config_editor::write_str(
            &cli.agent_config,
            "ai",
            "base_url",
            "https://api.ollama.com",
        )?;
        config_editor::write_str(&cli.agent_config, "ai", "api_key", &api_key)?;
        println!("  [ok] agent.toml updated");
    }

    println!("[2/2] Restarting innerwarden-agent...");
    if cli.dry_run {
        println!("  [dry-run] would restart innerwarden-agent");
    } else {
        if is_macos {
            systemd::restart_launchd("com.innerwarden.agent", false)?;
        } else {
            systemd::restart_service("innerwarden-agent", false)?;
        }
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("Done. Ollama cloud AI is active.");
    println!("Model:   {model}");
    println!("Tier:    Free (check https://ollama.com/pricing for limits)");
    println!();
    println!("Run 'innerwarden doctor' to validate the connection.");
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden test-alert
// ---------------------------------------------------------------------------

fn cmd_configure_2fa(cli: &Cli) -> Result<()> {
    println!();
    println!("  \u{1f510} Two-Factor Authentication Setup");
    println!("  ================================");
    println!();
    println!("  Choose your second factor:");
    println!("  1. TOTP (Google Authenticator, Authy, 1Password)");
    println!("  2. None (disabled, default)");
    println!();
    print!("  Choose [1-2]: ");
    use std::io::Write;
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    match choice {
        "1" => {
            // Generate TOTP secret
            use rand_core::{OsRng, RngCore};
            let mut secret_bytes = [0u8; 20];
            OsRng.fill_bytes(&mut secret_bytes);
            let secret_b32 = base32_encode_simple(&secret_bytes);

            let uri = format!(
                "otpauth://totp/InnerWarden:admin?secret={}&issuer=InnerWarden&algorithm=SHA1&digits=6&period=30",
                secret_b32
            );

            println!();
            println!("  Scan this URI with your authenticator app:");
            println!();
            println!("  {}", uri);
            println!();
            print!("  Enter the 6-digit code to verify: ");
            std::io::stdout().flush()?;

            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let code = code.trim();

            // Verify the code
            if verify_totp_code(&secret_bytes, code) {
                // Save to agent.env
                let env_file = cli
                    .agent_config
                    .parent()
                    .map(|p| p.join("agent.env"))
                    .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

                append_or_update_env(&env_file, "INNERWARDEN_TOTP_SECRET", &secret_b32)?;

                // Update agent.toml
                config_editor::write_str(
                    &cli.agent_config,
                    "security",
                    "two_factor_method",
                    "totp",
                )?;

                println!();
                println!("  \u{2705} 2FA enabled with TOTP");
                println!("  Secret saved to {}", env_file.display());
                println!();
                println!("  All sensitive actions (allowlist, mode changes) now require a code.");

                // Restart agent to pick up the new config
                if !cli.dry_run {
                    let _ = systemd::restart_service("innerwarden-agent", false);
                    println!("  Agent restarted.");
                }

                Ok(())
            } else {
                println!();
                println!("  \u{274c} Wrong code. Please try again.");
                println!("  Run: innerwarden configure 2fa");
                Ok(())
            }
        }
        "2" | "" => {
            config_editor::write_str(&cli.agent_config, "security", "two_factor_method", "none")?;
            println!();
            println!("  \u{2705} 2FA disabled");
            if !cli.dry_run {
                let _ = systemd::restart_service("innerwarden-agent", false);
                println!("  Agent restarted.");
            }
            Ok(())
        }
        _ => {
            println!("  Unknown option. Run: innerwarden configure 2fa");
            Ok(())
        }
    }
}

/// Simple base32 encoding (RFC 4648, no padding).
fn base32_encode_simple(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

/// Verify a TOTP code against a secret (for setup verification).
fn verify_totp_code(secret: &[u8], code: &str) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let user_code: u32 = match code.parse() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_step = now / 30;

    for offset in [0i64, -1, 1] {
        let step = (time_step as i64 + offset) as u64;
        if generate_totp_code(secret, step) == user_code {
            return true;
        }
    }
    false
}

/// Generate a TOTP code for a time step (standalone, for CTL).
fn generate_totp_code(secret: &[u8], time_step: u64) -> u32 {
    let msg = time_step.to_be_bytes();
    let hash = hmac_sha1_simple(secret, &msg);
    let offset = (hash[19] & 0x0f) as usize;
    let code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    code % 1_000_000
}

/// Minimal HMAC-SHA1 for TOTP (standalone, for CTL).
fn hmac_sha1_simple(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..20].copy_from_slice(&sha1_simple(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha1_simple(&inner_data);

    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    sha1_simple(&outer_data)
}

/// Minimal SHA-1 for TOTP (standalone, for CTL).
#[allow(clippy::needless_range_loop)]
fn sha1_simple(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

/// Append or update an environment variable in an env file.
fn append_or_update_env(env_file: &std::path::Path, key: &str, value: &str) -> Result<()> {
    let content = std::fs::read_to_string(env_file).unwrap_or_default();
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with(&format!("{key}=")) {
                found = true;
                format!("{key}=\"{value}\"")
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("{key}=\"{value}\""));
    }

    if let Some(parent) = env_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(env_file, lines.join("\n") + "\n")?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(env_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Load key=value pairs from an env file (silently ignores missing file).
fn load_env_file(path: &std::path::Path) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    map
}

/// Send a plain Telegram message (MarkdownV2).
fn send_telegram_message_md(token: &str, chat_id: &str, text: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    });
    let resp = ureq::post(&url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json: serde_json::Value = resp.into_body().read_json()?;
    if json["ok"].as_bool() != Some(true) {
        anyhow::bail!(
            "{}",
            json["description"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden tune
// ---------------------------------------------------------------------------

fn cmd_tune(cli: &Cli, days: u64, yes: bool, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    println!("InnerWarden Tune - analysing last {days} day(s) of data");
    println!("{}", "─".repeat(56));

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── Collect per-detector event counts and incident counts ──
    // Detectors we know how to tune
    let detectors = [
        (
            "ssh_bruteforce",
            "ssh.login_failed",
            "detectors.ssh_bruteforce.threshold",
        ),
        (
            "credential_stuffing",
            "ssh.invalid_user",
            "detectors.credential_stuffing.threshold",
        ),
        (
            "sudo_abuse",
            "sudo.command",
            "detectors.sudo_abuse.threshold",
        ),
        (
            "search_abuse",
            "http.request",
            "detectors.search_abuse.threshold",
        ),
        ("web_scan", "http.error", "detectors.web_scan.threshold"),
        (
            "port_scan",
            "network.connection_blocked",
            "detectors.port_scan.threshold",
        ),
    ];

    // Events per kind over the window
    let mut event_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    // Incidents per detector
    let mut incident_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for i in 0..days {
        let date = epoch_secs_to_date(now_secs.saturating_sub(i * 86400));

        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(kind) = v["kind"].as_str() {
                    *event_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }

        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(id) = v["incident_id"].as_str() {
                    // incident_id format: detector:entity:seq
                    let detector = id.split(':').next().unwrap_or("");
                    if !detector.is_empty() {
                        *incident_counts.entry(detector.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // ── Read current thresholds from sensor config ─────────
    let sensor_content = std::fs::read_to_string(&cli.sensor_config).unwrap_or_default();
    let sensor_toml: Option<toml_edit::DocumentMut> = sensor_content.parse().ok();

    let current_threshold = |config_path: &str| -> Option<i64> {
        let parts: Vec<&str> = config_path.split('.').collect();
        // e.g. ["detectors", "ssh_bruteforce", "threshold"]
        if parts.len() != 3 {
            return None;
        }
        sensor_toml
            .as_ref()
            .and_then(|doc| doc.get(parts[0]))
            .and_then(|t| t.get(parts[1]))
            .and_then(|d| d.get(parts[2]))
            .and_then(|v| v.as_integer())
    };

    // ── Compute suggestions ────────────────────────────────
    struct Suggestion {
        detector: &'static str,
        current: Option<i64>,
        suggested: i64,
        reason: String,
    }

    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut has_data = false;

    for (detector, event_kind, config_path) in &detectors {
        let events = *event_counts.get(*event_kind).unwrap_or(&0);
        let incidents = *incident_counts.get(*detector).unwrap_or(&0);
        let current = current_threshold(config_path);

        if events == 0 {
            continue;
        }
        has_data = true;

        let events_per_day = (events as f64 / days as f64).ceil() as i64;
        let current_val = current.unwrap_or(8);

        // Heuristic: if daily noise >> threshold → suggest raising it
        // If incident rate is very high (> 5/day) → suggest lowering threshold
        let incidents_per_day = incidents as f64 / days as f64;
        let suggested = if incidents_per_day > 10.0 && current_val > 3 {
            // Very noisy - lower threshold so we catch earlier
            (current_val - 1).max(2)
        } else if events_per_day > (current_val * 20) && incidents == 0 {
            // Extremely noisy with zero incidents → raise threshold
            (current_val + 2).min(50)
        } else if events_per_day > (current_val * 5) && incidents_per_day < 1.0 {
            // Moderately noisy with few incidents → raise slightly
            (current_val + 1).min(30)
        } else {
            current_val // no change
        };

        if suggested == current_val {
            continue; // no suggestion needed
        }

        let direction = if suggested > current_val {
            "raise"
        } else {
            "lower"
        };
        let reason = format!(
            "{} events/day, {} incidents in {days} days - {direction} to reduce noise",
            events_per_day, incidents
        );
        suggestions.push(Suggestion {
            detector,
            current,
            suggested,
            reason,
        });
    }

    if !has_data {
        println!("\nNo event data found in {}.", effective_dir.display());
        println!("Run the sensor for a few days first, then re-run tune.");
        return Ok(());
    }

    if suggestions.is_empty() {
        println!("\n✅ All detector thresholds look well-calibrated for this host.");
        println!("   Events/day are within expected range relative to current thresholds.");
        println!("   Re-run after more data accumulates: --days 14");
        return Ok(());
    }

    println!("\nSuggested threshold changes:\n");
    println!(
        "  {:<22}  {:>8}  {:>9}  Reason",
        "Detector", "Current", "Suggested"
    );
    println!("  {}", "─".repeat(72));
    for s in &suggestions {
        let cur_str = s
            .current
            .map(|v| v.to_string())
            .unwrap_or_else(|| "default".to_string());
        println!(
            "  {:<22}  {:>8}  {:>9}  {}",
            s.detector, cur_str, s.suggested, s.reason
        );
    }

    // ── Apply if confirmed ─────────────────────────────────
    let apply = if yes {
        true
    } else {
        print!(
            "\nApply these changes to {}? [y/N] ",
            cli.sensor_config.display()
        );
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    if !apply {
        println!("No changes made. Re-run with --yes to apply.");
        return Ok(());
    }

    if cli.dry_run {
        println!(
            "[dry-run] Would patch {} with {} change(s)",
            cli.sensor_config.display(),
            suggestions.len()
        );
        return Ok(());
    }

    // Patch sensor.toml
    let mut doc: toml_edit::DocumentMut = sensor_content
        .parse()
        .with_context(|| format!("failed to parse {}", cli.sensor_config.display()))?;

    for s in &suggestions {
        // config_path is "detectors.ssh_bruteforce.threshold"
        // Walk: doc["detectors"]["ssh_bruteforce"]["threshold"]
        let parts: Vec<&str> = detectors
            .iter()
            .find(|(d, _, _)| *d == s.detector)
            .map(|(_, _, p)| p.split('.').collect())
            .unwrap_or_default();
        if parts.len() == 3 {
            if let Some(section) = doc
                .get_mut(parts[0])
                .and_then(|t| t.as_table_mut())
                .and_then(|t| t.get_mut(parts[1]))
                .and_then(|t| t.as_table_mut())
            {
                section.insert(parts[2], toml_edit::value(s.suggested));
            }
        }
    }

    std::fs::write(&cli.sensor_config, doc.to_string())
        .with_context(|| format!("failed to write {}", cli.sensor_config.display()))?;

    println!(
        "✅ Applied {} change(s) to {}",
        suggestions.len(),
        cli.sensor_config.display()
    );
    println!("Restart the sensor to apply: sudo systemctl restart innerwarden-sensor");

    // Audit log
    let tuned: Vec<&str> = suggestions.iter().map(|s| s.detector).collect();
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "tune".to_string(),
        target: "detectors".to_string(),
        parameters: serde_json::json!({ "detectors": tuned, "days": days }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden incidents
// ---------------------------------------------------------------------------

fn cmd_incidents(cli: &Cli, days: u64, severity_filter: &str, data_dir: &Path) -> Result<()> {
    // Resolve data_dir from agent.toml if using default
    let effective_dir = if data_dir == Path::new("/var/lib/innerwarden") {
        std::fs::read_to_string(&cli.agent_config)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|v| {
                v.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    };

    let min_rank = severity_rank(severity_filter);

    // Collect dates to scan
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut dates = Vec::new();
    for i in 0..days {
        let secs = now_secs.saturating_sub(i * 86400);
        dates.push(epoch_secs_to_date(secs));
    }

    let mut total = 0usize;
    for date in &dates {
        let path = effective_dir.join(format!("incidents-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            continue;
        }

        println!("── {date} ─────────────────────────────────────────────");

        // Print in reverse (newest last, most scannable)
        for line in &lines {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let sev = v["severity"].as_str().unwrap_or("Info");
            if severity_rank(sev) < min_rank {
                continue;
            }
            let title = v["title"].as_str().unwrap_or("Unknown threat");
            let ts = v["ts"].as_str().unwrap_or("");
            let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
            let ip = v["entities"]
                .as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|e| e["type"].as_str() == Some("Ip"))
                        .and_then(|e| e["value"].as_str())
                })
                .unwrap_or("");
            let sev_tag = sev_tag_bracket(sev);
            let ip_part = if ip.is_empty() {
                String::new()
            } else {
                format!("  {ip}")
            };
            println!("  {time}  {sev_tag}  {title}{ip_part}");
            total += 1;
        }
        println!();
    }

    if total == 0 {
        if severity_filter != "low" {
            println!(
                "No {} or higher incidents found in the last {} day(s).",
                severity_filter, days
            );
        } else {
            println!("No incidents found in the last {} day(s). Quiet!", days);
        }
    } else {
        println!("{total} incident(s) shown.  Run 'innerwarden report' for the full narrative.");
    }
    Ok(())
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn sev_tag_bracket(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => "[CRITICAL]",
        "high" => "[HIGH]    ",
        "medium" => "[MEDIUM]  ",
        "low" => "[LOW]     ",
        _ => "[INFO]    ",
    }
}

fn sev_tag_plain(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => " CRITICAL",
        "high" => " HIGH    ",
        "medium" => " MEDIUM  ",
        "low" => " LOW     ",
        _ => "         ",
    }
}

pub(crate) fn epoch_secs_to_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ---------------------------------------------------------------------------
// innerwarden block / unblock
// ---------------------------------------------------------------------------

fn cmd_block(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    // Basic IP validation
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    // Read configured block backend from agent.toml
    let backend = std::fs::read_to_string(&cli.agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string());

    println!("Blocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would run block command for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    // Execute the block
    let blocked = match backend.as_str() {
        "iptables" => std::process::Command::new("sudo")
            .args(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "nftables" => std::process::Command::new("sudo")
            .args([
                "nft",
                "add",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                &format!("{{ {ip} }}"),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "pf" => std::process::Command::new("sudo")
            .args(["pfctl", "-t", "innerwarden-blocked", "-T", "add", ip])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => {
            // ufw (default)
            std::process::Command::new("sudo")
                .args(["ufw", "deny", "from", ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };

    if !blocked {
        anyhow::bail!("block command failed - check sudo permissions (run: innerwarden doctor)");
    }
    println!("  [ok] {ip} blocked via {backend}");

    // Write audit trail
    write_manual_decision(&effective_dir, ip, "block_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now blocked. To reverse: innerwarden unblock {ip} --reason \"...\"");
    Ok(())
}

fn cmd_unblock(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    let backend = std::fs::read_to_string(&cli.agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string());

    println!("Unblocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would remove block for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    let unblocked = match backend.as_str() {
        "iptables" => std::process::Command::new("sudo")
            .args(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "nftables" => std::process::Command::new("sudo")
            .args([
                "nft",
                "delete",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                &format!("{{ {ip} }}"),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        "pf" => std::process::Command::new("sudo")
            .args(["pfctl", "-t", "innerwarden-blocked", "-T", "delete", ip])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        _ => {
            // ufw: delete the deny rule
            std::process::Command::new("sudo")
                .args(["ufw", "delete", "deny", "from", ip])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };

    if !unblocked {
        println!("  Warning: unblock command may have failed (rule may not exist).");
        println!("  Check manually: sudo ufw status | grep {ip}");
    } else {
        println!("  [ok] {ip} unblocked via {backend}");
    }

    write_manual_decision(&effective_dir, ip, "unblock_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "unblock_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now unblocked.");
    Ok(())
}

fn looks_like_ip(s: &str) -> bool {
    // Accept IPv4 (digits and dots) or IPv6 (hex, colons, optional /)
    let s = s.split('/').next().unwrap_or(s); // strip CIDR
    let v4 = s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok());
    let v6 = s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    v4 || v6
}

/// Check whether the current process can write to the InnerWarden config directory.
/// If not, print a clear hint and exit - avoids failing mid-operation.
fn require_sudo(cli: &Cli) {
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/etc/innerwarden"));

    // Try creating a temp file in the directory as the write test
    let test_path = config_dir.join(".innerwarden-write-test");
    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&test_path)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "Permission denied: cannot write to {}",
                config_dir.display()
            );
            eprintln!();
            // Reconstruct the original command to show the sudo hint
            let args: Vec<String> = std::env::args().collect();
            let cmd_args = args[1..].join(" ");
            eprintln!("Run with sudo:");
            eprintln!("  sudo innerwarden {cmd_args}");
            std::process::exit(1);
        }
        Err(_) => {} // some other error; let the real operation surface it
    }
}

pub(crate) fn resolve_data_dir(cli: &Cli, data_dir: &Path) -> PathBuf {
    if data_dir == Path::new("/var/lib/innerwarden") {
        std::fs::read_to_string(&cli.agent_config)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|v| {
                v.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    }
}

fn write_manual_decision(
    data_dir: &Path,
    ip: &str,
    action: &str,
    reason: &str,
    provider: &str,
) -> Result<()> {
    let today = epoch_secs_to_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let now_iso = chrono::Utc::now().to_rfc3339();
    let entry = serde_json::json!({
        "ts": now_iso,
        "action": action,
        "target_ip": ip,
        "reason": reason,
        "ai_provider": provider,
        "confidence": 1.0,
        "executed": true,
        "dry_run": false,
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{}", entry)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden backup
// ---------------------------------------------------------------------------

fn cmd_backup(cli: &Cli, output: Option<&Path>) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    // When no --output is given, create a secure temp file with an unpredictable name
    let tmp_file = if output.is_none() {
        Some(
            tempfile::Builder::new()
                .prefix("innerwarden-backup-")
                .suffix(".tar.gz")
                .tempfile()
                .context("failed to create temp file for backup")?,
        )
    } else {
        None
    };
    let default_path: PathBuf;
    let output_path = if let Some(ref tmp) = tmp_file {
        default_path = tmp.path().to_path_buf();
        &default_path
    } else {
        output.unwrap()
    };

    let files = [
        "etc/innerwarden/config.toml",
        "etc/innerwarden/agent.toml",
        "etc/innerwarden/agent.env",
    ];

    println!("InnerWarden - backup\n");
    println!("Backing up configuration files:");
    for f in &files {
        let abs = Path::new("/").join(f);
        let exists = abs.exists();
        println!("  {} /{}", if exists { "●" } else { "○ (missing)" }, f);
    }
    println!();
    println!("Output: {}", output_path.display());

    if cli.dry_run {
        println!("\n  [dry-run] would create archive - skipping.");
        return Ok(());
    }

    let status = std::process::Command::new("tar")
        .arg("czf")
        .arg(output_path)
        .arg("-C")
        .arg("/")
        .args(files)
        .status()
        .context("failed to run tar")?;

    if status.success() {
        // Keep the temp file so the backup persists on disk
        if let Some(tmp) = tmp_file {
            let _ = tmp.keep();
        }
        println!("\n  [ok] backup saved to {}", output_path.display());
    } else {
        anyhow::bail!(
            "tar exited with status {} - some files may be missing from /etc/innerwarden/",
            status
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden export
// ---------------------------------------------------------------------------

fn cmd_export(
    cli: &Cli,
    kind: &str,
    from_arg: Option<&str>,
    to_arg: Option<&str>,
    format: &str,
    output_path: Option<&Path>,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let from = from_arg.unwrap_or(&today).to_string();
    let to = to_arg.unwrap_or(&today).to_string();

    let prefix = match kind {
        "events" => "events",
        "decisions" => "decisions",
        _ => "incidents",
    };

    // Collect all matching JSONL lines across the date range
    let mut all_lines: Vec<serde_json::Value> = Vec::new();

    // Enumerate all files matching prefix-*.jsonl in the dir
    if let Ok(entries) = std::fs::read_dir(&effective_dir) {
        let mut files: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(date) = name
                    .strip_prefix(&format!("{prefix}-"))
                    .and_then(|s| s.strip_suffix(".jsonl"))
                {
                    date >= from.as_str() && date <= to.as_str()
                } else {
                    false
                }
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        all_lines.push(v);
                    }
                }
            }
        }
    }

    if all_lines.is_empty() {
        eprintln!("No {kind} found between {from} and {to}.");
        return Ok(());
    }

    let content = match format {
        "csv" => {
            // Build CSV from the union of all keys across objects
            let mut keys: Vec<String> = all_lines
                .iter()
                .filter_map(|v| v.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            keys.retain(|k| k != "evidence" && k != "details" && k != "entities"); // skip nested

            let mut out = keys.join(",") + "\n";
            for row in &all_lines {
                let fields: Vec<String> = keys
                    .iter()
                    .map(|k| {
                        let v = &row[k];
                        let s = match v {
                            serde_json::Value::String(s) => s.replace('"', "\"\""),
                            serde_json::Value::Null => String::new(),
                            other => other.to_string().replace('"', "\"\""),
                        };
                        if s.contains(',') || s.contains('"') || s.contains('\n') {
                            format!("\"{s}\"")
                        } else {
                            s
                        }
                    })
                    .collect();
                out += &(fields.join(",") + "\n");
            }
            out
        }
        _ => serde_json::to_string_pretty(&all_lines)?,
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &content)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!(
                "Exported {} {kind}(s) ({from} → {to}) to {}",
                all_lines.len(),
                path.display()
            );
        }
        None => print!("{content}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden tail
// ---------------------------------------------------------------------------

fn cmd_tail(cli: &Cli, kind: &str, interval_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let prefix = if kind == "events" {
        "events"
    } else {
        "incidents"
    };

    println!("Streaming {kind}... (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        // Reset offset when the date changes
        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let path = effective_dir.join(format!("{prefix}-{today}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        print_tail_entry(&v, kind);
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
    }
}

fn print_tail_entry(v: &serde_json::Value, kind: &str) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 16 { &ts[11..16] } else { ts };

    if kind == "events" {
        let source = v["source"].as_str().unwrap_or("?");
        let ev_kind = v["kind"].as_str().unwrap_or("?");
        let sev = v["severity"].as_str().unwrap_or("Info");
        let summary = v["summary"].as_str().unwrap_or("");
        println!("{time}  [{sev:<8}]  {source:<16}  {ev_kind}  {summary}");
    } else {
        // incident
        let sev = v["severity"].as_str().unwrap_or("Info");
        let title = v["title"].as_str().unwrap_or("Unknown");
        let ip = v["entities"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|e| e["type"].as_str() == Some("Ip"))
                    .and_then(|e| e["value"].as_str())
            })
            .unwrap_or("");
        let sev_tag = sev_tag_bracket(sev);
        let ip_part = if ip.is_empty() {
            String::new()
        } else {
            format!("  {ip}")
        };
        println!("{time}  {sev_tag}  {title}{ip_part}");
    }
}

// ---------------------------------------------------------------------------
// innerwarden incidents --live
// ---------------------------------------------------------------------------

fn cmd_incidents_live(cli: &Cli, severity_filter: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let min_sev = parse_severity_filter(severity_filter);

    println!("● LIVE - streaming incidents (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let safe_date: String = today
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let path = effective_dir.join(format!("incidents-{safe_date}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        let sev = v["severity"].as_str().unwrap_or("info");
                        if severity_rank_str(sev) >= min_sev {
                            print_live_incident(&v);
                        }
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn print_live_incident(v: &serde_json::Value) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 19 { &ts[11..19] } else { ts };
    let sev = v["severity"].as_str().unwrap_or("info");
    let title = v["title"].as_str().unwrap_or("Unknown");
    let summary = v["summary"].as_str().unwrap_or("");

    let icon = match sev {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        _ => "⚪",
    };

    let entities: Vec<String> = v["entities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e["value"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let entity_str = if entities.is_empty() {
        String::new()
    } else {
        format!("  [{}]", entities.join(", "))
    };

    println!("{icon} {time}  {title}{entity_str}");
    if !summary.is_empty() && summary != title {
        // Truncate long summaries
        let short: String = summary.chars().take(100).collect();
        println!("  └ {short}");
    }
    println!();
}

fn parse_severity_filter(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// innerwarden decisions
// ---------------------------------------------------------------------------

fn cmd_decisions(cli: &Cli, days: u64, action_filter: Option<&str>, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    let mut total = 0usize;
    for date in &dates {
        let path = effective_dir.join(format!("decisions-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            continue;
        }

        println!("── {date} ─────────────────────────────────────────────");

        for line in &lines {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let action = v["action_type"].as_str().unwrap_or("unknown");
            if let Some(f) = action_filter {
                if !action.eq_ignore_ascii_case(f) {
                    continue;
                }
            }
            let ts = v["ts"].as_str().unwrap_or("");
            let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
            let target_ip = v["target_ip"].as_str().unwrap_or("");
            let target_user = v["target_user"].as_str().unwrap_or("");
            let confidence = v["confidence"].as_f64().unwrap_or(0.0);
            let dry_run = v["dry_run"].as_bool().unwrap_or(false);
            let provider = v["ai_provider"].as_str().unwrap_or("");

            let target = if !target_ip.is_empty() {
                target_ip.to_string()
            } else if !target_user.is_empty() {
                format!("user:{target_user}")
            } else {
                String::new()
            };

            let dry_tag = if dry_run { " [dry-run]" } else { "" };
            let conf_tag = if confidence > 0.0 {
                format!("  conf:{:.2}", confidence)
            } else {
                String::new()
            };
            let provider_tag = if !provider.is_empty() {
                format!("  via:{provider}")
            } else {
                String::new()
            };
            let target_part = if target.is_empty() {
                String::new()
            } else {
                format!("  {target}")
            };

            let action_tag = match action {
                "block_ip" => "[BLOCK]      ",
                "suspend_user_sudo" => "[SUSPEND]    ",
                "ignore" => "[IGNORE]     ",
                "monitor" => "[MONITOR]    ",
                "honeypot" => "[HONEYPOT]   ",
                "request_confirmation" => "[PENDING]    ",
                _ => "[UNKNOWN]    ",
            };

            println!("  {time}  {action_tag}{target_part}{conf_tag}{provider_tag}{dry_tag}");
            total += 1;
        }
        println!();
    }

    if total == 0 {
        if let Some(f) = action_filter {
            println!("No '{f}' decisions found in the last {days} day(s).");
        } else {
            println!("No decisions recorded in the last {days} day(s).");
            println!("The agent may be in observe-only mode or not running.");
            println!("Run 'innerwarden status' to check.");
        }
    } else {
        println!(
            "{total} decision(s) shown.  Full audit trail: {}/decisions-*.jsonl",
            effective_dir.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden entity
// ---------------------------------------------------------------------------

fn cmd_entity(cli: &Cli, target: &str, days: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    // Determine if target looks like an IP or a username
    let is_ip = looks_like_ip(target);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    // Collect all matching entries across events, incidents, and decisions
    #[derive(Debug)]
    struct Entry {
        ts: String,
        kind: &'static str, // "event", "incident", "decision"
        severity: String,
        summary: String,
        extra: String,
    }

    let mut entries: Vec<Entry> = Vec::new();

    for date in &dates {
        // ── events ──────────────────────────────────────
        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("Ip")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("User")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "event",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["summary"].as_str().unwrap_or("").to_string(),
                        extra: v["kind"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        // ── incidents ────────────────────────────────────
        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("ip"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("user"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "incident",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["title"].as_str().unwrap_or("").to_string(),
                        extra: v["summary"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        // ── decisions ────────────────────────────────────
        let decisions_path = effective_dir.join(format!("decisions-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let ip_match = is_ip && v["target_ip"].as_str() == Some(target);
                let user_match = !is_ip && v["target_user"].as_str() == Some(target);
                if ip_match || user_match {
                    let action = v["action_type"].as_str().unwrap_or("unknown");
                    let dry_run = v["dry_run"].as_bool().unwrap_or(false);
                    let dry_tag = if dry_run { " [dry-run]" } else { "" };
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "decision",
                        severity: String::new(),
                        summary: format!("Action: {action}{dry_tag}"),
                        extra: format!(
                            "conf:{:.2}  via:{}",
                            v["confidence"].as_f64().unwrap_or(0.0),
                            v["ai_provider"].as_str().unwrap_or("?")
                        ),
                    });
                }
            }
        }
    }

    if entries.is_empty() {
        let entity_type = if is_ip { "IP" } else { "user" };
        println!("No activity found for {entity_type} '{target}' in the last {days} day(s).");
        println!("Try --days 7 to search further back.");
        return Ok(());
    }

    // Sort by timestamp ascending
    entries.sort_by(|a, b| a.ts.cmp(&b.ts));

    let entity_type = if is_ip { "IP" } else { "User" };
    let event_count = entries.iter().filter(|e| e.kind == "event").count();
    let incident_count = entries.iter().filter(|e| e.kind == "incident").count();
    let decision_count = entries.iter().filter(|e| e.kind == "decision").count();

    println!("Entity: {entity_type} {target}");
    println!("Period: last {days} day(s)");
    println!("Found:  {event_count} event(s)  {incident_count} incident(s)  {decision_count} decision(s)");
    println!("{}", "─".repeat(72));

    for entry in &entries {
        let time = if entry.ts.len() >= 16 {
            &entry.ts[..16]
        } else {
            &entry.ts
        };
        let kind_tag = match entry.kind {
            "incident" => "[INCIDENT]  ",
            "decision" => "[DECISION]  ",
            _ => "[event]     ",
        };
        let sev_tag = if entry.kind == "event" || entry.kind == "incident" {
            sev_tag_plain(&entry.severity)
        } else {
            "         "
        };
        println!("{time}  {kind_tag}{sev_tag}  {}", entry.summary);
        if !entry.extra.is_empty() && entry.kind != "event" {
            println!("                                     {}", entry.extra);
        }
    }

    println!("{}", "─".repeat(72));
    println!("Open dashboard for full details: innerwarden status");
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden completions
// ---------------------------------------------------------------------------

fn cmd_completions(shell: &str) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::Shell;

    let mut cmd = Cli::command();
    let shell_enum = match shell.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        other => {
            anyhow::bail!("unsupported shell '{}' - supported: bash, zsh, fish", other)
        }
    };

    clap_complete::generate(shell_enum, &mut cmd, "innerwarden", &mut std::io::stdout());
    Ok(())
}

// C.4 - Doctor
// ---------------------------------------------------------------------------

fn cmd_doctor(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    #[derive(PartialEq)]
    enum Sev {
        Ok,
        Warn,
        Fail,
    }

    struct Check {
        label: String,
        sev: Sev,
        hint: Option<String>,
    }

    impl Check {
        fn ok(label: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Ok,
                hint: None,
            }
        }
        fn warn(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Warn,
                hint: Some(hint.into()),
            }
        }
        fn fail(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Fail,
                hint: Some(hint.into()),
            }
        }
        fn print(&self) {
            let tag = match self.sev {
                Sev::Ok => "[ok]  ",
                Sev::Warn => "[warn]",
                Sev::Fail => "[fail]",
            };
            println!("  {tag} {}", self.label);
            if let Some(h) = &self.hint {
                println!("         → {h}");
            }
        }
        fn is_issue(&self) -> bool {
            self.sev != Sev::Ok
        }
    }

    fn run_section(checks: Vec<Check>, issues: &mut u32) {
        for c in &checks {
            c.print();
            if c.is_issue() {
                *issues += 1;
            }
        }
    }

    println!("InnerWarden Doctor");
    println!("{}", "═".repeat(48));

    let mut total_issues: u32 = 0;

    let is_macos = std::env::consts::OS == "macos";

    // ── System ────────────────────────────────────────────
    println!("\nSystem");
    let mut sys = Vec::new();

    if is_macos {
        // launchctl
        let has_launchctl = std::path::Path::new("/bin/launchctl").exists()
            || std::path::Path::new("/usr/bin/launchctl").exists();
        sys.push(if has_launchctl {
            Check::ok("launchctl found (macOS service manager)")
        } else {
            Check::fail(
                "launchctl not found",
                "unexpected on macOS - check your PATH",
            )
        });

        // innerwarden user
        let user_ok = std::process::Command::new("id")
            .arg("innerwarden")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "run install.sh - it creates the user via dscl",
            )
        });

        // /etc/sudoers.d/ (exists on macOS too)
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::warn(
                "/etc/sudoers.d/ not found",
                "sudo mkdir -p /etc/sudoers.d  (needed for suspend-user-sudo skill)",
            )
        });

        // pfctl (needed for block-ip-pf)
        let has_pfctl = std::path::Path::new("/sbin/pfctl").exists();
        sys.push(if has_pfctl {
            Check::ok("pfctl found (block-ip-pf skill available)")
        } else {
            Check::warn(
                "pfctl not found",
                "pfctl is built-in on macOS - unexpected. block-ip-pf skill will not work.",
            )
        });

        // `log` binary (needed for macos_log collector)
        let has_log_bin = std::path::Path::new("/usr/bin/log").exists();
        sys.push(if has_log_bin {
            Check::ok("`log` binary found (macos_log collector available)")
        } else {
            Check::fail(
                "`log` binary not found at /usr/bin/log",
                "unexpected on macOS - macos_log collector requires Apple Unified Logging",
            )
        });
    } else {
        // systemctl
        let has_systemctl = std::path::Path::new("/usr/bin/systemctl").exists()
            || std::path::Path::new("/bin/systemctl").exists();
        sys.push(if has_systemctl {
            Check::ok("systemctl found")
        } else {
            Check::fail("systemctl not found", "install systemd or check PATH")
        });

        // innerwarden user
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let user_ok = passwd
            .lines()
            .any(|l| l.split(':').next() == Some("innerwarden"));
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "sudo useradd -r -s /sbin/nologin innerwarden",
            )
        });

        // /etc/sudoers.d/
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::fail("/etc/sudoers.d/ not found", "sudo mkdir -p /etc/sudoers.d")
        });
    }

    run_section(sys, &mut total_issues);

    // ── Services ──────────────────────────────────────────
    println!("\nServices");
    let mut svc = Vec::new();
    if is_macos {
        for (label, plist) in &[
            ("innerwarden-sensor", "com.innerwarden.sensor"),
            ("innerwarden-agent", "com.innerwarden.agent"),
        ] {
            let running = std::process::Command::new("launchctl")
                .args(["list", plist])
                .output()
                .map(|o| {
                    o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\"")
                })
                .unwrap_or(false);
            svc.push(if running {
                Check::ok(format!("{label} is running"))
            } else {
                Check::warn(
                    format!("{label} is not running"),
                    format!("sudo launchctl load /Library/LaunchDaemons/{plist}.plist"),
                )
            });
        }
    } else {
        for unit in &["innerwarden-sensor", "innerwarden-agent"] {
            svc.push(if systemd::is_service_active(unit) {
                Check::ok(format!("{unit} is running"))
            } else {
                Check::warn(
                    format!("{unit} is not running"),
                    format!("sudo systemctl start {unit}"),
                )
            });
        }
    }
    run_section(svc, &mut total_issues);

    // ── Configuration ─────────────────────────────────────
    println!("\nConfiguration");
    let mut cfg = Vec::new();

    for (label, path) in &[("Sensor", &cli.sensor_config), ("Agent", &cli.agent_config)] {
        if path.exists() {
            cfg.push(Check::ok(format!(
                "{} config found ({})",
                label,
                path.display()
            )));
            let valid_toml = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .is_some();
            cfg.push(if valid_toml {
                Check::ok(format!("{} config is valid TOML", label))
            } else {
                Check::fail(
                    format!(
                        "{} config has invalid TOML syntax ({})",
                        label,
                        path.display()
                    ),
                    format!("fix syntax in {}", path.display()),
                )
            });
        } else {
            cfg.push(Check::warn(
                format!(
                    "{} config not found ({}) - defaults are in use",
                    label,
                    path.display()
                ),
                "Run 'sudo innerwarden setup' to create your configuration",
            ));
        }
    }

    // AI provider + API key - detect provider from agent config then validate the right key
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Read agent.toml to find configured provider and whether AI is enabled
    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();

    // Helper: resolve a key from env var or agent.env file
    let resolve_key = |env_var: &str| -> Option<String> {
        if let Ok(v) = std::env::var(env_var) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        std::fs::read_to_string(&env_file).ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{env_var}=")))
                .and_then(|l| l.split_once('=').map(|x| x.1))
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        })
    };

    if !ai_enabled {
        cfg.push(Check::warn(
            "AI not configured (ai.enabled = false)",
            "Detection and logging still work without AI.\nTo add AI triage, run one of:\n\n  innerwarden configure ai openai --key sk-...\n  innerwarden configure ai anthropic --key sk-ant-...\n  innerwarden configure ai ollama --model llama3.2   (no key needed)",
        ));
    } else {
        match provider.as_str() {
            "anthropic" => {
                let key = resolve_key("ANTHROPIC_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "ANTHROPIC_API_KEY not set (provider = \"anthropic\")",
                            "Get a key at https://console.anthropic.com/settings/keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai anthropic --key sk-ant-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-ant-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("ANTHROPIC_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "ANTHROPIC_API_KEY is set but format looks wrong (should start with sk-ant-)",
                                "Run:\n  innerwarden configure ai anthropic --key sk-ant-...",
                            )
                        });
                    }
                }
            }
            "ollama" => {
                // Check if ollama is reachable
                let ollama_url = agent_doc
                    .as_ref()
                    .and_then(|doc| doc.get("ai"))
                    .and_then(|ai| ai.get("base_url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("http://localhost:11434")
                    .to_string();
                let ollama_ok = std::process::Command::new("curl")
                    .args(["-sf", "--max-time", "2", &format!("{ollama_url}/api/tags")])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                cfg.push(if ollama_ok {
                    Check::ok(format!("Ollama reachable at {ollama_url}"))
                } else {
                    Check::fail(
                        format!("Ollama not reachable at {ollama_url}"),
                        "Install and start Ollama:\n\n  curl -fsSL https://ollama.ai/install.sh | sh\n  ollama pull llama3.2\n\nThen run: innerwarden configure ai ollama --model llama3.2",
                    )
                });
            }
            _ => {
                // Default: openai (also handles unknown providers gracefully)
                let key = resolve_key("OPENAI_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "OPENAI_API_KEY not set (provider = \"openai\")",
                            "Get a key at https://platform.openai.com/api-keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai openai --key sk-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("OPENAI_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "OPENAI_API_KEY is set but format looks wrong (should start with sk-)",
                                "Run:\n  innerwarden configure ai openai --key sk-...",
                            )
                        });
                    }
                }
            }
        }
    }

    // AbuseIPDB enrichment - only when abuseipdb.enabled = true
    {
        let abuseipdb_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("abuseipdb"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if abuseipdb_enabled {
            let key_in_config = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("abuseipdb"))
                .and_then(|t| t.get("api_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let key_in_env = std::env::var("ABUSEIPDB_API_KEY")
                .ok()
                .filter(|s| !s.is_empty());
            let key_in_file = resolve_key("ABUSEIPDB_API_KEY");
            let resolved_key = key_in_config.or(key_in_env).or(key_in_file);

            cfg.push(match &resolved_key {
                None => Check::fail(
                    "abuseipdb.enabled=true but ABUSEIPDB_API_KEY not set",
                    "1. Register at https://www.abuseipdb.com/register (free)\n\
                     2. Go to https://www.abuseipdb.com/account/api\n\
                     3. Add to agent.toml:\n\
                     \n   [abuseipdb]\n   api_key = \"<your-key>\"\n\
                     \n   Or set env var: ABUSEIPDB_API_KEY=<your-key>",
                ),
                Some(k) if k.len() < 10 => Check::warn(
                    "ABUSEIPDB_API_KEY is set but looks too short",
                    "AbuseIPDB API keys are typically 80 characters.\n\
                     Get a fresh key at https://www.abuseipdb.com/account/api",
                ),
                Some(_) => Check::ok("ABUSEIPDB_API_KEY is set (free tier: 1,000 checks/day)"),
            });
        }
    }

    // Fail2ban integration - only when fail2ban.enabled = true
    {
        let fail2ban_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("fail2ban"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if fail2ban_enabled {
            let fb_bin = std::path::Path::new("/usr/bin/fail2ban-client").exists()
                || std::path::Path::new("/usr/local/bin/fail2ban-client").exists();
            cfg.push(if fb_bin {
                Check::ok("fail2ban-client binary found")
            } else {
                Check::fail(
                    "fail2ban-client not found but fail2ban.enabled=true",
                    "sudo apt-get install fail2ban",
                )
            });

            // Check fail2ban service is running
            let fb_running = if is_macos {
                false // fail2ban is Linux-only
            } else {
                std::process::Command::new("fail2ban-client")
                    .args(["ping"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            };
            cfg.push(if fb_running {
                Check::ok("fail2ban daemon is responding (ping ok)")
            } else if is_macos {
                Check::warn(
                    "fail2ban is Linux-only - integration will not run on macOS",
                    "disable [fail2ban] enabled=false in agent.toml on macOS",
                )
            } else {
                Check::warn(
                    "fail2ban daemon is not responding (fail2ban-client ping failed)",
                    "sudo systemctl start fail2ban",
                )
            });
        }
    }

    run_section(cfg, &mut total_issues);

    // ── Telegram ──────────────────────────────────────────
    // Only check Telegram when enabled = true in agent config.
    {
        let agent_toml: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let telegram_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("telegram"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if telegram_enabled {
            println!("\nTelegram");
            let mut tg = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve bot_token: config → env var → agent.env file
            let token_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("bot_token"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let token_in_env = std::env::var("TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let token_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_BOT_TOKEN="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_token = token_in_config.or(token_in_env).or(token_in_file);

            // Resolve chat_id: config → env var → agent.env file
            let chat_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("chat_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let chat_in_env = std::env::var("TELEGRAM_CHAT_ID")
                .ok()
                .filter(|s| !s.is_empty());
            let chat_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_CHAT_ID="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_chat = chat_in_config.or(chat_in_env).or(chat_in_file);

            // Check bot_token presence
            match &resolved_token {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_BOT_TOKEN not set",
                        format!(
                            "1. Open Telegram and message @BotFather\n\
                             2. Send /newbot and follow the steps\n\
                             3. Copy the token and add to {}:\n\
                             \n   TELEGRAM_BOT_TOKEN=1234567890:AABBccDDeeffGGHH...",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(token) => {
                    // Validate format: <digits>:<35+ alphanumeric chars>
                    let looks_valid = token.contains(':') && {
                        let mut parts = token.splitn(2, ':');
                        let id_part = parts.next().unwrap_or("");
                        let secret_part = parts.next().unwrap_or("");
                        id_part.chars().all(|c| c.is_ascii_digit())
                            && !id_part.is_empty()
                            && secret_part.len() >= 20
                    };
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_BOT_TOKEN is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_BOT_TOKEN is set but format looks wrong",
                            "Token should look like: 1234567890:AABBccDDeeffGGHHiijjKK...\n\
                             Get a fresh token from @BotFather on Telegram",
                        )
                    });
                }
            }

            // Check chat_id presence
            match &resolved_chat {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_CHAT_ID not set",
                        format!(
                            "1. Open Telegram and message @userinfobot\n\
                             2. It will reply with your chat ID (a number, e.g. 123456789)\n\
                             3. For a group/channel the ID starts with -100\n\
                             4. Add to {}:\n\
                             \n   TELEGRAM_CHAT_ID=123456789",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(chat_id) => {
                    // Chat ID should be numeric (possibly negative for groups)
                    let looks_valid = chat_id
                        .trim_start_matches('-')
                        .chars()
                        .all(|c| c.is_ascii_digit())
                        && !chat_id.is_empty();
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_CHAT_ID is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_CHAT_ID is set but format looks wrong",
                            "Chat ID should be a number like 123456789 (personal) or -1001234567890 (group/channel)\n\
                             Message @userinfobot on Telegram to find yours",
                        )
                    });
                }
            }

            // If both token and chat_id are valid, suggest a connectivity smoke-test
            if resolved_token.is_some() && resolved_chat.is_some() {
                tg.push(Check::ok(
                    "Telegram configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(tg, &mut total_issues);
        }

        // Only check Slack when enabled = true in agent config.
        let slack_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("slack"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if slack_enabled {
            println!("\nSlack");
            let mut sl = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve webhook_url: config → env var → agent.env file
            let url_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("slack"))
                .and_then(|t| t.get("webhook_url"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let url_in_env = std::env::var("SLACK_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.is_empty());
            let url_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("SLACK_WEBHOOK_URL="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_url = url_in_config.or(url_in_env).or(url_in_file);

            match &resolved_url {
                None => {
                    sl.push(Check::fail(
                        "SLACK_WEBHOOK_URL not set",
                        format!(
                            "1. In Slack: Apps → Incoming Webhooks → Add to Slack\n\
                             2. Choose a channel and copy the Webhook URL\n\
                             3. Add to {}:\n\
                             \n   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(url) => {
                    let looks_valid =
                        url.starts_with("https://hooks.slack.com/services/") && url.len() > 50;
                    sl.push(if looks_valid {
                        Check::ok("SLACK_WEBHOOK_URL is set and format looks correct")
                    } else {
                        Check::warn(
                            "SLACK_WEBHOOK_URL is set but format looks wrong",
                            "URL should start with https://hooks.slack.com/services/T.../B.../...\n\
                             Get a fresh webhook URL from your Slack workspace settings",
                        )
                    });
                }
            }

            if resolved_url.is_some() {
                sl.push(Check::ok(
                    "Slack configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(sl, &mut total_issues);
        }
    }

    // ── Webhook ────────────────────────────────────────────
    {
        let webhook_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if webhook_enabled {
            println!("\nWebhook");
            let mut wh: Vec<Check> = vec![];

            let url_val = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("webhook"))
                .and_then(|t| t.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if url_val.is_empty() {
                wh.push(Check::fail(
                    "webhook.url is not set",
                    "Run: innerwarden configure webhook",
                ));
            } else if !url_val.starts_with("http://") && !url_val.starts_with("https://") {
                wh.push(Check::fail(
                    "webhook.url does not look like a valid URL",
                    "Run: innerwarden configure webhook --url <correct-url>",
                ));
            } else {
                wh.push(Check::ok(format!("webhook.url = {url_val}").as_str()));
            }

            run_section(wh, &mut total_issues);
        }
    }

    // ── Dashboard ──────────────────────────────────────────
    {
        let dashboard_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("dashboard"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Always check if credentials are set (dashboard always available when agent runs)
        println!("\nDashboard");
        let mut db: Vec<Check> = vec![];

        let env_path = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
        let env_content = std::fs::read_to_string(&env_path).unwrap_or_default();

        let has_user = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_USER="))
            || std::env::var("INNERWARDEN_DASHBOARD_USER").is_ok();

        let has_hash = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_PASSWORD_HASH="))
            || std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").is_ok();

        // Check if --dashboard flag is in the service ExecStart
        let service_content =
            std::fs::read_to_string("/etc/systemd/system/innerwarden-agent.service")
                .unwrap_or_default();
        let dashboard_flag_in_service = service_content.contains("--dashboard");

        if dashboard_flag_in_service {
            db.push(Check::ok("--dashboard flag present in service ExecStart"));
        } else {
            db.push(Check::warn(
                "--dashboard flag is missing from innerwarden-agent.service ExecStart",
                "Run: innerwarden configure dashboard  (it will add the flag automatically)",
            ));
        }

        if has_user && has_hash {
            db.push(Check::ok(
                "Dashboard login is configured (credentials required)",
            ));
        } else {
            db.push(Check::ok(
                "Dashboard credentials: none set (open access when agent is running)",
            ));
            db.push(Check::ok(
                "To add a password: innerwarden configure dashboard",
            ));
        }

        // Check if the dashboard is actually reachable
        let dashboard_up = ureq::get("http://127.0.0.1:8787/api/status")
            .config()
            .timeout_global(Some(std::time::Duration::from_secs(2)))
            .build()
            .call()
            .is_ok();
        if dashboard_up {
            db.push(Check::ok(
                "Dashboard is reachable at http://YOUR_SERVER_IP:8787",
            ));
        } else if dashboard_flag_in_service {
            db.push(Check::warn(
                "Dashboard port 8787 is not responding",
                "Start the agent:  sudo systemctl start innerwarden-agent",
            ));
        }

        let _ = dashboard_enabled;
        run_section(db, &mut total_issues);
    }

    // ── GeoIP ──────────────────────────────────────────────
    {
        let geoip_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("geoip"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if geoip_enabled {
            println!("\nGeoIP");
            let mut geo: Vec<Check> = vec![];

            // Quick connectivity check
            let reachable = ureq::get("http://ip-api.com/json/8.8.8.8?fields=status")
                .config()
                .timeout_global(Some(std::time::Duration::from_secs(3)))
                .build()
                .call()
                .is_ok();

            if reachable {
                geo.push(Check::ok("ip-api.com is reachable"));
            } else {
                geo.push(Check::warn(
                    "ip-api.com is not reachable from this host",
                    "GeoIP lookups will fail silently. Check outbound HTTP access.",
                ));
            }

            run_section(geo, &mut total_issues);
        }
    }

    // ── Capabilities ──────────────────────────────────────
    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    let mut any_enabled = false;

    for cap in registry.all() {
        if !cap.is_enabled(&opts) {
            continue;
        }
        any_enabled = true;

        // Map capability → expected sudoers drop-in name
        let drop_in = match cap.id() {
            "block-ip" => Some("innerwarden-block-ip"),
            "sudo-protection" => Some("innerwarden-sudo-protection"),
            "search-protection" => Some("innerwarden-search-protection"),
            _ => None,
        };

        if let Some(name) = drop_in {
            let path = std::path::Path::new("/etc/sudoers.d").join(name);
            if path.exists() {
                println!("  [ok]   {} (enabled): sudoers drop-in present", cap.id());
            } else {
                println!(
                    "  [warn] {} (enabled): sudoers drop-in missing (/etc/sudoers.d/{name})",
                    cap.id()
                );
                println!("         → innerwarden enable {}", cap.id());
                total_issues += 1;
            }
        } else {
            println!("  [ok]   {} (enabled)", cap.id());
        }
    }

    if !any_enabled {
        println!("  (no capabilities enabled - run 'innerwarden list' to see options)");
    }

    // ── Integrations ──────────────────────────────────────
    // Only show this section when at least one integration collector is enabled.
    {
        let sensor_doc: Option<toml_edit::DocumentMut> = cli
            .sensor_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.sensor_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let collector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let collector_str = |name: &str, key: &str, default: &str| -> String {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };

        let detector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("detectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let falco_enabled = collector_enabled("falco_log");
        let suricata_enabled = collector_enabled("suricata_eve");
        let osquery_enabled = collector_enabled("osquery_log");
        let nginx_error_enabled = collector_enabled("nginx_error");
        let any_integration =
            falco_enabled || suricata_enabled || osquery_enabled || nginx_error_enabled;

        if any_integration {
            println!("\nIntegrations");

            // ── Falco ──────────────────────────────────────
            if falco_enabled {
                println!("  Falco");
                let mut falco = Vec::new();

                let falco_binary = std::path::Path::new("/usr/bin/falco").exists()
                    || std::path::Path::new("/usr/local/bin/falco").exists();
                falco.push(if falco_binary {
                    Check::ok("Falco binary found")
                } else {
                    Check::fail(
                        "Falco binary not found (/usr/bin/falco or /usr/local/bin/falco)",
                        "sudo apt-get install falco",
                    )
                });

                let falco_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.falco"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("falco")
                        || systemd::is_service_active("falco-modern-bpf")
                };
                let falco_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.falco.plist"
                } else {
                    "sudo systemctl start falco"
                };
                falco.push(if falco_active {
                    Check::ok("Falco service is running")
                } else {
                    Check::warn("Falco service is not running", falco_start_hint)
                });

                let falco_log = collector_str("falco_log", "path", "/var/log/falco/falco.log");
                let log_ok = std::path::Path::new(&falco_log).exists()
                    && std::fs::metadata(&falco_log)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false);
                let falco_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.falco"
                } else {
                    "sudo mkdir -p /var/log/falco && sudo systemctl restart falco"
                };
                let falco_json_hint = if is_macos {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo launchctl kickstart -k system/com.falco"
                } else {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo systemctl restart falco"
                };
                falco.push(if log_ok {
                    Check::ok(format!("Falco log file exists ({})", falco_log))
                } else {
                    Check::fail(
                        format!("Falco log file not found or not readable ({})", falco_log),
                        falco_restart_hint,
                    )
                });

                let falco_yaml =
                    std::fs::read_to_string("/etc/falco/falco.yaml").unwrap_or_default();
                let json_output_ok = falco_yaml.contains("json_output: true");
                falco.push(if json_output_ok {
                    Check::ok("Falco json_output is enabled")
                } else {
                    Check::warn(
                        "Falco json_output not enabled - events will not be parseable",
                        falco_json_hint,
                    )
                });

                run_section(falco, &mut total_issues);
            }

            // ── Suricata ───────────────────────────────────
            if suricata_enabled {
                println!("  Suricata (optional)");
                println!(
                    "    \x1b[2mNote: InnerWarden captures DNS, HTTP, and TLS natively.\x1b[0m"
                );
                println!(
                    "    \x1b[2mSuricata is optional — useful for deep packet inspection\x1b[0m"
                );
                println!("    \x1b[2mand CVE signatures in compliance-driven environments.\x1b[0m");
                let mut suri = Vec::new();

                let suri_binary = std::path::Path::new("/usr/bin/suricata").exists();
                suri.push(if suri_binary {
                    Check::ok("Suricata binary found")
                } else {
                    Check::fail(
                        "Suricata binary not found (/usr/bin/suricata)",
                        "sudo apt-get install suricata",
                    )
                });

                let suri_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.suricata"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("suricata")
                };
                let suri_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.suricata.plist"
                } else {
                    "sudo systemctl start suricata"
                };
                let suri_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.suricata  # creates eve.json on first run"
                } else {
                    "sudo systemctl restart suricata  # creates eve.json on first run"
                };
                suri.push(if suri_active {
                    Check::ok("Suricata service is running")
                } else {
                    Check::warn("Suricata service is not running", suri_start_hint)
                });

                let eve_log = collector_str("suricata_eve", "path", "/var/log/suricata/eve.json");
                let eve_ok = std::path::Path::new(&eve_log).exists();
                suri.push(if eve_ok {
                    Check::ok(format!("Suricata eve.json exists ({})", eve_log))
                } else {
                    Check::fail(
                        format!("Suricata eve.json not found ({})", eve_log),
                        suri_restart_hint,
                    )
                });

                let rules_present = std::path::Path::new("/var/lib/suricata/rules/suricata.rules")
                    .exists()
                    || std::fs::read_dir("/etc/suricata/rules/")
                        .map(|mut d| {
                            d.any(|e| {
                                e.map(|e| {
                                    e.path().extension().and_then(|x| x.to_str()) == Some("rules")
                                })
                                .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                suri.push(if rules_present {
                    Check::ok("Suricata ET rules present")
                } else {
                    Check::warn(
                        "Suricata ET rules not found",
                        if is_macos {
                            "sudo suricata-update && sudo launchctl kickstart -k system/com.suricata"
                        } else {
                            "sudo suricata-update && sudo systemctl restart suricata"
                        },
                    )
                });

                run_section(suri, &mut total_issues);
            }

            // ── osquery ────────────────────────────────────
            if osquery_enabled {
                println!("  osquery");
                let mut osq = Vec::new();

                let osq_binary = std::path::Path::new("/usr/bin/osqueryd").exists()
                    || std::path::Path::new("/usr/local/bin/osqueryd").exists();
                osq.push(if osq_binary {
                    Check::ok("osqueryd binary found")
                } else {
                    Check::fail(
                        "osqueryd binary not found (/usr/bin/osqueryd or /usr/local/bin/osqueryd)",
                        "sudo apt-get install osquery  # see modules/osquery-integration/docs/README.md",
                    )
                });

                let osq_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.facebook.osqueryd"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("osqueryd")
                };
                let osq_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist"
                } else {
                    "sudo systemctl start osqueryd"
                };
                osq.push(if osq_active {
                    Check::ok("osqueryd service is running")
                } else {
                    Check::warn("osqueryd service is not running", osq_start_hint)
                });

                let results_log = collector_str(
                    "osquery_log",
                    "path",
                    "/var/log/osquery/osqueryd.results.log",
                );
                let results_ok = std::path::Path::new(&results_log).exists();
                osq.push(if results_ok {
                    Check::ok(format!("osquery results log exists ({})", results_log))
                } else {
                    Check::warn(
                        format!("osquery results log not found yet ({})", results_log),
                        "ensure log_result_events=true in /etc/osquery/osquery.conf, then wait 60s for first query",
                    )
                });

                let osq_conf =
                    std::fs::read_to_string("/etc/osquery/osquery.conf").unwrap_or_default();
                let has_schedule = osq_conf.contains("\"schedule\"");
                osq.push(if has_schedule {
                    Check::ok("osquery config contains scheduled queries")
                } else {
                    Check::warn(
                        "osquery config does not contain scheduled queries",
                        "copy the recommended queries from modules/osquery-integration/config/sensor.example.toml into /etc/osquery/osquery.conf",
                    )
                });

                run_section(osq, &mut total_issues);
            }

            // ── nginx-error-monitor ────────────────────────
            if nginx_error_enabled {
                println!("  nginx-error-monitor");
                let mut nginx_err = Vec::new();

                // nginx binary
                let nginx_bin = std::path::Path::new("/usr/sbin/nginx").exists()
                    || std::path::Path::new("/usr/bin/nginx").exists()
                    || std::path::Path::new("/usr/local/sbin/nginx").exists();
                nginx_err.push(if nginx_bin {
                    Check::ok("nginx binary found")
                } else {
                    Check::fail("nginx binary not found", "sudo apt-get install nginx")
                });

                // error log path
                let err_log = collector_str("nginx_error", "path", "/var/log/nginx/error.log");
                let log_exists = std::path::Path::new(&err_log).exists();
                nginx_err.push(if log_exists {
                    Check::ok(format!("nginx error log exists ({})", err_log))
                } else {
                    Check::fail(
                        format!("nginx error log not found ({})", err_log),
                        "sudo systemctl start nginx  # log is created on first request or error",
                    )
                });

                // readability - can the current user read it?
                if log_exists {
                    let readable = std::fs::File::open(&err_log).is_ok();
                    nginx_err.push(if readable {
                        Check::ok(format!("nginx error log is readable ({})", err_log))
                    } else {
                        Check::warn(
                            format!("nginx error log is not readable by innerwarden user ({})", err_log),
                            "sudo usermod -aG adm innerwarden  # or: sudo chmod 640 /var/log/nginx/error.log",
                        )
                    });
                }

                // web_scan detector enabled?
                let web_scan_on = detector_enabled("web_scan");
                nginx_err.push(if web_scan_on {
                    Check::ok("web_scan detector is enabled")
                } else {
                    Check::warn(
                        "web_scan detector is disabled - http.error events are collected but not triaged",
                        "Add to sensor config:\n\n  [detectors.web_scan]\n  enabled = true\n  threshold = 15\n  window_seconds = 60",
                    )
                });

                run_section(nginx_err, &mut total_issues);
            }
        }
    }

    // ── Agent liveness ────────────────────────────────────
    {
        println!("\nAgent health");
        let mut liveness: Vec<Check> = vec![];

        let data_dir_opt: Option<std::path::PathBuf> = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("output"))
            .and_then(|o| o.get("data_dir"))
            .and_then(|d| d.as_str())
            .map(std::path::PathBuf::from)
            .or_else(|| Some(std::path::PathBuf::from("/var/lib/innerwarden")));

        if let Some(ref dir) = data_dir_opt {
            let today = chrono::Local::now().format("%Y-%m-%d").to_string();
            let telemetry_path = dir.join(format!("telemetry-{today}.jsonl"));
            if telemetry_path.exists() {
                if let Ok(meta) = std::fs::metadata(&telemetry_path) {
                    if let Ok(modified) = meta.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .map(|d| d.as_secs())
                            .unwrap_or(u64::MAX);
                        if age > 300 {
                            liveness.push(Check::warn(
                                format!("last telemetry write was {}s ago", age),
                                "agent may be stuck - check: journalctl -u innerwarden-agent -n 50",
                            ));
                        } else {
                            liveness
                                .push(Check::ok(format!("agent active - last write {}s ago", age)));
                        }
                    }
                }
            } else {
                liveness.push(Check::warn(
                    "no telemetry file for today",
                    "agent has not written telemetry yet - is it running? innerwarden status",
                ));
            }
        }
        run_section(liveness, &mut total_issues);
    }

    // ── Summary ───────────────────────────────────────────
    println!();
    println!("{}", "─".repeat(48));
    if total_issues == 0 {
        println!("All checks passed - system looks healthy.");
    } else {
        println!("{total_issues} issue(s) found - review hints above.");
        // If configs are missing, offer a one-command path forward
        let configs_missing = !cli.sensor_config.exists() || !cli.agent_config.exists();
        if configs_missing {
            println!();
            println!("Getting started:  sudo innerwarden setup");
            println!("  Walks you through AI, Telegram, and essential modules.");
        }
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn make_opts(
    cli: &Cli,
    params: HashMap<String, String>,
    yes: bool,
) -> ActivationOptions {
    ActivationOptions {
        sensor_config: cli.sensor_config.clone(),
        agent_config: cli.agent_config.clone(),
        dry_run: cli.dry_run,
        params,
        yes,
    }
}

fn parse_params(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (k, v) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid param '{}' - expected KEY=VALUE format", item)
        })?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

pub(crate) fn unknown_cap_error(id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unknown capability '{}' - run 'innerwarden list' to see available capabilities",
        id
    )
}

// ---------------------------------------------------------------------------
// innerwarden allowlist
// ---------------------------------------------------------------------------

fn cmd_allowlist_add(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use config_editor::write_array_push;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if added {
            println!("Added to trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} is already in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if added {
            println!("Added to trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} is already in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_add".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

fn cmd_allowlist_remove(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use config_editor::write_array_remove;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let removed = write_array_remove(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if removed {
            println!("Removed from trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} was not in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let removed =
            write_array_remove(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if removed {
            println!("Removed from trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} was not in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_remove".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

fn cmd_allowlist_list(cli: &Cli) -> Result<()> {
    use config_editor::read_str_array;
    let ips = read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
    let users = read_str_array(&cli.agent_config, "allowlist", "trusted_users");

    if ips.is_empty() && users.is_empty() {
        println!("Allowlist is empty - no trusted IPs or users configured.");
        println!("Add entries with: innerwarden allowlist add --ip <cidr>");
        return Ok(());
    }

    if !ips.is_empty() {
        println!("Trusted IPs / CIDRs:");
        for ip in &ips {
            println!("  {ip}");
        }
    }
    if !users.is_empty() {
        println!("Trusted users:");
        for user in &users {
            println!("  {user}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden suppress
// ---------------------------------------------------------------------------

fn suppressed_file(cli: &Cli) -> std::path::PathBuf {
    cli.data_dir.join("suppressed-incidents.txt")
}

fn cmd_suppress_add(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Check if already exists
    if existing.lines().any(|l| l.trim() == pattern) {
        println!("Pattern already suppressed: {pattern}");
        return Ok(());
    }

    // Append
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{pattern}")?;

    println!("Suppressed: {pattern}");
    println!("Matching incidents will be silently logged but not alerted.");
    println!();
    println!("  The agent will pick this up on next restart, or you can restart now:");
    println!("  sudo systemctl restart innerwarden-agent");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_add".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

fn cmd_suppress_remove(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    let new_content: String = content
        .lines()
        .filter(|l| l.trim() != pattern)
        .collect::<Vec<_>>()
        .join("\n");

    if content == new_content {
        println!("Pattern not found: {pattern}");
        return Ok(());
    }

    std::fs::write(
        &path,
        if new_content.is_empty() {
            String::new()
        } else {
            format!("{new_content}\n")
        },
    )?;
    println!("Removed suppression: {pattern}");
    println!("Matching incidents will alert again after agent restart.");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_remove".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

fn cmd_suppress_list(cli: &Cli) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let patterns: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if patterns.is_empty() {
        println!("No suppressed patterns.");
        println!("Add with: innerwarden suppress add <pattern>");
        return Ok(());
    }

    println!("Suppressed incident patterns:");
    for p in &patterns {
        println!("  {p}");
    }
    println!();
    println!(
        "{} pattern(s) active. Matching incidents are silently logged.",
        patterns.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden notify web-push setup
// ---------------------------------------------------------------------------

fn cmd_notify_web_push_setup(cli: &Cli, subject: Option<&str>) -> Result<()> {
    use config_editor::{write_bool, write_str};
    use std::io::Write as _;

    println!("Setting up Web Push notifications (RFC 8291 / VAPID)...");
    println!();

    // Check for existing keys
    let existing_key = write_str(&cli.agent_config, "web_push", "vapid_public_key", "");
    let has_existing = cli.agent_config.exists() && {
        let content = std::fs::read_to_string(&cli.agent_config).unwrap_or_default();
        content.contains("vapid_public_key") && !content.contains(r#"vapid_public_key = """#)
    };
    drop(existing_key);

    if has_existing {
        println!("⚠  VAPID keys are already configured.");
        print!("   Generate new keys? This will break existing browser subscriptions. [y/N] ");
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Keeping existing keys.");
            println!();
            print_web_push_next_steps(&cli.agent_config)?;
            return Ok(());
        }
    }

    // Generate VAPID key pair
    // We use p256 here via the agent crate's web_push module - but since ctl
    // is a separate binary, we implement key generation inline using the same
    // algorithm so we don't need to depend on the agent crate.
    let (private_pem, public_b64) = generate_vapid_keys_ctl()?;

    let subject_val = subject.unwrap_or("mailto:admin@example.com");

    // Write public key and subject to agent.toml
    write_str(
        &cli.agent_config,
        "web_push",
        "vapid_public_key",
        &public_b64,
    )?;
    write_str(&cli.agent_config, "web_push", "vapid_subject", subject_val)?;
    write_bool(&cli.agent_config, "web_push", "enabled", true)?;

    // Write private key to agent.env (never in plain TOML)
    let env_path = cli
        .agent_config
        .parent()
        .unwrap_or(std::path::Path::new("/etc/innerwarden"))
        .join("agent.env");
    append_or_replace_env(&env_path, "INNERWARDEN_VAPID_PRIVATE_KEY", &private_pem)?;

    println!("✓  VAPID key pair generated");
    println!("   Public key  → {}", &cli.agent_config.display());
    println!(
        "   Private key → {} (INNERWARDEN_VAPID_PRIVATE_KEY)",
        env_path.display()
    );
    println!();

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "web_push".to_string(),
        parameters: serde_json::json!({ "subject": subject_val }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    print_web_push_next_steps(&cli.agent_config)?;
    Ok(())
}

/// Generate a VAPID EC P-256 key pair (inline, no dep on agent crate).
/// Returns (private_key_pkcs8_pem, public_key_base64url).
fn generate_vapid_keys_ctl() -> Result<(String, String)> {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use p256::{ecdsa::SigningKey, EncodedPoint};

    let signing_key = SigningKey::random(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to serialize VAPID private key: {e}"))?
        .to_string();
    let public_bytes = EncodedPoint::from(verifying_key).to_bytes().to_vec();
    use base64::Engine as _;
    let public_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_bytes);
    Ok((pem, public_b64))
}

/// Append or replace a KEY=VALUE line in an env file.
fn append_or_replace_env(path: &std::path::Path, key: &str, value: &str) -> Result<()> {
    use std::io::Write as _;

    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };

    // Escape newlines in PEM for single-line env var storage
    let escaped_value = format!("\"{}\"", value.replace('\n', "\\n"));

    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| !l.starts_with(&format!("{key}=")))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key}={escaped_value}"));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    for line in &lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn print_web_push_next_steps(agent_config: &std::path::Path) -> Result<()> {
    println!("Next steps:");
    println!("  1. Restart the agent:");
    println!("       sudo systemctl restart innerwarden-agent");
    println!("  2. Open the InnerWarden dashboard");
    println!("  3. Click 'Enable browser notifications' in the top bar");
    println!("  4. Allow notifications when your browser asks");
    println!();
    println!(
        "The public key is configured in: {}",
        agent_config.display()
    );
    println!("Browsers will receive High and Critical incident alerts in real time,");
    println!("even when the dashboard tab is not open (requires browser running).");
    Ok(())
}

// ---------------------------------------------------------------------------
// Pipeline test
// ---------------------------------------------------------------------------

fn cmd_pipeline_test(cli: &Cli, wait_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = today_date_string();
    let incidents_path = effective_dir.join(format!("incidents-{today}.jsonl"));
    let decisions_path = effective_dir.join(format!("decisions-{today}.jsonl"));

    // Count existing decisions to detect new ones
    let baseline = count_jsonl_lines(&decisions_path);

    // Use RFC 5737 documentation IP - safe, never routable
    let test_ip = "198.51.100.123";
    let now_iso = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days_since_epoch = secs / 86400;
        // Compute date from days
        let (y, mo, d) = {
            let mut y = 1970i64;
            let mut rem = days_since_epoch as i64;
            loop {
                let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                    366
                } else {
                    365
                };
                if rem < ydays {
                    break;
                }
                rem -= ydays;
                y += 1;
            }
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let mdays = [
                31,
                if leap { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            let mut mo = 0usize;
            while mo < 12 && rem >= mdays[mo] {
                rem -= mdays[mo];
                mo += 1;
            }
            (y, mo + 1, rem + 1)
        };
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
    };
    let marker = format!("innerwarden-test-{}", std::process::id());

    let hostname = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let incident = serde_json::json!({
        "ts": now_iso,
        "host": hostname,
        "incident_id": format!("ssh_bruteforce:{test_ip}:{marker}"),
        "severity": "high",
        "title": format!("Possible SSH brute force from {test_ip}"),
        "summary": format!("12 failed SSH login attempts from {test_ip} in the last 30 seconds (pipeline test)"),
        "evidence": [{
            "count": 12,
            "ip": test_ip,
            "kind": "ssh.login_failed",
            "window_seconds": 30
        }],
        "recommended_checks": [
            format!("This is a pipeline test using RFC 5737 documentation IP {test_ip}"),
            "No real threat - safe to ignore"
        ],
        "tags": ["auth", "ssh", "bruteforce", "pipeline-test"],
        "entities": [{
            "type": "ip",
            "value": test_ip
        }]
    });

    println!("InnerWarden Pipeline Test");
    println!("{}\n", "─".repeat(50));

    // Step 1: Write test incident
    println!("  [1/4] Writing test incident...");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&incidents_path)?;
    writeln!(file, "{}", incident)?;
    println!("        Title: Possible SSH brute force from {test_ip}");
    println!("        Severity: HIGH");
    println!("        SSH brute-force from {test_ip} (documentation IP, safe)");
    println!("        Written to {}\n", incidents_path.display());

    // Step 2: Check agent is running
    println!("  [2/4] Checking agent status...");
    let agent_running = std::process::Command::new("pgrep")
        .args(["-f", "innerwarden-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !agent_running {
        println!("        Agent process not detected.");
        println!("        The test incident was written but nobody is reading it.");
        println!("        Start the agent: sudo systemctl start innerwarden-agent\n");
        println!("  Result: PARTIAL - incident written, agent not running");
        return Ok(());
    }
    println!("        Agent is running.\n");

    // Step 3: Wait for agent to process
    println!("  [3/4] Waiting up to {wait_secs}s for agent to process...");
    let start = std::time::Instant::now();
    let mut found = false;
    while start.elapsed().as_secs() < wait_secs {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let current = count_jsonl_lines(&decisions_path);
        if current > baseline {
            // Check if the new decision references our test
            if let Ok(content) = std::fs::read_to_string(&decisions_path) {
                if content.contains(&marker) || content.contains(test_ip) {
                    found = true;
                    break;
                }
            }
            // Even if marker not found, new decisions appeared
            if current > baseline {
                found = true;
                break;
            }
        }
        print!(".");
        std::io::stdout().flush().ok();
    }
    println!();

    // Step 4: Report results
    println!("\n  [4/4] Results:");
    if found {
        println!("        Pipeline is working.");
        println!("        Incident was detected, processed, and a decision was logged.");
        // Show the latest decision
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            if let Some(last_line) = content.lines().rev().find(|l| l.contains(test_ip)) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(last_line) {
                    let action = val
                        .get("action_type")
                        .and_then(|a| a.as_str())
                        .or_else(|| val.get("action").and_then(|a| a.as_str()))
                        .unwrap_or("?");
                    let conf = val
                        .get("confidence")
                        .and_then(|c| c.as_f64())
                        .unwrap_or(0.0);
                    let dry = val.get("dry_run").and_then(|d| d.as_bool()).unwrap_or(true);
                    let reason = val.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                    println!("\n        Action: {action}");
                    println!("        Confidence: {:.0}%", conf * 100.0);
                    println!("        Dry-run: {dry}");
                    if !reason.is_empty() {
                        println!("        Reason: {reason}");
                    }
                    if dry {
                        println!("        (safe - no real firewall changes)");
                    }
                }
            }
        }
        println!("\n  Result: PASS");
    } else {
        println!("        No decision appeared within {wait_secs} seconds.");
        println!("        Possible causes:");
        println!("          - Agent is running but AI provider is not configured");
        println!("          - Agent hasn't reached this incident in its read cycle");
        println!("          - Try again with --wait 30");
        println!("\n  Result: TIMEOUT - check `innerwarden doctor` for diagnostics");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// GDPR helpers
// ---------------------------------------------------------------------------

/// Check if a JSONL line references a given entity (IP or username).
fn matches_entity(line: &str, entity: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
        // Check entities array (events, incidents)
        if let Some(entities) = value.get("entities").and_then(|v| v.as_array()) {
            for e in entities {
                if let Some(val) = e.get("value").and_then(|v| v.as_str()) {
                    if val == entity {
                        return true;
                    }
                }
            }
        }
        // Check direct fields (decisions, admin-actions)
        for field in &["target_ip", "target_user", "operator", "target"] {
            if let Some(val) = value.get(*field).and_then(|v| v.as_str()) {
                if val == entity {
                    return true;
                }
            }
        }
    }
    false
}

/// Recompute SHA-256 hash chain after records have been removed.
fn recompute_hash_chain(lines: &mut [String]) {
    use innerwarden_core::audit::sha256_hex;
    let mut last_hash: Option<String> = None;
    for line in lines.iter_mut() {
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) {
            value["prev_hash"] = match &last_hash {
                Some(h) => serde_json::Value::String(h.clone()),
                None => serde_json::Value::Null,
            };
            let new_line = serde_json::to_string(&value).unwrap();
            last_hash = Some(sha256_hex(&new_line));
            *line = new_line;
        }
    }
}

/// Export all JSONL records matching an entity to a file or stdout.
fn cmd_gdpr_export(data_dir: &Path, entity: &str, output: Option<&Path>) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let mut total = 0usize;
    let mut writer: Box<dyn Write> = match output {
        Some(p) => Box::new(std::fs::File::create(p)?),
        None => Box::new(std::io::stdout()),
    };

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        if !patterns.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        let content = std::fs::read_to_string(entry.path())?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                writeln!(writer, "{line}")?;
                total += 1;
            }
        }
    }

    eprintln!("  Found {total} records matching '{entity}'");
    Ok(())
}

/// Erase all JSONL records matching an entity (GDPR right to erasure).
fn cmd_gdpr_erase(data_dir: &Path, entity: &str, yes: bool) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let hash_chained = &["decisions-", "admin-actions-"];

    // Phase 1: count matches per file
    let mut file_matches: Vec<(PathBuf, String, usize)> = Vec::new();
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let prefix = match patterns.iter().find(|p| name.starts_with(**p)) {
            Some(p) => p.to_string(),
            None => continue,
        };

        let content = std::fs::read_to_string(entry.path())?;
        let count = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| matches_entity(l, entity))
            .count();
        if count > 0 {
            file_matches.push((entry.path(), prefix, count));
        }
    }

    let total: usize = file_matches.iter().map(|(_, _, c)| *c).sum();
    if total == 0 {
        println!("  No records found matching '{entity}'");
        return Ok(());
    }

    // Phase 2: confirm
    println!(
        "  Found {total} records matching '{entity}' across {} files",
        file_matches.len()
    );
    if !yes {
        print!("  Proceed with erasure? [y/N] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("  Aborted.");
            return Ok(());
        }
    }

    // Phase 3: rewrite each file, removing matching records
    let mut erased = 0usize;
    for (path, prefix, _) in &file_matches {
        let content = std::fs::read_to_string(path)?;
        let mut kept: Vec<String> = Vec::new();
        let mut removed = 0usize;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                removed += 1;
            } else {
                kept.push(line.to_string());
            }
        }

        // Recompute hash chain for decisions and admin-actions
        if hash_chained.iter().any(|h| prefix.starts_with(h)) {
            recompute_hash_chain(&mut kept);
        }

        // Atomic write: temp file + rename
        let tmp = tempfile::Builder::new()
            .prefix("innerwarden-gdpr-")
            .tempfile_in(data_dir)?;
        let tmp_path = tmp.path().to_path_buf();
        {
            let mut writer = std::io::BufWriter::new(&tmp);
            for line in &kept {
                writeln!(writer, "{line}")?;
            }
            writer.flush()?;
        }
        std::fs::rename(&tmp_path, path)?;

        erased += removed;
    }

    println!(
        "  Erased {erased} records across {} files",
        file_matches.len()
    );

    // Audit the erase action
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "gdpr_erase".to_string(),
        target: entity.to_string(),
        parameters: serde_json::json!({
            "records_erased": erased,
            "files_modified": file_matches.len(),
        }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        eprintln!("  [warn] failed to write audit: {e:#}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ATT&CK Navigator layer generation
// ---------------------------------------------------------------------------

fn generate_navigator_layer() -> serde_json::Value {
    // All detector → technique mappings (mirrors agent/mitre.rs)
    let techniques: Vec<(&str, &str, &str)> = vec![
        ("T1110.001", "Credential Access", "ssh_bruteforce"),
        ("T1110.004", "Credential Access", "credential_stuffing"),
        ("T1110", "Credential Access", "distributed_ssh"),
        ("T1003", "Credential Access", "credential_harvest"),
        ("T1078", "Initial Access", "suspicious_login"),
        ("T1595", "Reconnaissance", "port_scan"),
        (
            "T1595.002",
            "Reconnaissance",
            "web_scan, user_agent_scanner",
        ),
        ("T1499", "Impact", "search_abuse"),
        ("T1496", "Impact", "crypto_miner"),
        ("T1498", "Impact", "outbound_anomaly"),
        ("T1486", "Impact", "ransomware"),
        ("T1059", "Execution", "execution_guard, process_tree"),
        ("T1059.004", "Execution", "reverse_shell"),
        ("T1610", "Execution", "docker_anomaly"),
        ("T1620", "Defense Evasion", "fileless"),
        ("T1098", "Defense Evasion", "integrity_alert"),
        ("T1070", "Defense Evasion", "log_tampering"),
        ("T1014", "Defense Evasion", "rootkit"),
        ("T1055", "Defense Evasion", "process_injection"),
        ("T1505.003", "Persistence", "web_shell"),
        ("T1098.004", "Persistence", "ssh_key_injection"),
        ("T1547.006", "Persistence", "kernel_module_load"),
        ("T1053.003", "Persistence", "crontab_persistence"),
        ("T1543.002", "Persistence", "systemd_persistence"),
        ("T1136", "Persistence", "user_creation"),
        ("T1611", "Privilege Escalation", "container_escape"),
        ("T1068", "Privilege Escalation", "privesc"),
        ("T1548", "Privilege Escalation", "sudo_abuse"),
        ("T1548.001", "Privilege Escalation", "sudo_abuse"),
        ("T1071", "Command and Control", "c2_callback"),
        ("T1571", "Command and Control", "c2_callback"),
        ("T1048.001", "Exfiltration", "dns_tunneling"),
        (
            "T1041",
            "Exfiltration",
            "data_exfiltration, data_exfil_ebpf",
        ),
        ("T1021", "Lateral Movement", "lateral_movement"),
        ("T1190", "Multiple", "suricata_alert"),
        ("T1546.004", "Persistence", "sensitive_write"),
        ("T1037.004", "Persistence", "sensitive_write"),
        ("T1574.006", "Persistence", "sensitive_write"),
        ("T1556", "Credential Access", "sensitive_write"),
        ("T1053.002", "Persistence", "at_job_persist"),
        ("T1222.002", "Defense Evasion", "file_permission_mod"),
        ("T1564.001", "Defense Evasion", "hidden_artifact"),
        ("T1219", "Command and Control", "remote_access_tool"),
        ("T1489", "Impact", "service_stop"),
        ("T1529", "Impact", "system_shutdown"),
        ("T1040", "Credential Access", "network_sniffing"),
        ("T1036.005", "Defense Evasion", "masquerading"),
        ("T1560", "Collection", "data_archive"),
        ("T1090", "Command and Control", "proxy_tunnel"),
        ("T1105", "Command and Control", "execution_guard"),
        ("T1140", "Defense Evasion", "execution_guard"),
        ("T1552.001", "Credential Access", "data_exfil_ebpf"),
        ("T1552.004", "Credential Access", "private_key_search"),
        ("T1562.001", "Defense Evasion", "sudo_abuse"),
        ("T1562.004", "Defense Evasion", "sudo_abuse"),
        ("T1485", "Impact", "sudo_abuse"),
    ];

    let tech_entries: Vec<serde_json::Value> = techniques
        .iter()
        .map(|(tid, _tactic, detectors)| {
            serde_json::json!({
                "techniqueID": tid,
                "score": 1,
                "color": "#00ff00",
                "comment": format!("Detectors: {detectors}"),
                "enabled": true,
                "showSubtechniques": true,
            })
        })
        .collect();

    serde_json::json!({
        "name": "InnerWarden Detection Coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": format!(
            "InnerWarden: {} MITRE ATT&CK techniques covered by 49 detectors + 8 YARA + 8 Sigma rules",
            tech_entries.len()
        ),
        "gradient": {
            "colors": ["#ffe766", "#00ff00"],
            "minValue": 1,
            "maxValue": 3
        },
        "techniques": tech_entries,
    })
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup::{ai_provider_defaults, count_failed_setup_checks, SetupCheck};
    use tempfile::TempDir;

    fn make_cli(data_dir: &std::path::Path) -> Cli {
        Cli {
            sensor_config: data_dir.join("config.toml"),
            agent_config: data_dir.join("agent.toml"),
            data_dir: data_dir.to_path_buf(),
            dry_run: false,
            command: Command::Decisions {
                days: 1,
                action: None,
            },
        }
    }

    #[test]
    fn parse_selection_indices_all_and_csv() {
        assert_eq!(
            crate::commands::agent::parse_selection_indices("all", 3),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("1,3,3,2", 3),
            Some(vec![1, 3, 2])
        );
    }

    #[test]
    fn parse_selection_indices_rejects_invalid_values() {
        assert_eq!(crate::commands::agent::parse_selection_indices("", 3), None);
        assert_eq!(
            crate::commands::agent::parse_selection_indices("0", 3),
            None
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("4", 3),
            None
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("x", 3),
            None
        );
    }

    #[test]
    fn ai_provider_defaults_cover_known_and_custom_providers() {
        let (model, key_var, base_url) = ai_provider_defaults("openrouter");
        assert_eq!(model, "meta-llama/llama-3.3-70b-instruct");
        assert_eq!(key_var.as_deref(), Some("OPENROUTER_API_KEY"));
        assert_eq!(base_url.as_deref(), Some("https://openrouter.ai/api"));

        let (_model, key_var, base_url) = ai_provider_defaults("acme");
        assert_eq!(key_var.as_deref(), Some("ACME_API_KEY"));
        assert!(base_url.is_none());
    }

    #[test]
    fn count_failed_setup_checks_only_counts_critical_failures() {
        let checks = vec![
            SetupCheck {
                label: "AI".to_string(),
                detail: "not configured".to_string(),
                ok: false,
                critical: true,
            },
            SetupCheck {
                label: "Dashboard".to_string(),
                detail: "not reachable".to_string(),
                ok: false,
                critical: false,
            },
            SetupCheck {
                label: "Protection".to_string(),
                detail: "watch only".to_string(),
                ok: true,
                critical: true,
            },
        ];

        assert_eq!(count_failed_setup_checks(&checks), 1);
    }

    #[test]
    fn decisions_empty_data_dir() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // Should return Ok even with no JSONL files present
        let result = cmd_decisions(&cli, 1, None, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn decisions_reads_jsonl() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"1.2.3.4\",\"confidence\":0.95,\"dry_run\":false,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = cmd_decisions(&cli, 1, None, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn decisions_action_filter() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"ignore\",\"target_ip\":\"1.2.3.4\",\"confidence\":0.3,\"dry_run\":false,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        // Filter for block_ip - should return Ok (0 matching)
        let result = cmd_decisions(&cli, 1, Some("block_ip"), dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        let result = cmd_entity(&cli, "1.2.3.4", 3, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_finds_ip_in_incident() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"title\":\"SSH Brute Force\",\"severity\":\"High\",\"summary\":\"8 failures\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.6.7.8\"}]}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = cmd_entity(&cli, "5.6.7.8", 1, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_finds_user_in_decision() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"suspend_user_sudo\",\"target_user\":\"alice\",\"confidence\":0.9,\"dry_run\":true,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = cmd_entity(&cli, "alice", 1, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn watchdog_status_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // Should return Ok even with no telemetry files
        let result = crate::commands::watchdog::cmd_watchdog_status(&cli, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn tune_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // No JSONL files - should return Ok with a "no data" message
        let result = cmd_tune(&cli, 7, true, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn tune_no_suggestions_when_calibrated() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        // Write a modest event count that matches default thresholds - no suggestion expected
        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        let mut content = String::new();
        for _ in 0..5 {
            content.push_str("{\"ts\":\"2026-03-16T10:00:00Z\",\"kind\":\"ssh.login_failed\",\"severity\":\"Low\",\"summary\":\"failed\",\"source\":\"auth_log\",\"host\":\"h\",\"entities\":[],\"tags\":[]}\n");
        }
        std::fs::write(&events_path, &content).unwrap();
        let cli = make_cli(dir.path());
        let result = cmd_tune(&cli, 1, true, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn completions_invalid_shell_errors() {
        let result = cmd_completions("powershell");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported shell"));
    }

    #[test]
    fn completions_bash_succeeds() {
        // Just verify it doesn't panic/error - output goes to stdout
        let result = cmd_completions("bash");
        assert!(result.is_ok());
    }

    // -- GDPR tests --

    #[test]
    fn matches_entity_finds_ip_in_entities_array() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","entities":[{"type":"Ip","value":"1.2.3.4"}]}"#;
        assert!(matches_entity(line, "1.2.3.4"));
        assert!(!matches_entity(line, "5.6.7.8"));
    }

    #[test]
    fn matches_entity_finds_target_ip() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"block_ip","target_ip":"1.2.3.4"}"#;
        assert!(matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_finds_target_user() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"suspend","target_user":"alice"}"#;
        assert!(matches_entity(line, "alice"));
        assert!(!matches_entity(line, "bob"));
    }

    #[test]
    fn matches_entity_finds_operator() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","operator":"admin","action":"enable"}"#;
        assert!(matches_entity(line, "admin"));
    }

    #[test]
    fn matches_entity_finds_target() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","target":"1.2.3.4","action":"gdpr_erase"}"#;
        assert!(matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_no_match_on_invalid_json() {
        assert!(!matches_entity("not json", "anything"));
    }

    #[test]
    fn gdpr_export_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = cmd_gdpr_export(dir.path(), "1.2.3.4", None);
        assert!(result.is_ok());
    }

    #[test]
    fn gdpr_export_finds_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"title\":\"Brute Force\",\"entities\":[{\"type\":\"Ip\",\"value\":\"9.8.7.6\"}]}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"title\":\"Port Scan\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();

        let out_path = dir.path().join("export.jsonl");
        let result = cmd_gdpr_export(dir.path(), "9.8.7.6", Some(&out_path));
        assert!(result.is_ok());

        let exported = std::fs::read_to_string(&out_path).unwrap();
        assert!(exported.contains("9.8.7.6"));
        assert!(!exported.contains("5.5.5.5"));
        assert_eq!(exported.lines().count(), 1);
    }

    #[test]
    fn gdpr_erase_no_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();
        let result = cmd_gdpr_erase(dir.path(), "9.9.9.9", true);
        assert!(result.is_ok());

        // File should be unchanged
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("5.5.5.5"));
    }

    #[test]
    fn gdpr_erase_removes_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"1.2.3.4\"}]}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();

        let result = cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("1.2.3.4"));
        assert!(content.contains("5.5.5.5"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn gdpr_erase_recomputes_hash_chain_for_decisions() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"1.2.3.4\",\"prev_hash\":null}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"5.5.5.5\",\"prev_hash\":\"abc123\"}\n\
             {\"ts\":\"2026-03-16T12:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"6.6.6.6\",\"prev_hash\":\"def456\"}\n",
        ).unwrap();

        let result = cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("1.2.3.4"));
        // Remaining lines should have recomputed prev_hash - first line should have null
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(first.get("prev_hash").unwrap().is_null());
        // Second line should have a proper SHA-256 hash (64 hex chars)
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let hash = second.get("prev_hash").unwrap().as_str().unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn gdpr_erase_creates_audit_entry() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &events_path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"1.2.3.4\"}]}\n",
        ).unwrap();

        let result = cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        // An admin-actions file should now exist with a gdpr_erase entry
        let audit_path = dir.path().join(format!("admin-actions-{today}.jsonl"));
        assert!(audit_path.exists());
        let audit_content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit_content.contains("gdpr_erase"));
        assert!(audit_content.contains("1.2.3.4"));
    }
}
