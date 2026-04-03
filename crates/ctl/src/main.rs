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
        Command::Daily { ref command } => {
            commands::core::cmd_daily(&cli, &registry, command.as_ref())
        }
        Command::Harden { verbose } => harden::cmd_harden(verbose),
        Command::Doctor => commands::ops::cmd_doctor(&cli, &registry),
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
        Command::Navigator { ref output } => commands::status::cmd_navigator(output.as_deref()),
        Command::Scan { ref modules_dir } => scan::cmd_scan(modules_dir),
        Command::Upgrade {
            check,
            yes,
            notify,
            ref install_dir,
        } => commands::update::cmd_upgrade(&cli, check, yes, notify, install_dir),
        Command::List => commands::core::cmd_list(&cli, &registry),
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
                    commands::history::cmd_entity(&cli, t, days, &cli.data_dir.clone())
                }
            }
        },
        Command::Enable {
            ref capability,
            ref params,
            yes,
        } => {
            let params = commands::capability::parse_params(params)?;
            commands::capability::cmd_enable(&cli, &registry, capability, params, yes)
        }
        Command::Disable {
            ref capability,
            yes,
        } => commands::capability::cmd_disable(&cli, &registry, capability, yes),
        Command::Configure { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
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
            Some(ConfigureCommand::TwoFa) => commands::ops::cmd_configure_2fa(&cli),
        },
        Command::Notify { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
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
                commands::notify::cmd_notify_web_push_setup(&cli, subject.as_deref())
            }
        },
        Command::Integrate { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
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
                commands::history::cmd_incidents_live(&cli, severity, &cli.data_dir.clone())
            } else {
                commands::history::cmd_incidents(&cli, days, severity, &cli.data_dir.clone())
            }
        }
        Command::Block { ref ip, ref reason } => {
            commands::response::cmd_block(&cli, ip, reason, &cli.data_dir.clone())
        }
        Command::Unblock { ref ip, ref reason } => {
            commands::response::cmd_unblock(&cli, ip, reason, &cli.data_dir.clone())
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
        Command::Tune { days, yes } => {
            commands::ops::cmd_tune(&cli, days, yes, &cli.data_dir.clone())
        }
        Command::SensorStatus => commands::status::cmd_sensor_status(&cli, &cli.data_dir.clone()),
        Command::Export {
            ref kind,
            ref from,
            ref to,
            ref format,
            ref output,
        } => commands::history::cmd_export(
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
        } => commands::history::cmd_tail(&cli, r#type, interval, &cli.data_dir.clone()),
        Command::Decisions { days, ref action } => {
            commands::history::cmd_decisions(&cli, days, action.as_deref(), &cli.data_dir.clone())
        }
        Command::Entity { ref target, days } => {
            commands::history::cmd_entity(&cli, target, days, &cli.data_dir.clone())
        }
        Command::Completions { ref shell } => commands::ops::cmd_completions(shell),
        Command::Allowlist { ref command } => match command {
            AllowlistCommand::Add { ref ip, ref user } => {
                commands::response::cmd_allowlist_add(&cli, ip.as_deref(), user.as_deref())
            }
            AllowlistCommand::Remove { ref ip, ref user } => {
                commands::response::cmd_allowlist_remove(&cli, ip.as_deref(), user.as_deref())
            }
            AllowlistCommand::List => commands::response::cmd_allowlist_list(&cli),
        },
        Command::Suppress { ref command } => match command {
            SuppressCommand::Add { ref pattern } => {
                commands::response::cmd_suppress_add(&cli, pattern)
            }
            SuppressCommand::Remove { ref pattern } => {
                commands::response::cmd_suppress_remove(&cli, pattern)
            }
            SuppressCommand::List => commands::response::cmd_suppress_list(&cli),
        },
        Command::PipelineTest { wait } => {
            commands::ops::cmd_pipeline_test(&cli, wait, &cli.data_dir.clone())
        }
        Command::Backup { ref output } => commands::ops::cmd_backup(&cli, output.as_deref()),
        Command::Metrics => commands::status::cmd_metrics(&cli, &cli.data_dir.clone()),
        Command::Gdpr { ref action } => match action {
            GdprCommand::Export {
                ref entity,
                ref output,
            } => commands::history::cmd_gdpr_export(&cli.data_dir, entity, output.as_deref()),
            GdprCommand::Erase { ref entity, yes } => {
                commands::history::cmd_gdpr_erase(&cli.data_dir, entity, *yes)
            }
        },
        Command::Agent { ref command } => commands::agent::cmd_agent(&cli, command.as_ref()),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Configure AI
// ---------------------------------------------------------------------------

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
// innerwarden test-alert
// ---------------------------------------------------------------------------

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

pub(crate) fn unknown_cap_error(id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unknown capability '{}' - run 'innerwarden list' to see available capabilities",
        id
    )
}

// ---------------------------------------------------------------------------
// innerwarden allowlist
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// innerwarden notify web-push setup
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
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
        let result = crate::commands::history::cmd_decisions(&cli, 1, None, dir.path());
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
        let result = crate::commands::history::cmd_decisions(&cli, 1, None, dir.path());
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
        let result = crate::commands::history::cmd_decisions(&cli, 1, Some("block_ip"), dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::history::cmd_entity(&cli, "1.2.3.4", 3, dir.path());
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
        let result = crate::commands::history::cmd_entity(&cli, "5.6.7.8", 1, dir.path());
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
        let result = crate::commands::history::cmd_entity(&cli, "alice", 1, dir.path());
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
        let result = crate::commands::ops::cmd_tune(&cli, 7, true, dir.path());
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
        let result = crate::commands::ops::cmd_tune(&cli, 1, true, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn completions_invalid_shell_errors() {
        let result = crate::commands::ops::cmd_completions("powershell");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported shell"));
    }

    #[test]
    fn completions_bash_succeeds() {
        // Just verify it doesn't panic/error - output goes to stdout
        let result = crate::commands::ops::cmd_completions("bash");
        assert!(result.is_ok());
    }

    // -- GDPR tests --

    #[test]
    fn matches_entity_finds_ip_in_entities_array() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","entities":[{"type":"Ip","value":"1.2.3.4"}]}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
        assert!(!crate::commands::history::matches_entity(line, "5.6.7.8"));
    }

    #[test]
    fn matches_entity_finds_target_ip() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"block_ip","target_ip":"1.2.3.4"}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_finds_target_user() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"suspend","target_user":"alice"}"#;
        assert!(crate::commands::history::matches_entity(line, "alice"));
        assert!(!crate::commands::history::matches_entity(line, "bob"));
    }

    #[test]
    fn matches_entity_finds_operator() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","operator":"admin","action":"enable"}"#;
        assert!(crate::commands::history::matches_entity(line, "admin"));
    }

    #[test]
    fn matches_entity_finds_target() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","target":"1.2.3.4","action":"gdpr_erase"}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_no_match_on_invalid_json() {
        assert!(!crate::commands::history::matches_entity(
            "not json", "anything"
        ));
    }

    #[test]
    fn gdpr_export_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = crate::commands::history::cmd_gdpr_export(dir.path(), "1.2.3.4", None);
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
        let result =
            crate::commands::history::cmd_gdpr_export(dir.path(), "9.8.7.6", Some(&out_path));
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
        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "9.9.9.9", true);
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

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
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

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
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

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        // An admin-actions file should now exist with a gdpr_erase entry
        let audit_path = dir.path().join(format!("admin-actions-{today}.jsonl"));
        assert!(audit_path.exists());
        let audit_content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit_content.contains("gdpr_erase"));
        assert!(audit_content.contains("1.2.3.4"));
    }
}
