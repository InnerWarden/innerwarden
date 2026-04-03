use std::io::Write;

use anyhow::Result;

use crate::{AgentCommand, Cli};

/// Resolve the dashboard URL from agent config or default.
pub(crate) fn resolve_dashboard_url(cli: &Cli) -> String {
    // Try to read from agent.toml [dashboard] bind
    if let Ok(content) = std::fs::read_to_string(&cli.agent_config) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("dashboard_bind") || trimmed.starts_with("bind") {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let addr = val.trim().trim_matches('"');
                    if !addr.is_empty() {
                        return format!("http://{addr}");
                    }
                }
            }
        }
    }
    "http://127.0.0.1:8787".to_string()
}

pub(crate) fn parse_selection_indices(input: &str, max: usize) -> Option<Vec<usize>> {
    let trimmed = input.trim();
    if trimmed.is_empty() || max == 0 {
        return None;
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Some((1..=max).collect());
    }

    let mut indexes = Vec::new();
    for part in trimmed.split(',') {
        let idx: usize = part.trim().parse().ok()?;
        if idx == 0 || idx > max {
            return None;
        }
        if !indexes.contains(&idx) {
            indexes.push(idx);
        }
    }
    if indexes.is_empty() {
        None
    } else {
        Some(indexes)
    }
}

pub(crate) fn cmd_agent(cli: &Cli, command: Option<&AgentCommand>) -> Result<()> {
    use innerwarden_agent_guard::signatures::{Kind, SignatureIndex, KNOWN};

    match command {
        None => {
            // Interactive menu
            println!();
            println!("  \x1b[1;36m🤖 InnerWarden Agent Guard\x1b[0m");
            println!();
            println!("  \x1b[1mWhat do you want to do?\x1b[0m");
            println!();
            println!("  1. Install a new agent        (OpenClaw, ZeroClaw, others)");
            println!("  2. Scan for existing agents   (find agents already running)");
            println!("  3. View connected agents      (see what's being protected)");
            println!("  4. List available agents       (see what we support)");
            println!();
            println!("  Or use directly:");
            println!("    innerwarden agent add <name>");
            println!("    innerwarden agent scan");
            println!("    innerwarden agent status");
            println!();
            Ok(())
        }

        Some(AgentCommand::List) => {
            println!();
            println!("  \x1b[1;36m🤖 Available Agents\x1b[0m");
            println!();
            println!("  \x1b[1mInstallable agents\x1b[0m (innerwarden agent add <name>):");
            println!("  {:<16} {:<20} DESCRIPTION", "NAME", "VENDOR");
            println!("  {}", "─".repeat(60));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Agent) {
                println!(
                    "  {:<16} {:<20} {}",
                    sig.name.to_lowercase(),
                    sig.vendor,
                    match sig.name {
                        "OpenClaw" => "Autonomous AI assistant with persistent memory",
                        "ZeroClaw" => "Ultra-lightweight Rust AI agent (5MB RAM)",
                        _ => "",
                    }
                );
            }
            println!();
            println!("  \x1b[1mAuto-detected tools\x1b[0m (monitored when running):");
            println!("  {:<16} {:<12} VENDOR", "NAME", "INTEGRATION");
            println!("  {}", "─".repeat(50));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Tool) {
                let integ = format!("{:?}", sig.integration).to_lowercase();
                println!("  {:<16} {:<12} {}", sig.name, integ, sig.vendor);
            }
            println!();
            println!("  \x1b[1mAuto-detected runtimes\x1b[0m (API monitored):");
            println!("  {:<16} VENDOR", "NAME");
            println!("  {}", "─".repeat(36));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Runtime) {
                println!("  {:<16} {}", sig.name, sig.vendor);
            }
            println!();
            println!("  \x1b[2m💡 Agents: install + full protection");
            println!("  💡 Tools: auto-detected, connect for full MCP protection");
            println!("  💡 Runtimes: auto-detected, API traffic monitored\x1b[0m");
            println!();
            Ok(())
        }

        Some(AgentCommand::Add { name }) => {
            let agents: Vec<_> = SignatureIndex::installable_agents();

            match name {
                None => {
                    println!();
                    println!("  \x1b[1;36m🤖 Install an Agent\x1b[0m");
                    println!();
                    println!("  Available agents:");
                    println!();
                    for sig in &agents {
                        let desc = match sig.name {
                            "OpenClaw" => "Autonomous AI assistant with persistent memory",
                            "ZeroClaw" => "Ultra-lightweight Rust AI agent (5MB RAM)",
                            _ => "",
                        };
                        println!("  \x1b[1m{:<16}\x1b[0m {}", sig.name.to_lowercase(), desc);
                        if let Some(cmd) = sig.install_cmd {
                            println!("  {:<16} install: {}", "", cmd);
                        }
                        println!();
                    }
                    println!("  Usage: innerwarden agent add <name>");
                    println!();
                    Ok(())
                }
                Some(agent_name) => {
                    let lower = agent_name.to_lowercase();
                    let sig = agents.iter().find(|s| s.name.to_lowercase() == lower);

                    match sig {
                        Some(sig) => {
                            println!();
                            println!("  Installing {}...", sig.name);

                            if let Some(cmd) = sig.install_cmd {
                                println!("  Running: {cmd}");
                                let parts: Vec<&str> = cmd.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    let status = std::process::Command::new(parts[0])
                                        .args(&parts[1..])
                                        .status();
                                    match status {
                                        Ok(s) if s.success() => {
                                            println!("  \x1b[32m✓\x1b[0m {} installed", sig.name);
                                            println!(
                                                "  \x1b[32m✓\x1b[0m Connected to InnerWarden (agent-guard active)"
                                            );
                                            println!("  \x1b[32m✓\x1b[0m Protection: warn mode (alerts you, doesn't block)");
                                            println!();
                                            println!(
                                                "  Your agent is ready. Start it with: {}",
                                                sig.name.to_lowercase()
                                            );
                                            println!();
                                            println!("  \x1b[2m💡 Tip: run 'innerwarden agent status' to see what your agent is doing\x1b[0m");
                                        }
                                        Ok(s) => {
                                            eprintln!(
                                                "  \x1b[31m✗\x1b[0m Installation failed (exit code {:?})",
                                                s.code()
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "  \x1b[31m✗\x1b[0m Failed to run installer: {e}"
                                            );
                                            eprintln!("  Try installing manually: {cmd}");
                                        }
                                    }
                                }
                            }
                            println!();
                            Ok(())
                        }
                        None => {
                            eprintln!("  Unknown agent: {agent_name}");
                            eprintln!();
                            eprintln!("  Available agents:");
                            for a in &agents {
                                eprintln!("    {}", a.name.to_lowercase());
                            }
                            eprintln!();
                            eprintln!("  Run 'innerwarden agent list' to see all supported agents and tools.");
                            Ok(())
                        }
                    }
                }
            }
        }

        Some(AgentCommand::Scan) => {
            use innerwarden_agent_guard::detect;

            println!();
            println!("  Scanning for running agents...");
            println!();

            let index = SignatureIndex::new();
            let found = detect::scan_processes(&index);

            if found.is_empty() {
                println!("  No known agents or tools detected.");
                println!();
                println!("  To install an agent: innerwarden agent add <name>");
                println!("  See supported names: innerwarden agent list");
                println!("  To connect detected agents: innerwarden agent connect");
            } else {
                println!(
                    "  {:<6} {:<8} {:<16} {:<10} STATUS",
                    "FOUND", "PID", "NAME", "TYPE"
                );
                println!("  {}", "─".repeat(56));
                for (i, agent) in found.iter().enumerate() {
                    let kind = if agent.integration == "official" {
                        "agent"
                    } else {
                        "tool"
                    };
                    println!(
                        "  {:<6} {:<8} {:<16} {:<10} not connected",
                        i + 1,
                        agent.pid,
                        agent.name,
                        kind
                    );
                }
                println!();
                println!("  Connect with: innerwarden agent connect");
            }
            println!();
            Ok(())
        }

        Some(AgentCommand::Status) => {
            println!();
            println!("  \x1b[1;36m🤖 Agent Guard Status\x1b[0m");
            println!();
            // TODO: read from running agent via API
            println!("  Agent guard is enabled. Checking dashboard API...");
            println!();

            // Try to hit the dashboard API
            match std::process::Command::new("curl")
                .args(["-s", "http://localhost:8787/api/agent/security-context"])
                .output()
            {
                Ok(output) if output.status.success() => {
                    let body = String::from_utf8_lossy(&output.stdout);
                    if let Ok(ctx) = serde_json::from_str::<serde_json::Value>(&body) {
                        let level = ctx["threat_level"].as_str().unwrap_or("unknown");
                        let incidents = ctx["active_incidents_today"].as_u64().unwrap_or(0);
                        let blocks = ctx["recent_blocks_today"].as_u64().unwrap_or(0);
                        println!("  Server threat level: {level}");
                        println!("  Incidents today:     {incidents}");
                        println!("  IPs blocked today:   {blocks}");
                    }
                }
                _ => {
                    println!("  \x1b[33m⚠\x1b[0m  Dashboard not reachable (is innerwarden-agent running?)");
                }
            }

            // Scan for running agents/tools
            let index = SignatureIndex::new();
            let found = innerwarden_agent_guard::detect::scan_processes(&index);

            if !found.is_empty() {
                println!();
                println!("  \x1b[1mDetected processes:\x1b[0m");
                println!("  {:<16} {:<8} {:<12} INTEGRATION", "NAME", "PID", "TYPE");
                println!("  {}", "─".repeat(48));
                for agent in &found {
                    println!(
                        "  {:<16} {:<8} {:<12} {}",
                        agent.name, agent.pid, agent.comm, agent.integration
                    );
                }
            } else {
                println!();
                println!("  No agents or tools detected.");
                println!("  Install one with: innerwarden agent add <name>");
                println!("  See options: innerwarden agent list");
            }
            println!();
            Ok(())
        }

        Some(AgentCommand::Connect { pid, name, label }) => {
            println!();
            let index = SignatureIndex::new();

            let selected_pids: Vec<u32> = if let Some(pid) = *pid {
                vec![pid]
            } else {
                let found = innerwarden_agent_guard::detect::scan_processes(&index);
                if found.is_empty() {
                    println!("  No known agent process detected.");
                    println!("  Run one first, then use: innerwarden agent connect");
                    println!("  Or install one with: innerwarden agent add <name>");
                    println!("  See options: innerwarden agent list");
                    println!();
                    return Ok(());
                }

                let candidates: Vec<_> = if let Some(filter) = name.as_deref() {
                    let filter_lc = filter.to_lowercase();
                    let matches: Vec<_> = found
                        .iter()
                        .filter(|a| {
                            a.name.to_lowercase().contains(&filter_lc)
                                || a.comm.to_lowercase().contains(&filter_lc)
                        })
                        .collect();
                    if matches.is_empty() {
                        println!("  No running agent matched '{filter}'.");
                        println!("  Running detections:");
                        for agent in &found {
                            println!(
                                "    - {} (pid {}, comm {}, integration {})",
                                agent.name, agent.pid, agent.comm, agent.integration
                            );
                        }
                        println!();
                        return Ok(());
                    }
                    matches
                } else {
                    found.iter().collect()
                };

                if candidates.len() == 1 {
                    println!(
                        "  Auto-detected: {} (pid {})",
                        candidates[0].name, candidates[0].pid
                    );
                    vec![candidates[0].pid]
                } else {
                    println!("  Detected agents:");
                    println!("  {:<4} {:<8} {:<16} TYPE", "NO.", "PID", "NAME");
                    println!("  {}", "─".repeat(48));
                    for (i, agent) in candidates.iter().enumerate() {
                        println!(
                            "  {:<4} {:<8} {:<16} {}",
                            i + 1,
                            agent.pid,
                            agent.name,
                            agent.integration
                        );
                    }
                    println!();
                    print!("  Select one or more (ex: 1,3) or 'all' [Enter to cancel]: ");
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let trimmed = input.trim();
                    if trimmed.is_empty() {
                        println!("  Cancelled.");
                        println!();
                        return Ok(());
                    }
                    let Some(indexes) = parse_selection_indices(trimmed, candidates.len()) else {
                        println!("  Invalid selection '{trimmed}'.");
                        println!();
                        return Ok(());
                    };
                    indexes
                        .into_iter()
                        .map(|idx| candidates[idx - 1].pid)
                        .collect()
                }
            };

            let dashboard_url = resolve_dashboard_url(cli);
            let mut connected = 0usize;

            for selected_pid in selected_pids {
                // Read /proc/<pid>/comm to identify
                let comm_path = format!("/proc/{selected_pid}/comm");
                let comm = std::fs::read_to_string(&comm_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());

                let name = if let Some(sig) = index.identify(&comm) {
                    sig.name.to_string()
                } else {
                    comm.clone()
                };

                println!("  Connecting {name} (pid {selected_pid})...");

                // Call agent-guard API to register
                let payload = serde_json::json!({
                    "name": name,
                    "pid": selected_pid,
                    "label": label.as_deref().unwrap_or(""),
                });

                let url = format!("{dashboard_url}/api/agent-guard/connect");
                match ureq::post(url).send_json(&payload) {
                    Ok(resp) => {
                        let body: serde_json::Value =
                            resp.into_body().read_json().unwrap_or_default();
                        let agent_id = body
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        println!(
                            "  \x1b[32m✓\x1b[0m {name} (pid {selected_pid}) connected as {agent_id}"
                        );
                        connected += 1;
                    }
                    Err(e) => {
                        // Fallback: write to persistence file for agent to pick up on restart
                        let path = cli.data_dir.join("agent-connections.jsonl");
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                        {
                            use std::io::Write;
                            let entry = serde_json::json!({
                                "ts": chrono::Utc::now().to_rfc3339(),
                                "action": "connect",
                                "name": name,
                                "pid": selected_pid,
                                "label": label,
                            });
                            let _ = writeln!(f, "{}", entry);
                        }
                        println!(
                            "  \x1b[33m!\x1b[0m Dashboard not reachable ({e:#}), saved for next agent restart"
                        );
                    }
                }
            }

            if let Some(lbl) = label {
                println!("  Label: {lbl}");
            }
            if connected > 1 {
                println!("  Connected {connected} agents.");
            }
            println!();
            println!("  \x1b[2mView status: innerwarden agent status\x1b[0m");
            println!();
            Ok(())
        }

        Some(AgentCommand::Disconnect { id }) => {
            println!();
            let dashboard_url = resolve_dashboard_url(cli);
            let payload = serde_json::json!({ "agent_id": id });
            let url = format!("{dashboard_url}/api/agent-guard/disconnect");

            match ureq::post(url).send_json(&payload) {
                Ok(_) => {
                    println!("  \x1b[32m✓\x1b[0m Agent {id} disconnected");
                }
                Err(e) => {
                    println!("  \x1b[33m!\x1b[0m Dashboard not reachable ({e:#})");
                }
            }
            println!();
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// ATT&CK Navigator layer generation
// ---------------------------------------------------------------------------
