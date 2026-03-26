use std::future::Future;
use std::net::Ipv4Addr;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Path where the XDP blocklist map is pinned.
const BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";

pub struct KillChainResponse;

#[derive(Debug, Serialize, Deserialize)]
struct KillChainForensics {
    ts: DateTime<Utc>,
    incident_id: String,
    pattern: String,
    c2_ip: String,
    pid: u64,
    process_tree_killed: bool,
    c2_blocked_xdp: bool,
    network_snapshot: String,
    proc_snapshot: String,
    actions_taken: Vec<String>,
}

impl ResponseSkill for KillChainResponse {
    fn id(&self) -> &'static str {
        "kill-chain-response"
    }

    fn name(&self) -> &'static str {
        "Kill Chain Response"
    }

    fn description(&self) -> &'static str {
        "Atomic response to kernel-blocked kill chain: kills process tree, \
         blocks C2 IP via XDP, captures forensics."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["kill_chain"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            // Extract C2 IP and PID from incident evidence
            let evidence = ctx.incident.evidence.get(0);

            let c2_ip = evidence
                .and_then(|ev| ev.get("c2_ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let pid = evidence
                .and_then(|ev| ev.get("pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let pattern = evidence
                .and_then(|ev| ev.get("pattern"))
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");

            if c2_ip.is_empty() && pid == 0 {
                return SkillResult {
                    success: false,
                    message: "kill-chain-response: no C2 IP or PID found in incident evidence"
                        .to_string(),
                };
            }

            let mut actions: Vec<String> = Vec::new();

            if dry_run {
                if pid > 0 {
                    info!(pid, "DRY RUN: would kill process tree (PID {pid})");
                    actions.push(format!("would kill process tree PID {pid}"));
                }
                if !c2_ip.is_empty() {
                    info!(c2_ip, "DRY RUN: would block C2 IP {c2_ip} via XDP");
                    actions.push(format!("would block C2 IP {c2_ip} via XDP"));
                }
                actions.push("would capture network + process forensics".to_string());
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: kill-chain-response for pattern {pattern}: {}",
                        actions.join("; ")
                    ),
                };
            }

            let mut process_tree_killed = false;
            let mut c2_blocked_xdp = false;

            // Step 1: Kill the process tree
            if pid > 0 {
                let pid_str = pid.to_string();

                // Kill children first
                let child_kill = Command::new("pkill")
                    .args(["-9", "-P", &pid_str])
                    .output()
                    .await;
                match &child_kill {
                    Ok(out) if out.status.success() || out.status.code() == Some(1) => {
                        info!(pid, "killed child processes of PID {pid}");
                        actions.push(format!("killed child processes of PID {pid}"));
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        warn!(pid, stderr = %stderr, "pkill children returned unexpected exit code");
                        actions.push(format!("pkill -P {pid} failed: {stderr}"));
                    }
                    Err(e) => {
                        warn!(pid, error = %e, "failed to spawn pkill for children");
                        actions.push(format!("failed to pkill children of PID {pid}: {e}"));
                    }
                }

                // Kill the process itself
                let kill = Command::new("kill")
                    .args(["-9", &pid_str])
                    .output()
                    .await;
                match &kill {
                    Ok(out) if out.status.success() => {
                        info!(pid, "killed process PID {pid}");
                        actions.push(format!("killed PID {pid}"));
                        process_tree_killed = true;
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        // Process may already be dead (kernel blocked it)
                        warn!(pid, stderr = %stderr, "kill -9 returned error (process may already be dead)");
                        actions.push(format!("kill -9 {pid}: {stderr} (may already be dead)"));
                        process_tree_killed = true; // count as success if kernel already killed it
                    }
                    Err(e) => {
                        warn!(pid, error = %e, "failed to spawn kill command");
                        actions.push(format!("failed to kill PID {pid}: {e}"));
                    }
                }
            }

            // Step 2: Block C2 IP via XDP if available
            if !c2_ip.is_empty() {
                // Strip port if present (e.g. "185.234.1.1:4444" -> "185.234.1.1")
                let ip_only = c2_ip.split(':').next().unwrap_or(c2_ip);

                let addr: Option<Ipv4Addr> = ip_only.parse().ok();
                if let Some(addr) = addr {
                    if Path::new(BLOCKLIST_PIN).exists() {
                        let ip_bytes = addr.octets();
                        let output = Command::new("sudo")
                            .args([
                                "bpftool",
                                "map",
                                "update",
                                "pinned",
                                BLOCKLIST_PIN,
                                "key",
                                &ip_bytes[0].to_string(),
                                &ip_bytes[1].to_string(),
                                &ip_bytes[2].to_string(),
                                &ip_bytes[3].to_string(),
                                "value",
                                "1",
                                "0",
                                "0",
                                "0",
                                "any",
                            ])
                            .output()
                            .await;

                        match output {
                            Ok(out) if out.status.success() => {
                                info!(c2_ip = ip_only, "blocked C2 IP via XDP (wire-speed drop)");
                                actions.push(format!("blocked C2 {ip_only} via XDP"));
                                c2_blocked_xdp = true;
                            }
                            Ok(out) => {
                                let stderr = String::from_utf8_lossy(&out.stderr);
                                warn!(c2_ip = ip_only, stderr = %stderr, "XDP block failed for C2 IP");
                                actions.push(format!("XDP block failed for {ip_only}: {stderr}"));
                            }
                            Err(e) => {
                                warn!(c2_ip = ip_only, error = %e, "failed to spawn bpftool for C2 block");
                                actions.push(format!("bpftool failed for {ip_only}: {e}"));
                            }
                        }
                    } else {
                        warn!(c2_ip = ip_only, "XDP blocklist not available, skipping C2 block");
                        actions.push(format!(
                            "XDP not available for C2 {ip_only} (map not found at {BLOCKLIST_PIN})"
                        ));
                    }
                } else {
                    warn!(c2_ip, "invalid C2 IP address, skipping XDP block");
                    actions.push(format!("invalid C2 IP: {c2_ip}"));
                }
            }

            // Step 3: Capture forensics
            let network_snapshot = capture_network_snapshot().await;
            actions.push("captured network snapshot (ss -tunp)".to_string());

            let proc_snapshot = if pid > 0 {
                capture_proc_snapshot(pid).await
            } else {
                "no PID to snapshot".to_string()
            };
            if pid > 0 {
                actions.push(format!("captured /proc/{pid}/ snapshot"));
            }

            // Write forensics metadata
            let forensics = KillChainForensics {
                ts: Utc::now(),
                incident_id: ctx.incident.incident_id.clone(),
                pattern: pattern.to_string(),
                c2_ip: c2_ip.to_string(),
                pid,
                process_tree_killed,
                c2_blocked_xdp,
                network_snapshot,
                proc_snapshot,
                actions_taken: actions.clone(),
            };

            if let Err(e) = write_forensics(&ctx.data_dir, &forensics) {
                warn!(error = %e, "failed to write kill-chain forensics metadata");
            }

            info!(
                pattern,
                c2_ip,
                pid,
                process_tree_killed,
                c2_blocked_xdp,
                actions_count = actions.len(),
                "kill-chain-response completed"
            );

            SkillResult {
                success: true,
                message: format!(
                    "Kill chain response ({pattern}): {}",
                    actions.join("; ")
                ),
            }
        })
    }
}

async fn capture_network_snapshot() -> String {
    match Command::new("ss")
        .args(["-tunp"])
        .output()
        .await
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Truncate to avoid huge forensics files
            if stdout.len() > 8192 {
                format!("{}... [truncated]", &stdout[..8192])
            } else {
                stdout.to_string()
            }
        }
        Err(e) => format!("failed to run ss: {e}"),
    }
}

async fn capture_proc_snapshot(pid: u64) -> String {
    let proc_dir = format!("/proc/{pid}");
    if !Path::new(&proc_dir).exists() {
        return format!("/proc/{pid} no longer exists (process already terminated)");
    }

    let mut snapshot = String::new();

    // Capture cmdline
    if let Ok(cmdline) = tokio::fs::read_to_string(format!("{proc_dir}/cmdline")).await {
        let cmdline = cmdline.replace('\0', " ");
        snapshot.push_str(&format!("cmdline: {cmdline}\n"));
    }

    // Capture status
    if let Ok(status) = tokio::fs::read_to_string(format!("{proc_dir}/status")).await {
        // Only keep first 20 lines of status
        let status_lines: String = status.lines().take(20).collect::<Vec<_>>().join("\n");
        snapshot.push_str(&format!("status:\n{status_lines}\n"));
    }

    // Capture cwd (symlink target)
    if let Ok(cwd) = tokio::fs::read_link(format!("{proc_dir}/cwd")).await {
        snapshot.push_str(&format!("cwd: {}\n", cwd.display()));
    }

    // Capture exe (symlink target)
    if let Ok(exe) = tokio::fs::read_link(format!("{proc_dir}/exe")).await {
        snapshot.push_str(&format!("exe: {}\n", exe.display()));
    }

    if snapshot.is_empty() {
        format!("/proc/{pid} exists but could not read details")
    } else {
        snapshot
    }
}

fn write_forensics(data_dir: &Path, forensics: &KillChainForensics) -> Result<()> {
    let dir = data_dir.join("kill-chain-forensics");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create forensics dir {}", dir.display()))?;

    let filename = format!(
        "{}_{}.json",
        forensics.ts.format("%Y%m%d_%H%M%S"),
        forensics.incident_id.replace(['/', ':', ' '], "_")
    );
    let path = dir.join(filename);
    let content = serde_json::to_string_pretty(forensics)?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write forensics {}", path.display()))?;

    info!(path = %path.display(), "wrote kill-chain forensics");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_with_c2_and_pid() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "kill_chain:reverse_shell:test".to_string(),
                severity: innerwarden_core::event::Severity::Critical,
                title: "Reverse shell blocked".to_string(),
                summary: "Kernel LSM blocked reverse shell to 185.234.1.1:4444".to_string(),
                evidence: serde_json::json!([{
                    "kind": "kill_chain_blocked",
                    "pattern": "REVERSE_SHELL",
                    "c2_ip": "185.234.1.1:4444",
                    "pid": 1234,
                    "process": "python3",
                    "uid": 1000,
                    "timeline": [
                        "connect(185.234.1.1:4444)",
                        "dup2(stdin)",
                        "dup2(stdout)",
                        "execve(/bin/sh) BLOCKED"
                    ]
                }]),
                recommended_checks: vec![],
                tags: vec!["kill_chain".to_string()],
                entities: vec![],
            },
            target_ip: Some("185.234.1.1".to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = KillChainResponse.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
        assert!(res.message.contains("REVERSE_SHELL"));
        assert!(res.message.contains("PID 1234"));
        assert!(res.message.contains("185.234.1.1"));
    }

    #[tokio::test]
    async fn no_evidence_fails_gracefully() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "test:id".to_string(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: None,
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = KillChainResponse.execute(&ctx, true).await;
        assert!(!res.success);
        assert!(res.message.contains("no C2 IP or PID"));
    }

    #[tokio::test]
    async fn dry_run_with_only_pid() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "kill_chain:bind_shell:test".to_string(),
                severity: innerwarden_core::event::Severity::Critical,
                title: "Bind shell detected".to_string(),
                summary: "Bind shell detected on port 4444".to_string(),
                evidence: serde_json::json!([{
                    "kind": "kill_chain_detected",
                    "pattern": "BIND_SHELL",
                    "pid": 5678,
                    "process": "nc",
                    "uid": 1000
                }]),
                recommended_checks: vec![],
                tags: vec!["kill_chain".to_string()],
                entities: vec![],
            },
            target_ip: None,
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = KillChainResponse.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
        assert!(res.message.contains("PID 5678"));
    }
}
