use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Premium honeypot skill with two runtime modes:
///
/// - `demo` (default): controlled marker only.
/// - `listener`: starts a minimal decoy TCP listener for a bounded time window.
///
/// TODO(real honeypot rebuild):
/// - Replace listener foundation with full infrastructure:
///   decoy service suite, selective traffic diversion, isolation, and forensics pipeline.
pub struct Honeypot;

impl ResponseSkill for Honeypot {
    fn id(&self) -> &'static str { "honeypot" }
    fn name(&self) -> &'static str { "Honeypot (Premium)" }
    fn description(&self) -> &'static str {
        "Supports demo marker mode and a minimal real listener mode (bounded decoy TCP service). \
         Full honeypot rebuild remains a future dedicated phase."
    }
    fn tier(&self) -> SkillTier { SkillTier::Premium }
    fn applicable_to(&self) -> &'static [&'static str] { &[] }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip_raw = ctx.target_ip.as_deref().unwrap_or("unknown");
            let mode = ctx.honeypot.mode.trim().to_ascii_lowercase();

            if mode != "listener" {
                info!(
                    ip = ip_raw,
                    "[PREMIUM] honeypot demo marker triggered \
                     (DEMO/SIMULATION/DECOY mode; no real honeypot infrastructure)"
                );
                return SkillResult {
                    success: true,
                    message: format!(
                        "[PREMIUM DEMO] Honeypot simulation marker armed for {ip_raw}. \
                         TODO: dedicated future phase will rebuild this into real infrastructure."
                    ),
                };
            }

            let ip = match ip_raw.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    return SkillResult {
                        success: false,
                        message: format!(
                            "honeypot listener: invalid target IP '{ip_raw}'"
                        ),
                    };
                }
            };

            let bind_target = format!("{}:{}", ctx.honeypot.bind_addr, ctx.honeypot.port);
            if dry_run {
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would start honeypot listener at {bind_target} for {}s targeting {ip}",
                        ctx.honeypot.duration_secs
                    ),
                };
            }

            let session_dir = ctx.data_dir.join("honeypot");
            if let Err(e) = tokio::fs::create_dir_all(&session_dir).await {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to create session dir {}: {e}",
                        session_dir.display()
                    ),
                };
            }

            let session_id = format!(
                "{}-{}",
                Utc::now().format("%Y%m%dT%H%M%SZ"),
                ip.to_string().replace(':', "_")
            );
            let metadata_path = session_dir.join(format!("listener-session-{session_id}.json"));
            let metadata = serde_json::json!({
                "ts": Utc::now().to_rfc3339(),
                "mode": "listener",
                "host": ctx.host,
                "incident_id": ctx.incident.incident_id,
                "target_ip": ip.to_string(),
                "bind_addr": ctx.honeypot.bind_addr,
                "port": ctx.honeypot.port,
                "duration_secs": ctx.honeypot.duration_secs,
                "note": "Minimal real listener foundation. Full honeypot rebuild remains planned."
            });
            if let Err(e) = tokio::fs::write(&metadata_path, format!("{metadata}\n")).await {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to write metadata {}: {e}",
                        metadata_path.display()
                    ),
                };
            }

            let listener = match TcpListener::bind(&bind_target).await {
                Ok(listener) => listener,
                Err(e) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: failed to bind {bind_target}: {e}"),
                    };
                }
            };

            let target_ip = ip;
            let duration_secs = ctx.honeypot.duration_secs;
            let bind_addr = bind_target.clone();
            tokio::spawn(async move {
                run_listener(listener, &bind_addr, target_ip, duration_secs).await;
            });

            SkillResult {
                success: true,
                message: format!(
                    "Honeypot listener started at {bind_target} for {}s (target {ip}). metadata: {}",
                    ctx.honeypot.duration_secs,
                    metadata_path.display()
                ),
            }
        })
    }
}

async fn run_listener(
    listener: TcpListener,
    bind_addr: &str,
    target_ip: IpAddr,
    duration_secs: u64,
) {
    info!(
        bind_addr,
        target_ip = %target_ip,
        duration_secs,
        "honeypot listener started"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let timeout = deadline.duration_since(now);
        match tokio::time::timeout(timeout, listener.accept()).await {
            Ok(Ok((mut socket, peer))) => {
                let peer_ip = peer.ip();
                let watched = peer_ip == target_ip;
                info!(
                    bind_addr,
                    peer = %peer,
                    watched_target = watched,
                    "honeypot listener accepted connection"
                );
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-4ubuntu0.5\r\n").await;
            }
            Ok(Err(e)) => {
                warn!(bind_addr, "honeypot listener accept error: {e}");
                break;
            }
            Err(_) => break,
        }
    }

    info!(bind_addr, "honeypot listener finished");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::HoneypotRuntimeConfig;
    use innerwarden_core::{event::Severity, incident::Incident};

    fn ctx(mode: &str) -> SkillContext {
        SkillContext {
            incident: Incident {
                ts: Utc::now(),
                host: "host-a".to_string(),
                incident_id: "incident-1".to_string(),
                severity: Severity::High,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: Some("1.2.3.4".to_string()),
            host: "host-a".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig {
                mode: mode.to_string(),
                bind_addr: "127.0.0.1".to_string(),
                port: 2222,
                duration_secs: 30,
            },
        }
    }

    #[tokio::test]
    async fn demo_mode_returns_demo_message() {
        let result = Honeypot.execute(&ctx("demo"), false).await;
        assert!(result.success);
        assert!(result.message.contains("PREMIUM DEMO"));
    }

    #[tokio::test]
    async fn listener_mode_dry_run_returns_preview() {
        let result = Honeypot.execute(&ctx("listener"), true).await;
        assert!(result.success);
        assert!(result.message.contains("would start honeypot listener"));
    }
}
