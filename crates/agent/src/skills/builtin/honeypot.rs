use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-4ubuntu0.5\r\n";
const HTTP_BANNER: &[u8] =
    b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const PAYLOAD_READ_TIMEOUT_MS: u64 = 700;
const DEFAULT_LOCK_FILE: &str = "listener-active.lock";

/// Premium honeypot skill.
///
/// Modes:
/// - `demo`: controlled marker only.
/// - `listener`: real bounded decoy listeners + selective redirect (optional) + forensics artifacts.
///
/// TODO(next hardening phase):
/// - move listener runtime into stricter OS-level isolation (namespace/jail)
/// - integrate richer protocol transcripts and pcap handoff
pub struct Honeypot;

#[derive(Debug, Clone)]
struct DecoyEndpoint {
    service: String,
    bind_addr: String,
    listen_port: u16,
    redirect_from_port: u16,
    banner: &'static [u8],
}

#[derive(Debug, Clone, Serialize)]
struct RedirectRuleStatus {
    service: String,
    target_ip: String,
    from_port: u16,
    to_port: u16,
    add_command: String,
    remove_command: String,
    applied: bool,
    apply_error: Option<String>,
    cleanup_ok: Option<bool>,
    cleanup_error: Option<String>,
    cleanup_verified_absent: Option<bool>,
}

#[derive(Debug, Clone)]
struct SessionRuntime {
    session_id: String,
    target_ip: IpAddr,
    strict_target_only: bool,
    duration_secs: u64,
    max_connections: usize,
    max_payload_bytes: usize,
    transcript_preview_bytes: usize,
    isolation_profile: String,
    evidence_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
struct ListenerStats {
    service: String,
    bind_addr: String,
    listen_port: u16,
    accepted: u64,
    rejected: u64,
    payload_bytes_captured: u64,
    read_timeouts: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PayloadCapture {
    bytes_captured: usize,
    payload_hex: String,
    transcript_preview: String,
    protocol_guess: String,
    read_timed_out: bool,
}

#[derive(Debug)]
struct SessionLock {
    path: PathBuf,
}

impl ResponseSkill for Honeypot {
    fn id(&self) -> &'static str {
        "honeypot"
    }
    fn name(&self) -> &'static str {
        "Honeypot (Premium)"
    }
    fn description(&self) -> &'static str {
        "Runs in demo mode or in bounded real listener mode with multi-service decoys, \
         selective redirection, and lightweight forensic artifacts."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Premium
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[]
    }

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
                         Real decoy infra lives in listener mode."
                    ),
                };
            }

            let target_ip = match ip_raw.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: invalid target IP '{ip_raw}'"),
                    };
                }
            };

            let isolation_profile = normalize_isolation_profile(&ctx.honeypot.isolation_profile);
            let strict_profile = isolation_profile == "strict_local";

            if strict_profile
                && (!ctx.honeypot.strict_target_only
                    || ctx.honeypot.allow_public_listener
                    || !ctx.honeypot.require_high_ports)
            {
                return SkillResult {
                    success: false,
                    message: "honeypot listener: strict_local profile requires strict_target_only=true, allow_public_listener=false and require_high_ports=true".to_string(),
                };
            }

            if !ctx.honeypot.allow_public_listener && !is_loopback_bind(&ctx.honeypot.bind_addr) {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: bind_addr {} rejected by isolation guard (set honeypot.allow_public_listener=true if intentional)",
                        ctx.honeypot.bind_addr
                    ),
                };
            }

            let endpoints = match build_endpoints(&ctx.honeypot, &ctx.honeypot.bind_addr) {
                Ok(endpoints) => endpoints,
                Err(msg) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: {msg}"),
                    };
                }
            };

            if ctx.honeypot.require_high_ports
                && endpoints.iter().any(|endpoint| endpoint.listen_port < 1024)
            {
                return SkillResult {
                    success: false,
                    message: "honeypot listener: high-port guard enabled (set honeypot.require_high_ports=false to override)".to_string(),
                };
            }

            let redirect_preview = preview_redirect_commands(
                &endpoints,
                target_ip,
                ctx.honeypot.redirect_enabled,
                &ctx.honeypot.redirect_backend,
            );

            if dry_run {
                let services = endpoints
                    .iter()
                    .map(|e| format!("{}:{}", e.service, e.listen_port))
                    .collect::<Vec<_>>()
                    .join(", ");
                let redirect_note = if redirect_preview.is_empty() {
                    "redirect disabled".to_string()
                } else {
                    format!("redirect rules: {}", redirect_preview.join(" | "))
                };
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would start honeypot listeners ({services}) for {}s targeting {target_ip}; profile={isolation_profile}; {redirect_note}",
                        ctx.honeypot.duration_secs,
                    ),
                };
            }

            if ctx.honeypot.redirect_enabled
                && !ctx
                    .honeypot
                    .redirect_backend
                    .eq_ignore_ascii_case("iptables")
            {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: redirect backend '{}' not supported (supported: iptables)",
                        ctx.honeypot.redirect_backend
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

            let pruned_artifacts =
                match cleanup_old_forensics(&session_dir, ctx.honeypot.forensics_keep_days).await {
                    Ok(removed) => removed,
                    Err(e) => {
                        warn!(
                            path = %session_dir.display(),
                            "honeypot forensics cleanup failed (continuing fail-open): {e}"
                        );
                        0
                    }
                };

            let session_id = format!(
                "{}-{}",
                Utc::now().format("%Y%m%dT%H%M%SZ"),
                target_ip.to_string().replace(':', "_")
            );
            let metadata_path = session_dir.join(format!("listener-session-{session_id}.json"));
            let evidence_path = session_dir.join(format!("listener-session-{session_id}.jsonl"));

            let lock_path = session_dir.join(DEFAULT_LOCK_FILE);
            let session_lock = match SessionLock::acquire(
                lock_path.clone(),
                &session_id,
                ctx.honeypot.lock_stale_secs,
            )
            .await
            {
                Ok(lock) => lock,
                Err(e) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: {e}"),
                    };
                }
            };

            let mut bound = Vec::new();
            let mut bind_errors = Vec::new();
            for endpoint in endpoints {
                let bind_target = format!("{}:{}", endpoint.bind_addr, endpoint.listen_port);
                match TcpListener::bind(&bind_target).await {
                    Ok(listener) => {
                        info!(service = %endpoint.service, bind = %bind_target, "honeypot listener bound");
                        bound.push((endpoint, listener));
                    }
                    Err(e) => bind_errors.push(format!("{bind_target}: {e}")),
                }
            }

            if bound.is_empty() {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to bind all decoys: {}",
                        bind_errors.join("; ")
                    ),
                };
            }

            let mut redirect_rules = if ctx.honeypot.redirect_enabled {
                apply_redirect_rules(
                    &bound
                        .iter()
                        .map(|(endpoint, _)| endpoint.clone())
                        .collect::<Vec<_>>(),
                    target_ip,
                    &ctx.honeypot.redirect_backend,
                )
                .await
            } else {
                vec![]
            };

            let start_metadata = serde_json::json!({
                "ts": Utc::now().to_rfc3339(),
                "status": "running",
                "mode": "listener",
                "host": ctx.host,
                "incident_id": ctx.incident.incident_id,
                "target_ip": target_ip.to_string(),
                "bind_addr": ctx.honeypot.bind_addr,
                "duration_secs": ctx.honeypot.duration_secs,
                "services": bound.iter().map(|(ep, _)| serde_json::json!({
                    "service": ep.service.clone(),
                    "listen_port": ep.listen_port,
                    "redirect_from_port": ep.redirect_from_port,
                })).collect::<Vec<_>>(),
                "strict_target_only": ctx.honeypot.strict_target_only,
                "max_connections": ctx.honeypot.max_connections,
                "max_payload_bytes": ctx.honeypot.max_payload_bytes,
                "isolation_profile": isolation_profile,
                "require_high_ports": ctx.honeypot.require_high_ports,
                "forensics_keep_days": ctx.honeypot.forensics_keep_days,
                "transcript_preview_bytes": ctx.honeypot.transcript_preview_bytes,
                "lock_stale_secs": ctx.honeypot.lock_stale_secs,
                "lock_file": lock_path,
                "forensics_pruned_files": pruned_artifacts,
                "redirect": {
                    "enabled": ctx.honeypot.redirect_enabled,
                    "backend": ctx.honeypot.redirect_backend,
                    "rules": redirect_rules.clone(),
                },
                "note": "Real honeypot listener session. Bounded and fail-open."
            });
            if let Err(e) = write_json_file(&metadata_path, &start_metadata).await {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to write metadata {}: {e}",
                        metadata_path.display()
                    ),
                };
            }

            if let Err(e) = append_json_line(
                &evidence_path,
                &serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "type": "session_started",
                    "session_id": session_id.clone(),
                    "target_ip": target_ip.to_string(),
                    "isolation_profile": isolation_profile,
                    "forensics_pruned_files": pruned_artifacts,
                }),
            )
            .await
            {
                warn!(path = %evidence_path.display(), "failed to append honeypot session start line: {e}");
            }

            let runtime = SessionRuntime {
                session_id: session_id.clone(),
                target_ip,
                strict_target_only: ctx.honeypot.strict_target_only,
                duration_secs: ctx.honeypot.duration_secs,
                max_connections: ctx.honeypot.max_connections,
                max_payload_bytes: ctx.honeypot.max_payload_bytes,
                transcript_preview_bytes: ctx.honeypot.transcript_preview_bytes,
                isolation_profile: isolation_profile.to_string(),
                evidence_path: evidence_path.clone(),
            };

            let metadata_path_bg = metadata_path.clone();
            let evidence_path_bg = evidence_path.clone();
            tokio::spawn(async move {
                let _session_lock = session_lock;
                let mut task_stats = Vec::new();
                let mut tasks = Vec::new();
                for (endpoint, listener) in bound {
                    let runtime = runtime.clone();
                    tasks.push(tokio::spawn(async move {
                        run_listener(endpoint, listener, runtime).await
                    }));
                }

                for task in tasks {
                    match task.await {
                        Ok(stats) => task_stats.push(stats),
                        Err(e) => warn!("honeypot listener task join error: {e}"),
                    }
                }

                cleanup_redirect_rules(&mut redirect_rules).await;
                let redirect_cleanup_verified = redirect_rules
                    .iter()
                    .all(|rule| rule.cleanup_verified_absent.unwrap_or(true));

                if let Err(e) = append_json_line(
                    &evidence_path_bg,
                    &serde_json::json!({
                        "ts": Utc::now().to_rfc3339(),
                        "type": "session_finished",
                        "session_id": runtime.session_id.clone(),
                        "services": task_stats,
                        "redirect_cleanup_verified": redirect_cleanup_verified,
                    }),
                )
                .await
                {
                    warn!(path = %evidence_path_bg.display(), "failed to append honeypot completion line: {e}");
                }

                let final_metadata = serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "status": "completed",
                    "session_id": runtime.session_id.clone(),
                    "target_ip": runtime.target_ip.to_string(),
                    "strict_target_only": runtime.strict_target_only,
                    "duration_secs": runtime.duration_secs,
                    "max_connections": runtime.max_connections,
                    "max_payload_bytes": runtime.max_payload_bytes,
                    "isolation_profile": runtime.isolation_profile,
                    "service_stats": task_stats,
                    "redirect_rules": redirect_rules,
                    "redirect_cleanup_verified": redirect_cleanup_verified,
                    "forensics_file": evidence_path_bg,
                });
                if let Err(e) = write_json_file(&metadata_path_bg, &final_metadata).await {
                    warn!(path = %metadata_path_bg.display(), "failed to write honeypot final metadata: {e}");
                }
            });

            let warning_suffix = if bind_errors.is_empty() {
                String::new()
            } else {
                format!(" | warnings: {}", bind_errors.join("; "))
            };

            SkillResult {
                success: true,
                message: format!(
                    "Honeypot listeners started (session {session_id}, profile {isolation_profile}, pruned {pruned_artifacts}). metadata: {} evidence: {}{}",
                    metadata_path.display(),
                    evidence_path.display(),
                    warning_suffix
                ),
            }
        })
    }
}

async fn run_listener(
    endpoint: DecoyEndpoint,
    listener: TcpListener,
    runtime: SessionRuntime,
) -> ListenerStats {
    info!(
        service = %endpoint.service,
        bind_addr = %endpoint.bind_addr,
        port = endpoint.listen_port,
        target_ip = %runtime.target_ip,
        strict_target_only = runtime.strict_target_only,
        "honeypot listener started"
    );

    let mut stats = ListenerStats {
        service: endpoint.service.clone(),
        bind_addr: endpoint.bind_addr.clone(),
        listen_port: endpoint.listen_port,
        accepted: 0,
        rejected: 0,
        payload_bytes_captured: 0,
        read_timeouts: 0,
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(runtime.duration_secs);
    while tokio::time::Instant::now() < deadline {
        if (stats.accepted + stats.rejected) >= runtime.max_connections as u64 {
            break;
        }

        let now = tokio::time::Instant::now();
        let timeout = deadline.duration_since(now);
        let accepted = tokio::time::timeout(timeout, listener.accept()).await;

        let (mut socket, peer) = match accepted {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                warn!(service = %endpoint.service, "honeypot listener accept error: {e}");
                break;
            }
            Err(_) => break,
        };

        let is_target = peer.ip() == runtime.target_ip;
        let allowed = !runtime.strict_target_only || is_target;

        let payload = capture_payload(
            &mut socket,
            runtime.max_payload_bytes,
            runtime.transcript_preview_bytes,
        )
        .await;

        if payload.read_timed_out {
            stats.read_timeouts += 1;
        }
        stats.payload_bytes_captured += payload.bytes_captured as u64;

        if allowed {
            stats.accepted += 1;
            let _ = socket.write_all(endpoint.banner).await;
        } else {
            stats.rejected += 1;
        }

        let entry = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "type": "connection",
            "session_id": runtime.session_id.clone(),
            "service": endpoint.service.clone(),
            "bind_addr": endpoint.bind_addr.clone(),
            "listen_port": endpoint.listen_port,
            "peer": peer.to_string(),
            "peer_ip": peer.ip().to_string(),
            "target_ip": runtime.target_ip.to_string(),
            "target_match": is_target,
            "accepted": allowed,
            "bytes_captured": payload.bytes_captured,
            "payload_hex": payload.payload_hex,
            "transcript_preview": payload.transcript_preview,
            "protocol_guess": payload.protocol_guess,
            "read_timed_out": payload.read_timed_out,
            "isolation_profile": runtime.isolation_profile.clone(),
        });
        if let Err(e) = append_json_line(&runtime.evidence_path, &entry).await {
            warn!(path = %runtime.evidence_path.display(), "failed to append honeypot evidence line: {e}");
        }
    }

    info!(
        service = %endpoint.service,
        accepted = stats.accepted,
        rejected = stats.rejected,
        "honeypot listener finished"
    );
    stats
}

async fn capture_payload(
    socket: &mut tokio::net::TcpStream,
    max_bytes: usize,
    transcript_preview_bytes: usize,
) -> PayloadCapture {
    if max_bytes == 0 {
        return PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "none".to_string(),
            read_timed_out: false,
        };
    }

    let read_cap = max_bytes.min(4096);
    let mut buf = vec![0u8; read_cap];
    match tokio::time::timeout(
        Duration::from_millis(PAYLOAD_READ_TIMEOUT_MS),
        socket.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => {
            let n = n.min(read_cap);
            let payload = &buf[..n];
            PayloadCapture {
                bytes_captured: n,
                payload_hex: bytes_to_hex(payload),
                transcript_preview: sanitize_transcript(payload, transcript_preview_bytes),
                protocol_guess: guess_protocol(payload),
                read_timed_out: false,
            }
        }
        Ok(Err(_)) => PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "unknown".to_string(),
            read_timed_out: false,
        },
        Err(_) => PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "unknown".to_string(),
            read_timed_out: true,
        },
    }
}

fn bytes_to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn sanitize_transcript(data: &[u8], preview_limit: usize) -> String {
    let mut out = String::new();
    for &b in data.iter().take(preview_limit) {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push('.'),
        }
    }
    out
}

fn guess_protocol(data: &[u8]) -> String {
    if data.is_empty() {
        return "none".to_string();
    }
    if data.starts_with(b"SSH-") {
        return "ssh".to_string();
    }
    if data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"HEAD ")
        || data.windows(5).any(|w| w == b"HTTP/")
    {
        return "http".to_string();
    }

    let printable = data
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7e | b'\r' | b'\n' | b'\t'))
        .count();
    if printable * 100 / data.len().max(1) >= 70 {
        "text".to_string()
    } else {
        "binary".to_string()
    }
}

fn build_endpoints(
    runtime: &crate::skills::HoneypotRuntimeConfig,
    bind_addr: &str,
) -> Result<Vec<DecoyEndpoint>, String> {
    let mut services = runtime
        .services
        .iter()
        .map(|svc| svc.trim().to_ascii_lowercase())
        .filter(|svc| !svc.is_empty())
        .collect::<Vec<_>>();
    if services.is_empty() {
        services.push("ssh".to_string());
    }

    let mut dedup = HashSet::new();
    services.retain(|svc| dedup.insert(svc.clone()));

    let mut endpoints = Vec::new();
    for service in services {
        match service.as_str() {
            "ssh" => endpoints.push(DecoyEndpoint {
                service,
                bind_addr: bind_addr.to_string(),
                listen_port: runtime.port,
                redirect_from_port: 22,
                banner: SSH_BANNER,
            }),
            "http" => endpoints.push(DecoyEndpoint {
                service,
                bind_addr: bind_addr.to_string(),
                listen_port: runtime.http_port,
                redirect_from_port: 80,
                banner: HTTP_BANNER,
            }),
            other => {
                return Err(format!(
                    "unsupported service '{other}' (supported: ssh, http)"
                ));
            }
        }
    }

    let mut ports = HashSet::new();
    for endpoint in &endpoints {
        if endpoint.listen_port == 0 {
            return Err(format!("service '{}' has invalid port 0", endpoint.service));
        }
        if !ports.insert(endpoint.listen_port) {
            return Err(format!(
                "duplicate listener port {} in honeypot services",
                endpoint.listen_port
            ));
        }
    }

    Ok(endpoints)
}

fn is_loopback_bind(bind_addr: &str) -> bool {
    bind_addr
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn normalize_isolation_profile(profile: &str) -> &'static str {
    if profile.eq_ignore_ascii_case("standard") {
        "standard"
    } else {
        "strict_local"
    }
}

async fn cleanup_old_forensics(session_dir: &Path, keep_days: usize) -> std::io::Result<usize> {
    let mut removed = 0usize;
    let cutoff = Utc::now().date_naive() - chrono::Duration::days(keep_days as i64);

    let mut entries = tokio::fs::read_dir(session_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(file_date) = extract_listener_artifact_date(name) else {
            continue;
        };
        if file_date < cutoff {
            if tokio::fs::remove_file(&path).await.is_ok() {
                removed += 1;
            }
        }
    }

    Ok(removed)
}

fn extract_listener_artifact_date(name: &str) -> Option<chrono::NaiveDate> {
    if !name.starts_with("listener-session-") {
        return None;
    }
    let ts = name.trim_start_matches("listener-session-");
    let ts = ts.split('-').next()?;
    let parsed = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%dT%H%M%SZ").ok()?;
    Some(parsed.date())
}

fn preview_redirect_commands(
    endpoints: &[DecoyEndpoint],
    target_ip: IpAddr,
    enabled: bool,
    backend: &str,
) -> Vec<String> {
    if !enabled || !backend.eq_ignore_ascii_case("iptables") {
        return Vec::new();
    }
    endpoints
        .iter()
        .map(|endpoint| {
            format!(
                "sudo iptables -t nat -A PREROUTING -p tcp -s {} --dport {} -j REDIRECT --to-ports {}",
                target_ip, endpoint.redirect_from_port, endpoint.listen_port
            )
        })
        .collect()
}

async fn apply_redirect_rules(
    endpoints: &[DecoyEndpoint],
    target_ip: IpAddr,
    backend: &str,
) -> Vec<RedirectRuleStatus> {
    if !backend.eq_ignore_ascii_case("iptables") {
        return vec![];
    }

    let mut statuses = Vec::new();
    for endpoint in endpoints {
        let add_args = vec![
            "iptables".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-A".to_string(),
            "PREROUTING".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "-s".to_string(),
            target_ip.to_string(),
            "--dport".to_string(),
            endpoint.redirect_from_port.to_string(),
            "-j".to_string(),
            "REDIRECT".to_string(),
            "--to-ports".to_string(),
            endpoint.listen_port.to_string(),
        ];
        let del_args = vec![
            "iptables".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-D".to_string(),
            "PREROUTING".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "-s".to_string(),
            target_ip.to_string(),
            "--dport".to_string(),
            endpoint.redirect_from_port.to_string(),
            "-j".to_string(),
            "REDIRECT".to_string(),
            "--to-ports".to_string(),
            endpoint.listen_port.to_string(),
        ];

        let add_cmd = format!("sudo {}", add_args.join(" "));
        let del_cmd = format!("sudo {}", del_args.join(" "));

        let output = Command::new("sudo").args(&add_args).output().await;
        let status = match output {
            Ok(out) if out.status.success() => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: true,
                apply_error: None,
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
            Ok(out) => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: false,
                apply_error: Some(String::from_utf8_lossy(&out.stderr).trim().to_string()),
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
            Err(e) => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: false,
                apply_error: Some(e.to_string()),
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
        };

        if !status.applied {
            warn!(service = %endpoint.service, "honeypot redirect rule not applied: {:?}", status.apply_error);
        }
        statuses.push(status);
    }

    statuses
}

async fn cleanup_redirect_rules(rules: &mut [RedirectRuleStatus]) {
    for rule in rules.iter_mut() {
        if !rule.applied {
            continue;
        }

        let del_args = redirect_rule_args(rule, "D");
        match Command::new("sudo").args(&del_args).output().await {
            Ok(out) if out.status.success() => {
                rule.cleanup_ok = Some(true);
                rule.cleanup_error = None;
            }
            Ok(out) => {
                rule.cleanup_ok = Some(false);
                rule.cleanup_error = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
            Err(e) => {
                rule.cleanup_ok = Some(false);
                rule.cleanup_error = Some(e.to_string());
            }
        }

        let check_args = redirect_rule_args(rule, "C");
        match Command::new("sudo").args(&check_args).output().await {
            Ok(out) if out.status.success() => {
                rule.cleanup_verified_absent = Some(false);
                if rule.cleanup_error.is_none() {
                    rule.cleanup_error =
                        Some("redirect rule still present after cleanup".to_string());
                }
            }
            Ok(_) => {
                rule.cleanup_verified_absent = Some(true);
            }
            Err(e) => {
                rule.cleanup_verified_absent = None;
                if rule.cleanup_error.is_none() {
                    rule.cleanup_error = Some(format!("redirect cleanup verification failed: {e}"));
                }
            }
        }
    }
}

fn redirect_rule_args(rule: &RedirectRuleStatus, op: &str) -> Vec<String> {
    vec![
        "iptables".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        format!("-{op}"),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        rule.target_ip.clone(),
        "--dport".to_string(),
        rule.from_port.to_string(),
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-ports".to_string(),
        rule.to_port.to_string(),
    ]
}

impl SessionLock {
    async fn acquire(path: PathBuf, session_id: &str, stale_secs: u64) -> Result<Self, String> {
        let lock_body = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "session_id": session_id,
        });
        for attempt in 0..2 {
            match tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await
            {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(format!("{lock_body}\n").as_bytes()).await {
                        return Err(format!(
                            "failed to write session lock {}: {e}",
                            path.display()
                        ));
                    }
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt == 0 && is_lock_stale(&path, stale_secs).await {
                        warn!(path = %path.display(), "stale honeypot session lock detected; removing");
                        let _ = tokio::fs::remove_file(&path).await;
                        continue;
                    }
                    return Err(format!(
                        "another honeypot listener session is active (lock: {})",
                        path.display()
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "failed to create session lock {}: {e}",
                        path.display()
                    ));
                }
            }
        }
        Err(format!(
            "another honeypot listener session is active (lock: {})",
            path.display()
        ))
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn is_lock_stale(path: &Path, stale_secs: u64) -> bool {
    if stale_secs == 0 {
        return false;
    }

    if let Ok(content) = tokio::fs::read_to_string(path).await {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(ts) = value.get("ts").and_then(|v| v.as_str()) {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                    let age = Utc::now() - parsed.with_timezone(&Utc);
                    return age.num_seconds() > stale_secs as i64;
                }
            }
        }
    }

    if let Ok(meta) = tokio::fs::metadata(path).await {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() > stale_secs;
            }
        }
    }
    false
}

async fn append_json_line(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(format!("{value}\n").as_bytes()).await?;
    file.flush().await
}

async fn write_json_file(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    tokio::fs::write(path, format!("{value}\n")).await
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
                http_port: 8080,
                duration_secs: 30,
                services: vec!["ssh".to_string()],
                strict_target_only: true,
                allow_public_listener: false,
                max_connections: 8,
                max_payload_bytes: 256,
                isolation_profile: "strict_local".to_string(),
                require_high_ports: true,
                forensics_keep_days: 7,
                transcript_preview_bytes: 96,
                lock_stale_secs: 1800,
                redirect_enabled: false,
                redirect_backend: "iptables".to_string(),
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
        assert!(result.message.contains("would start honeypot listeners"));
    }

    #[tokio::test]
    async fn listener_rejects_public_bind_when_guard_enabled() {
        let mut context = ctx("listener");
        context.honeypot.bind_addr = "0.0.0.0".to_string();
        context.honeypot.allow_public_listener = false;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("isolation guard"));
    }

    #[test]
    fn builds_multiple_services() {
        let runtime = HoneypotRuntimeConfig {
            services: vec!["ssh".to_string(), "http".to_string()],
            ..HoneypotRuntimeConfig::default()
        };
        let endpoints = build_endpoints(&runtime, "127.0.0.1").unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().any(|e| e.service == "ssh"));
        assert!(endpoints.iter().any(|e| e.service == "http"));
    }

    #[test]
    fn rejects_unknown_service() {
        let runtime = HoneypotRuntimeConfig {
            services: vec!["smtp".to_string()],
            ..HoneypotRuntimeConfig::default()
        };
        let err = build_endpoints(&runtime, "127.0.0.1").unwrap_err();
        assert!(err.contains("unsupported service"));
    }

    #[tokio::test]
    async fn strict_profile_enforces_listener_guards() {
        let mut context = ctx("listener");
        context.honeypot.allow_public_listener = true;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("strict_local profile"));
    }

    #[tokio::test]
    async fn high_port_guard_blocks_privileged_listener_ports() {
        let mut context = ctx("listener");
        context.honeypot.port = 22;
        context.honeypot.require_high_ports = true;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("high-port guard"));
    }

    #[test]
    fn transcript_preview_and_protocol_guess() {
        let payload = b"GET /admin HTTP/1.1\r\nHost: demo\r\n";
        let transcript = sanitize_transcript(payload, 12);
        assert!(transcript.contains("GET /admin"));
        assert_eq!(guess_protocol(payload), "http");
        assert_eq!(guess_protocol(b"SSH-2.0-test"), "ssh");
    }

    #[test]
    fn parses_listener_artifact_date() {
        let date = extract_listener_artifact_date("listener-session-20260313T162200Z-1.2.3.4.json")
            .expect("date should parse");
        assert_eq!(date.format("%Y-%m-%d").to_string(), "2026-03-13");
    }
}
