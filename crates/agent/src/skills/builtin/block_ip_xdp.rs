use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// XDP firewall block - drops packets at the network driver level.
///
/// Instead of adding a firewall rule (ufw/iptables), this inserts the IP
/// into a BPF hash map that the XDP program checks on every incoming packet.
/// Drop rate: 10-25 million packets per second, zero CPU overhead.
///
/// The BPF map is pinned at /sys/fs/bpf/innerwarden/blocklist.
/// We use bpftool to manage it (available on all eBPF-capable systems).
pub struct BlockIpXdp;

/// Path where the XDP blocklist map is pinned.
const BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";

impl ResponseSkill for BlockIpXdp {
    fn id(&self) -> &'static str {
        "block-ip-xdp"
    }
    fn name(&self) -> &'static str {
        "Block IP via XDP (wire-speed)"
    }
    fn description(&self) -> &'static str {
        "Drops packets from the attacking IP at the network driver level using XDP. \
         10-25 million pps drop rate, zero CPU overhead. \
         The fastest possible firewall - packets never reach the kernel network stack."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[
            "ssh_bruteforce",
            "port_scan",
            "credential_stuffing",
            "c2_callback",
            "distributed_ssh",
        ]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => {
                    return SkillResult {
                        success: false,
                        message: "block-ip-xdp: no target IP in context".to_string(),
                    }
                }
            };

            // Parse and convert IP to bytes (network byte order)
            let addr: Ipv4Addr = match ip.parse() {
                Ok(a) => a,
                Err(_) => {
                    return SkillResult {
                        success: false,
                        message: format!("block-ip-xdp: invalid IPv4 address: {ip}"),
                    }
                }
            };
            let ip_bytes = addr.octets();
            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would insert {ip} into XDP blocklist (wire-speed drop)"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via XDP (wire-speed)"),
                };
            }

            // Check if pinned map exists
            if !std::path::Path::new(BLOCKLIST_PIN).exists() {
                // XDP not loaded - fall through, agent will use fallback backend
                warn!(
                    ip,
                    "XDP blocklist map not found at {BLOCKLIST_PIN} - XDP firewall not loaded"
                );
                return SkillResult {
                    success: false,
                    message: format!(
                        "XDP not available (map not found at {BLOCKLIST_PIN}). \
                         Ensure innerwarden-sensor is running with --features ebpf and XDP is attached."
                    ),
                };
            }

            // Insert into pinned BPF map via bpftool
            // Key: 4 bytes (IPv4 addr), Value: 4 bytes (flag = 1)
            let output = tokio::process::Command::new("sudo")
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
                    info!(ip, "blocked via XDP (wire-speed drop)");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via XDP - wire-speed drop active"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "bpftool map update failed");
                    SkillResult {
                        success: false,
                        message: format!("XDP block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn bpftool");
                    SkillResult {
                        success: false,
                        message: format!("failed to run bpftool: {e}"),
                    }
                }
            }
        })
    }
}

/// Check if XDP firewall is available on this system.
#[allow(dead_code)]
pub fn is_xdp_available() -> bool {
    std::path::Path::new(BLOCKLIST_PIN).exists()
}

/// Remove an IP from the XDP blocklist (unblock).
#[allow(dead_code)]
pub async fn xdp_unblock_ip(ip: &str) -> Result<(), String> {
    let addr: Ipv4Addr = ip.parse().map_err(|e| format!("invalid IP: {e}"))?;
    let ip_bytes = addr.octets();

    let output = tokio::process::Command::new("sudo")
        .args([
            "bpftool",
            "map",
            "delete",
            "pinned",
            BLOCKLIST_PIN,
            "key",
            &ip_bytes[0].to_string(),
            &ip_bytes[1].to_string(),
            &ip_bytes[2].to_string(),
            &ip_bytes[3].to_string(),
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run bpftool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
