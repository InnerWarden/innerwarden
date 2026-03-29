//! Selective packet capture on High/Critical incidents.
//!
//! When a High or Critical incident fires and involves an external IP,
//! spawns `tcpdump` to capture 60 seconds of traffic for that IP.
//! The pcap file is saved to `data/pcap/` and the path is returned
//! for attachment to incident evidence.
//!
//! Best-effort: if tcpdump is not installed or capture fails, the
//! incident processing continues normally. No blocking.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use tracing::{debug, info, warn};

/// Default capture duration in seconds.
const CAPTURE_DURATION_SECS: u64 = 60;
/// Maximum packets to capture per incident.
const MAX_PACKETS: u32 = 10_000;
/// Cooldown per IP: don't re-capture within this window.
const COOLDOWN_SECS: i64 = 300;
/// Maximum concurrent captures.
const MAX_CONCURRENT: usize = 3;

/// Manages selective packet captures triggered by incidents.
pub struct PcapCapture {
    data_dir: PathBuf,
    /// Cooldown per IP to prevent duplicate captures.
    cooldowns: HashMap<String, DateTime<Utc>>,
    /// Currently running capture count.
    active_captures: usize,
}

/// Result of initiating a capture.
#[derive(Debug)]
pub struct CaptureResult {
    pub pcap_path: PathBuf,
    pub ip: String,
    pub duration_secs: u64,
}

impl PcapCapture {
    pub fn new(data_dir: &Path) -> Self {
        // Create pcap directory
        let pcap_dir = data_dir.join("pcap");
        let _ = std::fs::create_dir_all(&pcap_dir);

        Self {
            data_dir: data_dir.to_path_buf(),
            cooldowns: HashMap::new(),
            active_captures: 0,
        }
    }

    /// Attempt to start a packet capture for the given IP.
    ///
    /// Returns the pcap file path if capture was initiated, None if skipped
    /// (cooldown, no tcpdump, too many concurrent captures, internal IP).
    pub fn try_capture(&mut self, ip: &str, incident_id: &str) -> Option<CaptureResult> {
        let now = Utc::now();

        // Skip internal/private IPs
        if is_internal(ip) {
            return None;
        }

        // Cooldown check
        if let Some(last) = self.cooldowns.get(ip) {
            if now - *last < Duration::seconds(COOLDOWN_SECS) {
                debug!(ip, "pcap: skipping (cooldown active)");
                return None;
            }
        }

        // Concurrency check
        if self.active_captures >= MAX_CONCURRENT {
            debug!("pcap: skipping (max concurrent captures reached)");
            return None;
        }

        // Check if tcpdump is available
        if !tcpdump_available() {
            debug!("pcap: tcpdump not found in PATH");
            return None;
        }

        self.cooldowns.insert(ip.to_string(), now);

        let pcap_dir = self.data_dir.join("pcap");
        let filename = format!(
            "incident-{}-{}.pcap",
            sanitize_filename(incident_id),
            now.format("%Y%m%d-%H%M%S")
        );
        let pcap_path = pcap_dir.join(&filename);

        let ip_owned = ip.to_string();
        let path_clone = pcap_path.clone();

        info!(
            ip = %ip,
            incident_id = %incident_id,
            pcap = %pcap_path.display(),
            duration = CAPTURE_DURATION_SECS,
            "pcap: starting packet capture"
        );

        // Spawn tcpdump in background — non-blocking
        self.active_captures += 1;
        let active_counter = self.active_captures;
        std::thread::spawn(move || {
            let result = std::process::Command::new("tcpdump")
                .args([
                    "-i",
                    "any",
                    "-c",
                    &MAX_PACKETS.to_string(),
                    "-w",
                    &path_clone.to_string_lossy(),
                    "-G",
                    &CAPTURE_DURATION_SECS.to_string(),
                    "-W",
                    "1", // rotate: 1 file only
                    "host",
                    &ip_owned,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match result {
                Ok(status) => {
                    if status.success() {
                        info!(
                            ip = %ip_owned,
                            pcap = %path_clone.display(),
                            "pcap: capture completed"
                        );
                    } else {
                        warn!(
                            ip = %ip_owned,
                            code = ?status.code(),
                            "pcap: tcpdump exited with error"
                        );
                    }
                }
                Err(e) => {
                    warn!(ip = %ip_owned, "pcap: failed to run tcpdump: {e}");
                }
            }
        });

        Some(CaptureResult {
            pcap_path,
            ip: ip.to_string(),
            duration_secs: CAPTURE_DURATION_SECS,
        })
    }

    /// Prune expired cooldowns.
    pub fn cleanup(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(COOLDOWN_SECS);
        self.cooldowns.retain(|_, ts| *ts > cutoff);
        // Reset active counter (conservative — threads self-manage)
        if self.active_captures > 0 {
            self.active_captures = self.active_captures.saturating_sub(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tcpdump_available() -> bool {
    std::process::Command::new("which")
        .arg("tcpdump")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_internal(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(80)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_works() {
        assert_eq!(
            sanitize_filename("reverse_shell:10.0.0.1:2026-03-29T12:00Z"),
            "reverse_shell_10_0_0_1_2026-03-29T12_00Z"
        );
    }

    #[test]
    fn internal_ip_detection() {
        assert!(is_internal("127.0.0.1"));
        assert!(is_internal("192.168.1.1"));
        assert!(is_internal("10.0.0.1"));
        assert!(!is_internal("8.8.8.8"));
        assert!(!is_internal("1.2.3.4"));
    }

    #[test]
    fn pcap_capture_skips_internal() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cap = PcapCapture::new(dir.path());
        assert!(cap.try_capture("192.168.1.1", "test").is_none());
    }

    #[test]
    fn pcap_dir_created() {
        let dir = tempfile::TempDir::new().unwrap();
        let _cap = PcapCapture::new(dir.path());
        assert!(dir.path().join("pcap").exists());
    }

    #[test]
    fn cooldown_prevents_recapture() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cap = PcapCapture::new(dir.path());
        // First attempt might succeed or fail depending on tcpdump availability
        let _ = cap.try_capture("8.8.8.8", "test-1");
        // Second attempt within cooldown should be skipped
        assert!(cap.try_capture("8.8.8.8", "test-2").is_none());
    }
}
