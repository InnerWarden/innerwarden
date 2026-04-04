//! Environment profiling — detect cloud/VM, admin UIDs, services, crons.
//!
//! Bootstrap profiling runs once at first boot (or when profile is missing).
//! The profile is stored as JSON in data_dir and loaded at agent startup to
//! adjust notification thresholds and suppress known noise.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::EnvironmentConfig;

// ---------------------------------------------------------------------------
// Profile data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvironmentProfile {
    /// "cloud_vps", "vm", or "bare_metal"
    pub platform: String,
    /// Cloud provider if detected (e.g., "oracle", "aws", "gcp", "azure", "digitalocean")
    pub provider: String,
    /// UIDs of human users (uid >= 1000, with login shell)
    pub human_uids: Vec<u32>,
    /// Running systemd service names
    pub services: Vec<String>,
    /// Cron job descriptions
    pub crons: Vec<String>,
    /// When the profile was generated
    pub profiled_at: chrono::DateTime<chrono::Utc>,
}

impl Default for EnvironmentProfile {
    fn default() -> Self {
        Self {
            platform: "unknown".into(),
            provider: "unknown".into(),
            human_uids: vec![],
            services: vec![],
            crons: vec![],
            profiled_at: chrono::Utc::now(),
        }
    }
}

impl EnvironmentProfile {
    pub fn is_cloud(&self) -> bool {
        self.platform == "cloud_vps" || self.platform == "vm"
    }

    pub fn is_human_uid(&self, uid: u32) -> bool {
        self.human_uids.contains(&uid)
    }
}

// ---------------------------------------------------------------------------
// Profile file path
// ---------------------------------------------------------------------------

fn profile_path(data_dir: &Path) -> PathBuf {
    data_dir.join("environment-profile.json")
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load the environment profile from disk. Returns None if not found.
pub(crate) fn load_profile(data_dir: &Path) -> Option<EnvironmentProfile> {
    let path = profile_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(profile) => Some(profile),
            Err(e) => {
                warn!("failed to parse environment profile: {e:#}");
                None
            }
        },
        Err(_) => None,
    }
}

fn save_profile(data_dir: &Path, profile: &EnvironmentProfile) -> anyhow::Result<()> {
    let path = profile_path(data_dir);
    let json = serde_json::to_string_pretty(profile)?;
    std::fs::write(&path, json)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap profiling
// ---------------------------------------------------------------------------

/// Generate and save the environment profile. Runs once at first boot.
pub(crate) fn bootstrap_profile(data_dir: &Path, _cfg: &EnvironmentConfig) -> EnvironmentProfile {
    let (platform, provider) = detect_platform();
    let human_uids = detect_human_uids();
    let services = detect_services();
    let crons = detect_crons();

    let profile = EnvironmentProfile {
        platform,
        provider,
        human_uids,
        services,
        crons,
        profiled_at: chrono::Utc::now(),
    };

    if let Err(e) = save_profile(data_dir, &profile) {
        warn!("failed to save environment profile: {e:#}");
    } else {
        info!(
            platform = %profile.platform,
            provider = %profile.provider,
            human_uids = ?profile.human_uids,
            services_count = profile.services.len(),
            crons_count = profile.crons.len(),
            "environment profile bootstrapped"
        );
    }

    profile
}

/// Load existing profile or bootstrap a new one.
pub(crate) fn load_or_bootstrap(data_dir: &Path, cfg: &EnvironmentConfig) -> EnvironmentProfile {
    if !cfg.auto_profile {
        return EnvironmentProfile::default();
    }

    if let Some(profile) = load_profile(data_dir) {
        info!(
            platform = %profile.platform,
            provider = %profile.provider,
            "loaded environment profile from disk"
        );
        return profile;
    }

    bootstrap_profile(data_dir, cfg)
}

// ---------------------------------------------------------------------------
// Platform detection (cloud/VM/bare metal)
// ---------------------------------------------------------------------------

fn detect_platform() -> (String, String) {
    // Read DMI product name — available on most Linux systems
    let product_name = read_dmi("product_name");
    let sys_vendor = read_dmi("sys_vendor");
    let bios_vendor = read_dmi("bios_vendor");

    // Check for known cloud/VM signatures
    let combined = format!(
        "{} {} {}",
        product_name.to_lowercase(),
        sys_vendor.to_lowercase(),
        bios_vendor.to_lowercase()
    );

    let (platform, provider) = if combined.contains("oracle") || combined.contains("oci") {
        ("cloud_vps", "oracle")
    } else if combined.contains("amazon") || combined.contains("aws") || combined.contains("ec2") {
        ("cloud_vps", "aws")
    } else if combined.contains("google") || combined.contains("gce") {
        ("cloud_vps", "gcp")
    } else if combined.contains("microsoft") || combined.contains("azure") || combined.contains("hyper-v") {
        ("cloud_vps", "azure")
    } else if combined.contains("digitalocean") {
        ("cloud_vps", "digitalocean")
    } else if combined.contains("hetzner") {
        ("cloud_vps", "hetzner")
    } else if combined.contains("linode") || combined.contains("akamai") {
        ("cloud_vps", "linode")
    } else if combined.contains("vultr") {
        ("cloud_vps", "vultr")
    } else if combined.contains("ovh") {
        ("cloud_vps", "ovh")
    } else if combined.contains("vmware") || combined.contains("virtualbox") || combined.contains("qemu") || combined.contains("kvm") || combined.contains("xen") || combined.contains("bhyve") {
        ("vm", "unknown")
    } else {
        ("bare_metal", "none")
    };

    (platform.into(), provider.into())
}

fn read_dmi(field: &str) -> String {
    let path = format!("/sys/class/dmi/id/{field}");
    std::fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Human UID detection
// ---------------------------------------------------------------------------

fn detect_human_uids() -> Vec<u32> {
    let content = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let nologin_shells = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"];

    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                return None;
            }
            let uid: u32 = parts[2].parse().ok()?;
            let shell = parts[6];

            // Human users: uid >= 1000, with a login shell (not nologin/false)
            if uid >= 1000 && uid < 65534 && !nologin_shells.iter().any(|s| shell.ends_with(s)) {
                Some(uid)
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Service detection
// ---------------------------------------------------------------------------

fn detect_services() -> Vec<String> {
    let output = match std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    if !output.status.success() {
        return vec![];
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // Format: "unit.service loaded active running description..."
            line.split_whitespace().next().map(|unit| {
                unit.strip_suffix(".service")
                    .unwrap_or(unit)
                    .to_string()
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cron detection
// ---------------------------------------------------------------------------

fn detect_crons() -> Vec<String> {
    let mut crons = Vec::new();

    // System crontab
    if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                crons.push(format!("system: {trimmed}"));
            }
        }
    }

    // User crontabs for root
    let output = std::process::Command::new("crontab")
        .args(["-l"])
        .output();
    if let Ok(o) = output {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    crons.push(format!("root: {trimmed}"));
                }
            }
        }
    }

    // /etc/cron.d/
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                crons.push(format!("cron.d: {name}"));
            }
        }
    }

    crons
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_unknown() {
        let p = EnvironmentProfile::default();
        assert_eq!(p.platform, "unknown");
        assert!(!p.is_cloud());
    }

    #[test]
    fn cloud_profile_is_detected() {
        let mut p = EnvironmentProfile::default();
        p.platform = "cloud_vps".into();
        assert!(p.is_cloud());
    }

    #[test]
    fn vm_profile_is_cloud() {
        let mut p = EnvironmentProfile::default();
        p.platform = "vm".into();
        assert!(p.is_cloud());
    }

    #[test]
    fn human_uid_check() {
        let mut p = EnvironmentProfile::default();
        p.human_uids = vec![1000, 1001];
        assert!(p.is_human_uid(1000));
        assert!(!p.is_human_uid(0));
    }

    #[test]
    fn save_and_load_profile() {
        let dir = tempfile::tempdir().unwrap();
        let profile = EnvironmentProfile {
            platform: "cloud_vps".into(),
            provider: "oracle".into(),
            human_uids: vec![1001],
            services: vec!["nginx".into()],
            crons: vec!["root: certbot renew".into()],
            profiled_at: chrono::Utc::now(),
        };

        save_profile(dir.path(), &profile).unwrap();
        let loaded = load_profile(dir.path()).unwrap();

        assert_eq!(loaded.platform, "cloud_vps");
        assert_eq!(loaded.provider, "oracle");
        assert_eq!(loaded.human_uids, vec![1001]);
        assert_eq!(loaded.services, vec!["nginx"]);
    }

    #[test]
    fn load_missing_profile_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_profile(dir.path()).is_none());
    }

    #[test]
    fn bootstrap_creates_profile_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig::default();
        let profile = bootstrap_profile(dir.path(), &cfg);

        // Profile should be saved to disk
        assert!(profile_path(dir.path()).exists());
        // Platform should be detected (at least not panic)
        assert!(!profile.platform.is_empty());
    }

    #[test]
    fn load_or_bootstrap_uses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig::default();

        // Bootstrap first
        let p1 = bootstrap_profile(dir.path(), &cfg);

        // Load should return existing
        let p2 = load_or_bootstrap(dir.path(), &cfg);
        assert_eq!(p1.platform, p2.platform);
        assert_eq!(p1.provider, p2.provider);
    }

    #[test]
    fn load_or_bootstrap_respects_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig {
            auto_profile: false,
            ..Default::default()
        };

        let profile = load_or_bootstrap(dir.path(), &cfg);
        assert_eq!(profile.platform, "unknown");
        // No file should be created
        assert!(!profile_path(dir.path()).exists());
    }
}
