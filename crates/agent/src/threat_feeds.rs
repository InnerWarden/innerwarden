//! Threat Feed Ingestion — STIX/TAXII and VirusTotal integration.
//!
//! Polls external threat intelligence feeds for indicators (IPs, domains,
//! file hashes) and stores them in a local lookup table for enrichment.
//!
//! Supported feeds:
//! - **VirusTotal**: Check SHA-256 hashes of unknown binaries.
//! - **Generic IOC feed**: Poll a URL returning newline-separated IOCs.
//!
//! Configuration in agent.toml:
//! ```toml
//! [threat_feeds]
//! enabled = true
//! virustotal_api_key = ""  # or VT_API_KEY env var
//! ioc_feed_urls = ["https://example.com/iocs.txt"]
//! poll_interval_secs = 3600
//! ```

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Feed state
// ---------------------------------------------------------------------------

/// Local IOC database populated from external feeds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatFeedState {
    /// Malicious IP addresses from feeds.
    pub malicious_ips: HashSet<String>,
    /// Malicious domains from feeds.
    pub malicious_domains: HashSet<String>,
    /// Malicious file hashes (SHA-256) from feeds.
    pub malicious_hashes: HashSet<String>,
    /// Last poll timestamp per feed URL.
    pub last_poll: HashMap<String, DateTime<Utc>>,
    /// Total IOCs loaded.
    pub total_iocs: usize,
}

/// Result from a VirusTotal hash check.
#[derive(Debug, Clone, Serialize)]
pub struct VtResult {
    pub sha256: String,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub is_malicious: bool,
}

// ---------------------------------------------------------------------------
// Feed client
// ---------------------------------------------------------------------------

pub struct ThreatFeedClient {
    http: reqwest::Client,
    vt_api_key: String,
    ioc_feed_urls: Vec<String>,
    state: ThreatFeedState,
}

impl ThreatFeedClient {
    pub fn new(vt_api_key: String, ioc_feed_urls: Vec<String>, data_dir: &Path) -> Self {
        let state = load_state(data_dir);
        info!(
            ips = state.malicious_ips.len(),
            domains = state.malicious_domains.len(),
            hashes = state.malicious_hashes.len(),
            "threat feed state loaded"
        );
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            vt_api_key,
            ioc_feed_urls,
            state,
        }
    }

    /// Check if an IP is in the threat feed database.
    pub fn is_known_malicious_ip(&self, ip: &str) -> bool {
        self.state.malicious_ips.contains(ip)
    }

    /// Check if a domain is in the threat feed database.
    #[allow(dead_code)]
    pub fn is_known_malicious_domain(&self, domain: &str) -> bool {
        self.state.malicious_domains.contains(domain)
    }

    /// Check if a file hash is in the threat feed database.
    #[allow(dead_code)]
    pub fn is_known_malicious_hash(&self, hash: &str) -> bool {
        self.state.malicious_hashes.contains(hash)
    }

    /// Check a SHA-256 hash against VirusTotal API.
    /// Returns None if VT is not configured or the check fails.
    pub async fn check_virustotal(&self, sha256: &str) -> Option<VtResult> {
        if self.vt_api_key.is_empty() {
            return None;
        }

        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.vt_api_key)
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            debug!(status = %resp.status(), "VirusTotal check failed");
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let stats = body
            .pointer("/data/attributes/last_analysis_stats")?;

        let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
        let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;

        Some(VtResult {
            sha256: sha256.to_string(),
            malicious,
            suspicious,
            undetected,
            is_malicious: malicious >= 3, // 3+ engines = malicious
        })
    }

    /// Poll all configured IOC feeds and update the local database.
    pub async fn poll_feeds(&mut self) {
        for url in self.ioc_feed_urls.clone() {
            if let Err(e) = self.poll_single_feed(&url).await {
                warn!(url = %url, "failed to poll IOC feed: {e}");
            }
        }
        self.state.total_iocs = self.state.malicious_ips.len()
            + self.state.malicious_domains.len()
            + self.state.malicious_hashes.len();
    }

    async fn poll_single_feed(&mut self, url: &str) -> anyhow::Result<()> {
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {}", resp.status());
        }
        let body = resp.text().await?;

        let mut added = 0usize;
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // Classify the IOC
            if is_ip_like(trimmed) {
                if self.state.malicious_ips.insert(trimmed.to_string()) {
                    added += 1;
                }
            } else if is_hash_like(trimmed) {
                if self.state.malicious_hashes.insert(trimmed.to_lowercase()) {
                    added += 1;
                }
            } else if is_domain_like(trimmed) {
                if self.state.malicious_domains.insert(trimmed.to_lowercase()) {
                    added += 1;
                }
            }
        }

        self.state
            .last_poll
            .insert(url.to_string(), Utc::now());
        info!(url = %url, added, "IOC feed polled");
        Ok(())
    }

    /// Persist state to disk.
    pub fn save(&self, data_dir: &Path) {
        let path = data_dir.join("threat-feeds.json");
        match serde_json::to_string(&self.state) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write threat-feeds.json: {e}");
                }
            }
            Err(e) => warn!("failed to serialize threat feeds: {e}"),
        }
    }

    /// Get the current state for API exposure.
    pub fn state(&self) -> &ThreatFeedState {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_ip_like(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn is_hash_like(s: &str) -> bool {
    (s.len() == 64 || s.len() == 40 || s.len() == 32) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_domain_like(s: &str) -> bool {
    s.contains('.') && !s.contains(' ') && !s.starts_with("http") && !is_ip_like(s)
}

fn load_state(data_dir: &Path) -> ThreatFeedState {
    let path = data_dir.join("threat-feeds.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return ThreatFeedState::default();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Resolve VT API key from config or environment.
pub fn resolve_vt_api_key(config_key: &str) -> String {
    if !config_key.is_empty() {
        return config_key.to_string();
    }
    std::env::var("VT_API_KEY")
        .or_else(|_| std::env::var("VIRUSTOTAL_API_KEY"))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_iocs() {
        assert!(is_ip_like("1.2.3.4"));
        assert!(is_ip_like("2001:db8::1"));
        assert!(!is_ip_like("example.com"));

        assert!(is_hash_like("a" .repeat(64).as_str()));
        assert!(is_hash_like("b".repeat(40).as_str())); // SHA-1
        assert!(!is_hash_like("short"));

        assert!(is_domain_like("evil.com"));
        assert!(is_domain_like("sub.evil.com"));
        assert!(!is_domain_like("1.2.3.4"));
        assert!(!is_domain_like("http://evil.com"));
    }

    #[test]
    fn state_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut state = ThreatFeedState::default();
        state.malicious_ips.insert("1.2.3.4".into());
        state.malicious_domains.insert("evil.com".into());
        state.malicious_hashes.insert("aa".repeat(32));

        let path = dir.path().join("threat-feeds.json");
        std::fs::write(&path, serde_json::to_string(&state).unwrap()).unwrap();

        let loaded = load_state(dir.path());
        assert!(loaded.malicious_ips.contains("1.2.3.4"));
        assert!(loaded.malicious_domains.contains("evil.com"));
    }

    #[test]
    fn empty_state_for_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let state = load_state(dir.path());
        assert!(state.malicious_ips.is_empty());
    }
}
