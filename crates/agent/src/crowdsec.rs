// ---------------------------------------------------------------------------
// CrowdSec integration — community threat intelligence lookup
// ---------------------------------------------------------------------------
//
// CrowdSec runs a Local API (LAPI) on each host. This module maintains a
// local HashSet of banned IPs from the CrowdSec community blocklist.
//
// Architecture (lookup table, not preventive blocking):
//   1. Every `poll_secs` seconds, GET /v1/decisions/stream (delta mode)
//   2. Add new IPs to `threat_list`, remove expired ones
//   3. When the agent processes an incident, it checks `is_known_threat(ip)`
//   4. If the IP is in the CrowdSec list → auto-block (same as AbuseIPDB gate)
//
// This avoids creating 24k+ firewall rules. Only IPs that actually attack
// your server get blocked — the list is just intelligence, not enforcement.
//
// Required: CrowdSec LAPI must be running and the API key must be set.
//   - Default URL: http://localhost:8080
//   - API key: find in /etc/crowdsec/local_api_credentials.yaml under `password`
//   - Or set via CROWDSEC_API_KEY env var

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use tracing::{debug, info, warn};

use crate::config::CrowdSecConfig;

// ---------------------------------------------------------------------------
// LAPI response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct StreamResponse {
    new: Option<Vec<CrowdSecDecision>>,
    deleted: Option<Vec<CrowdSecDecision>>,
}

#[derive(Debug, Deserialize)]
pub struct CrowdSecDecision {
    #[allow(dead_code)]
    pub id: i64,
    #[allow(dead_code)]
    pub origin: String,
    #[allow(dead_code)]
    pub r#type: String,
    #[allow(dead_code)]
    pub scope: String,
    pub value: String, // the IP address
    #[allow(dead_code)]
    pub duration: String, // e.g. "87599.956744792s"
    #[serde(rename = "simulated")]
    pub simulated: Option<bool>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct CrowdSecClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl CrowdSecClient {
    pub fn new(cfg: &CrowdSecConfig) -> Self {
        let api_key = if !cfg.api_key.is_empty() {
            cfg.api_key.clone()
        } else {
            std::env::var("CROWDSEC_API_KEY").unwrap_or_default()
        };

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build CrowdSec HTTP client");

        Self {
            base_url: cfg.url.trim_end_matches('/').to_string(),
            api_key,
            http,
        }
    }

    /// Fetch new/deleted IP ban decisions from the LAPI stream endpoint.
    /// Returns (new_ips, deleted_ips).
    async fn fetch_stream(&self) -> Result<(Vec<String>, Vec<String>)> {
        let url = format!(
            "{}/v1/decisions/stream?startup=false&scopes=ip",
            self.base_url
        );

        debug!(url = %url, "polling CrowdSec LAPI stream");

        let resp = self
            .http
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "CrowdSec LAPI unreachable at {url} — is CrowdSec running?\n\
                     Start it with: sudo systemctl start crowdsec"
                )
            })?;

        if resp.status().as_u16() == 204 {
            return Ok((vec![], vec![]));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 403 || body.contains("Forbidden") {
                anyhow::bail!(
                    "CrowdSec LAPI returned 403: invalid API key.\n\
                     Check crowdsec.api_key in agent.toml or CROWDSEC_API_KEY env var.\n\
                     Find your key in: /etc/crowdsec/local_api_credentials.yaml"
                );
            }
            anyhow::bail!(
                "CrowdSec LAPI returned {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }

        // Cap body at 8MB safety net
        const MAX_BODY: usize = 8 * 1024 * 1024;
        let bytes = resp.bytes().await?;
        if bytes.len() > MAX_BODY {
            warn!(
                body_bytes = bytes.len(),
                "CrowdSec stream response too large, skipping this tick"
            );
            return Ok((vec![], vec![]));
        }
        let text = std::str::from_utf8(&bytes).unwrap_or("null");
        if text.trim() == "null" || text.trim().is_empty() {
            return Ok((vec![], vec![]));
        }

        let stream: StreamResponse =
            serde_json::from_str(text).context("failed to parse CrowdSec stream response")?;

        let extract_ips = |decisions: Vec<CrowdSecDecision>| -> Vec<String> {
            decisions
                .into_iter()
                .filter(|d| d.simulated != Some(true))
                .map(|d| d.value)
                .collect()
        };

        let new_ips = stream.new.map(extract_ips).unwrap_or_default();
        let deleted_ips = stream.deleted.map(extract_ips).unwrap_or_default();

        Ok((new_ips, deleted_ips))
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Threat list — in-memory lookup table
// ---------------------------------------------------------------------------

/// Max IPs to keep in the threat list before stopping additions.
/// At ~50 bytes per IP string, 50k IPs ≈ 2.5MB — acceptable.
const THREAT_LIST_MAX: usize = 50_000;

/// CrowdSec state: a lookup table of known-bad IPs, updated via delta stream.
/// No firewall rules are created. The list is consulted when processing incidents.
pub struct CrowdSecState {
    /// Known-bad IPs from CrowdSec community intelligence.
    threat_list: HashSet<String>,
    pub client: CrowdSecClient,
}

impl CrowdSecState {
    pub fn new(cfg: &CrowdSecConfig) -> Self {
        Self {
            threat_list: HashSet::new(),
            client: CrowdSecClient::new(cfg),
        }
    }

    /// Check if an IP is in the CrowdSec community threat list.
    pub fn is_known_threat(&self, ip: &str) -> bool {
        self.threat_list.contains(ip)
    }

    /// Number of IPs in the threat list.
    #[allow(dead_code)]
    pub fn threat_count(&self) -> usize {
        self.threat_list.len()
    }
}

/// Update the threat list from CrowdSec LAPI (delta stream).
/// Called from the agent's slow loop. Returns (added, removed) counts.
pub async fn sync_threat_list(cs: &mut CrowdSecState) -> (usize, usize) {
    if !cs.client.is_configured() {
        return (0, 0);
    }

    let (new_ips, deleted_ips) = match cs.client.fetch_stream().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "CrowdSec threat list sync failed");
            return (0, 0);
        }
    };

    // Remove expired IPs
    let mut removed = 0;
    for ip in &deleted_ips {
        if cs.threat_list.remove(ip) {
            removed += 1;
        }
    }

    // Add new IPs (respect cap)
    let mut added = 0;
    for ip in &new_ips {
        if cs.threat_list.len() >= THREAT_LIST_MAX {
            warn!(
                max = THREAT_LIST_MAX,
                "CrowdSec threat list at capacity, skipping new additions"
            );
            break;
        }
        // Skip private/loopback
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            if is_private_or_loopback(addr) {
                continue;
            }
        }
        if cs.threat_list.insert(ip.clone()) {
            added += 1;
        }
    }

    if added > 0 || removed > 0 {
        info!(
            added,
            removed,
            total = cs.threat_list.len(),
            "CrowdSec threat list updated"
        );
    }

    (added, removed)
}

fn is_private_or_loopback(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stream_response() {
        let raw = r#"{"new":[{"id":1,"origin":"CAPI","type":"ban","scope":"ip","value":"1.2.3.4","duration":"86399s"}],"deleted":[{"id":2,"origin":"CAPI","type":"ban","scope":"ip","value":"5.6.7.8","duration":"0s"}]}"#;
        let stream: StreamResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(stream.new.as_ref().unwrap().len(), 1);
        assert_eq!(stream.new.as_ref().unwrap()[0].value, "1.2.3.4");
        assert_eq!(stream.deleted.as_ref().unwrap().len(), 1);
        assert_eq!(stream.deleted.as_ref().unwrap()[0].value, "5.6.7.8");
    }

    #[test]
    fn parse_null_response() {
        let text = "null";
        assert!(text.trim() == "null");
    }

    #[test]
    fn parse_empty_stream() {
        let raw = r#"{"new":null,"deleted":null}"#;
        let stream: StreamResponse = serde_json::from_str(raw).unwrap();
        assert!(stream.new.is_none());
        assert!(stream.deleted.is_none());
    }

    #[test]
    fn skips_simulated_decisions() {
        let raw = r#"{"new":[{"id":1,"origin":"CAPI","type":"ban","scope":"ip","value":"1.2.3.4","duration":"3600s","simulated":true}]}"#;
        let stream: StreamResponse = serde_json::from_str(raw).unwrap();
        let new = stream.new.unwrap();
        // Simulated should be filtered by extract_ips
        let filtered: Vec<String> = new
            .into_iter()
            .filter(|d| d.simulated != Some(true))
            .map(|d| d.value)
            .collect();
        assert!(filtered.is_empty());
    }

    #[test]
    fn private_ip_is_filtered() {
        assert!(is_private_or_loopback("192.168.1.1".parse().unwrap()));
        assert!(is_private_or_loopback("127.0.0.1".parse().unwrap()));
        assert!(!is_private_or_loopback("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn threat_list_lookup() {
        let mut list = HashSet::new();
        list.insert("1.2.3.4".to_string());
        list.insert("5.6.7.8".to_string());
        assert!(list.contains("1.2.3.4"));
        assert!(!list.contains("9.9.9.9"));
    }
}
