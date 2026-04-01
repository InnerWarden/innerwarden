//! Cloud provider IP safelist — IPs that should NOT be auto-blocked.
//!
//! Major cloud providers (Google Cloud, AWS, Cloudflare, Azure, Oracle) publish
//! their IP ranges. Attackers can use these, but auto-blocking them risks
//! blocking legitimate traffic (Googlebot, CDN, APIs).
//!
//! Policy: DETECT but DON'T AUTO-BLOCK. Let AI evaluate with context.
//! The AI can still decide to block if the evidence is strong enough.

use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::info;

/// Parsed CIDR range for fast matching.
struct CidrRange {
    base: u32,
    mask: u32,
}

impl CidrRange {
    fn from_str(cidr: &str) -> Option<Self> {
        let (base_str, prefix_str) = cidr.split_once('/')?;
        let prefix_len: u32 = prefix_str.parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let base: IpAddr = base_str.parse().ok()?;
        let base_u32 = match base {
            IpAddr::V4(v4) => u32::from(v4),
            _ => return None,
        };
        let shift = 32u32.saturating_sub(prefix_len);
        let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
        Some(Self {
            base: base_u32 & mask,
            mask,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }
}

/// Cloud provider safelist — loaded once, checked on every auto-block decision.
static CLOUD_RANGES: OnceLock<Vec<CidrRange>> = OnceLock::new();
static CLOUD_PROVIDER_COUNT: OnceLock<usize> = OnceLock::new();

/// Cloudflare IPv4 ranges (from https://www.cloudflare.com/ips-v4).
/// Updated 2026-04-01. These rarely change.
const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
];

/// Major cloud provider CIDR ranges that should not be auto-blocked.
/// These are broad ranges — individual IPs may still be malicious,
/// but auto-blocking risks collateral damage.
const CLOUD_PROVIDER_RANGES: &[&str] = &[
    // Google Cloud Platform (major allocations)
    "34.0.0.0/9",      // 34.0-127.x — GCE
    "35.184.0.0/13",   // 35.184-191.x — GCE
    "35.192.0.0/12",   // 35.192-207.x — GCE
    "35.208.0.0/12",   // 35.208-223.x — GCE
    "35.224.0.0/12",   // 35.224-239.x — GCE
    "35.240.0.0/13",   // 35.240-247.x — GCE
    "130.211.0.0/16",  // GCE load balancers
    "142.250.0.0/15",  // Google services
    "172.217.0.0/16",  // Google services
    "216.58.192.0/19", // Google services
    "209.85.128.0/17", // Google mail/services
    // AWS (major allocations)
    "3.0.0.0/9",     // 3.0-127.x — EC2
    "13.0.0.0/8",    // 13.x — EC2 various
    "15.0.0.0/11",   // 15.0-31.x — EC2
    "18.0.0.0/10",   // 18.0-63.x — EC2
    "44.192.0.0/11", // 44.192-223.x — EC2
    "52.0.0.0/11",   // 52.0-31.x — EC2
    "54.0.0.0/8",    // 54.x — EC2
    "99.80.0.0/12",  // 99.80-95.x — EC2
    // Azure (major allocations)
    "20.0.0.0/11",    // 20.0-31.x — Azure
    "40.64.0.0/10",   // 40.64-127.x — Azure
    "52.128.0.0/10",  // 52.128-191.x — Azure
    "104.40.0.0/13",  // 104.40-47.x — Azure
    "168.61.0.0/16",  // Azure
    "191.232.0.0/13", // Azure
    // Oracle Cloud
    "129.146.0.0/16", // OCI
    "130.35.0.0/16",  // OCI
    "130.61.0.0/16",  // OCI
    "132.145.0.0/16", // OCI
    "134.70.0.0/16",  // OCI
    "140.204.0.0/16", // OCI
    "140.238.0.0/16", // OCI
    "144.24.0.0/14",  // OCI
    "150.136.0.0/13", // OCI
    "152.67.0.0/16",  // OCI
    "152.70.0.0/15",  // OCI
    // DigitalOcean
    "64.227.0.0/16",
    "134.209.0.0/16",
    "157.230.0.0/16",
    "159.65.0.0/16",
    "159.89.0.0/16",
    "161.35.0.0/16",
    "164.90.0.0/16",
    "165.22.0.0/16",
    "165.227.0.0/16",
    "167.71.0.0/16",
    "167.172.0.0/16",
    "174.138.0.0/16",
    "178.128.0.0/16",
    "188.166.0.0/16",
    "206.189.0.0/16",
    "209.97.0.0/16",
    "209.122.0.0/16",
    // Hetzner
    "49.12.0.0/14",
    "78.46.0.0/15",
    "88.198.0.0/16",
    "88.99.0.0/16",
    "95.216.0.0/15",
    "116.202.0.0/15",
    "116.203.0.0/16",
    "128.140.0.0/16",
    "135.181.0.0/16",
    "136.243.0.0/16",
    "138.201.0.0/16",
    "142.132.0.0/16",
    "148.251.0.0/16",
    "157.90.0.0/16",
    "159.69.0.0/16",
    "162.55.0.0/16",
    "167.235.0.0/16",
    "168.119.0.0/16",
    "176.9.0.0/16",
    "178.63.0.0/16",
    "195.201.0.0/16",
    "213.133.96.0/19",
    "213.239.192.0/18",
];

/// Initialize the cloud safelist. Call once at agent startup.
pub fn init() {
    let mut ranges = Vec::new();

    for cidr in CLOUDFLARE_RANGES.iter().chain(CLOUD_PROVIDER_RANGES.iter()) {
        if let Some(r) = CidrRange::from_str(cidr) {
            ranges.push(r);
        }
    }

    let count = ranges.len();
    let _ = CLOUD_RANGES.set(ranges);
    let _ = CLOUD_PROVIDER_COUNT.set(count);
    info!(ranges = count, "Cloud provider safelist loaded");
}

/// Check if an IP belongs to a known cloud provider.
/// Returns true if the IP should NOT be auto-blocked.
pub fn is_cloud_provider_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        _ => return false,
    };

    if let Some(ranges) = CLOUD_RANGES.get() {
        ranges.iter().any(|r| r.contains(ip_u32))
    } else {
        false
    }
}

/// Get the provider name for logging (best-effort, broad match).
pub fn identify_provider(ip_str: &str) -> Option<&'static str> {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return None;
    };
    let first_octet = match ip {
        IpAddr::V4(v4) => v4.octets()[0],
        _ => return None,
    };

    // Broad heuristic based on first octet
    match first_octet {
        34 | 35 | 130 | 142 | 172 | 216 | 209 => Some("Google Cloud"),
        3 | 13 | 15 | 18 | 44 | 52 | 54 | 99 => Some("AWS"),
        20 | 40 | 104 | 168 | 191 => Some("Azure"),
        129 | 132 | 134 | 140 | 144 | 150 | 152 => Some("Oracle Cloud"),
        64 | 157 | 159 | 161 | 164 | 165 | 167 | 174 | 178 | 188 | 206 => Some("DigitalOcean"),
        173 | 108 | 190 | 162 | 141 | 197 | 198 => Some("Cloudflare"),
        49 | 78 | 88 | 95 | 116 | 128 | 135 | 136 | 138 | 148 | 176 | 195 | 213 => Some("Hetzner"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_detected() {
        init();
        assert!(is_cloud_provider_ip("104.16.0.1"));
        assert!(is_cloud_provider_ip("172.64.1.1"));
        assert!(is_cloud_provider_ip("104.23.217.2"));
    }

    #[test]
    fn google_detected() {
        init();
        assert!(is_cloud_provider_ip("34.95.197.36"));
        assert!(is_cloud_provider_ip("35.200.190.223"));
        assert!(is_cloud_provider_ip("142.250.1.1"));
    }

    #[test]
    fn aws_detected() {
        init();
        assert!(is_cloud_provider_ip("3.5.1.1"));
        assert!(is_cloud_provider_ip("52.1.1.1"));
        assert!(is_cloud_provider_ip("54.200.1.1"));
    }

    #[test]
    fn random_ip_not_cloud() {
        init();
        assert!(!is_cloud_provider_ip("93.152.217.51")); // real attacker
        assert!(!is_cloud_provider_ip("1.2.3.4"));
        assert!(!is_cloud_provider_ip("185.143.223.100"));
    }

    #[test]
    fn provider_identified() {
        assert_eq!(identify_provider("34.95.197.36"), Some("Google Cloud"));
        assert_eq!(identify_provider("52.1.1.1"), Some("AWS"));
        assert_eq!(identify_provider("20.12.41.6"), Some("Azure"));
    }
}
