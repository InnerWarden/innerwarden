//! DNS query capture collector.
//!
//! Captures DNS queries from network traffic via AF_PACKET raw socket
//! (same approach as JA3/JA4 TLS fingerprinting). Extracts queried domain
//! names and emits them as `dns.query` events for the dns_tunneling detector.
//!
//! Eliminates the dependency on Suricata for DNS visibility.
//!
//! Requires: Linux, CAP_NET_RAW capability.
//! Falls back gracefully on non-Linux or when unprivileged.

use tokio::sync::mpsc;
use tracing::info;

use innerwarden_core::event::Event;

// ---------------------------------------------------------------------------
// DNS parsing
// ---------------------------------------------------------------------------

// DNS query fields are extracted inline during packet parsing
// rather than constructing a struct, to avoid allocation overhead.

/// Query type names for display.
#[cfg(any(target_os = "linux", test))]
fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Parse a DNS domain name from a packet buffer.
/// DNS names are encoded as length-prefixed labels: \x03www\x06google\x03com\x00
#[cfg(any(target_os = "linux", test))]
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut total_len = 0;
    let max_labels = 128; // prevent infinite loops

    for _ in 0..max_labels {
        if offset >= data.len() {
            return None;
        }

        let len = data[offset] as usize;

        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            // We don't follow compression pointers for simplicity
            total_len += 2;
            break;
        }

        if len == 0 {
            // End of name
            total_len += 1;
            break;
        }

        offset += 1;
        total_len += 1 + len;

        if offset + len > data.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&data[offset..offset + len]) {
            labels.push(label.to_string());
        } else {
            return None;
        }

        offset += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some((labels.join("."), total_len))
}

/// Parse a DNS query from a UDP payload.
#[cfg(any(target_os = "linux", test))]
fn parse_dns_query(udp_payload: &[u8]) -> Option<(u16, String, u16)> {
    // DNS header is 12 bytes minimum
    if udp_payload.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);

    // QR bit (bit 15) must be 0 for a query
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([udp_payload[4], udp_payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse first question (starts at offset 12)
    let (domain, name_len) = parse_dns_name(udp_payload, 12)?;

    // After the name: QTYPE (2 bytes) + QCLASS (2 bytes)
    let qtype_offset = 12 + name_len;
    if qtype_offset + 4 > udp_payload.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([udp_payload[qtype_offset], udp_payload[qtype_offset + 1]]);

    Some((id, domain, qtype))
}

// ---------------------------------------------------------------------------
// Packet parsing (Ethernet → IP → UDP → DNS)
// ---------------------------------------------------------------------------

/// Parse Ethernet + IP + UDP headers, return (src_ip, src_port, dst_ip, dst_port, udp_payload).
#[cfg(target_os = "linux")]
fn parse_packet(raw: &[u8]) -> Option<(String, u16, String, u16, &[u8])> {
    // Ethernet header: 14 bytes
    if raw.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

    let ip_offset = match ethertype {
        0x0800 => 14,     // IPv4
        0x8100 => 18,     // VLAN tagged
        _ => return None, // Skip IPv6 for now
    };

    if raw.len() < ip_offset + 20 {
        return None;
    }

    let ip_header = &raw[ip_offset..];
    let ihl = ((ip_header[0] & 0x0F) as usize) * 4;
    let protocol = ip_header[9];

    // Only UDP (17)
    if protocol != 17 {
        return None;
    }

    let src_ip = format!(
        "{}.{}.{}.{}",
        ip_header[12], ip_header[13], ip_header[14], ip_header[15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        ip_header[16], ip_header[17], ip_header[18], ip_header[19]
    );

    let udp_offset = ip_offset + ihl;
    if raw.len() < udp_offset + 8 {
        return None;
    }

    let udp_header = &raw[udp_offset..];
    let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
    let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);

    // We want DNS queries: dst_port == 53
    if dst_port != 53 {
        return None;
    }

    let payload = &raw[udp_offset + 8..];
    Some((src_ip, src_port, dst_ip, dst_port, payload))
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

// COOLDOWN_SECS and MAX_TRACKED defined inside run_linux()

pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tx, host);
        info!("dns_capture: not on Linux, skipping");
    }

    #[cfg(target_os = "linux")]
    {
        run_linux(tx, host).await;
    }
}

#[cfg(target_os = "linux")]
async fn run_linux(tx: mpsc::Sender<Event>, host: String) {
    use chrono::{DateTime, Duration, Utc};
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use std::collections::HashMap;
    use tracing::warn;

    const COOLDOWN_SECS: i64 = 10;
    const MAX_TRACKED: usize = 5000;

    // Create AF_PACKET raw socket (requires CAP_NET_RAW)
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if fd < 0 {
        warn!("dns_capture: failed to create AF_PACKET socket (need CAP_NET_RAW)");
        return;
    }

    info!("dns_capture: listening for DNS queries on all interfaces");

    let mut buf = [0u8; 65536];
    let mut cooldown: HashMap<String, DateTime<Utc>> = HashMap::new();

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n <= 0 {
            tokio::task::yield_now().await;
            continue;
        }

        let raw = &buf[..n as usize];

        let (src_ip, src_port, dst_ip, _dst_port, udp_payload) = match parse_packet(raw) {
            Some(p) => p,
            None => continue,
        };

        let (tx_id, domain, qtype) = match parse_dns_query(udp_payload) {
            Some(q) => q,
            None => continue,
        };

        // Skip empty or root domain
        if domain.is_empty() || domain == "." {
            continue;
        }

        // Skip common internal queries
        if domain.ends_with(".local")
            || domain.ends_with(".internal")
            || domain.ends_with(".localhost")
        {
            continue;
        }

        // Cooldown per (src_ip, domain)
        let now = Utc::now();
        let key = format!("{}:{}", src_ip, domain);
        if let Some(&last) = cooldown.get(&key) {
            if (now - last).num_seconds() < COOLDOWN_SECS {
                continue;
            }
        }
        cooldown.insert(key, now);

        // Prune cooldown map
        if cooldown.len() > MAX_TRACKED {
            let cutoff = now - Duration::seconds(COOLDOWN_SECS);
            cooldown.retain(|_, v| *v > cutoff);
        }

        let event = Event {
            ts: now,
            host: host.clone(),
            source: "dns_capture".to_string(),
            kind: "dns.query".to_string(),
            severity: Severity::Info,
            summary: format!(
                "DNS {} query for {} from {} (server: {})",
                qtype_name(qtype),
                domain,
                src_ip,
                dst_ip
            ),
            details: serde_json::json!({
                "domain": domain,
                "qtype": qtype,
                "qtype_name": qtype_name(qtype),
                "src_ip": src_ip,
                "src_port": src_port,
                "dns_server": dst_ip,
                "tx_id": tx_id,
            }),
            tags: vec!["dns".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(&src_ip)],
        };

        let _ = tx.send(event).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_name_simple() {
        // \x03www\x06google\x03com\x00
        let data = b"\x03www\x06google\x03com\x00";
        let (name, len) = parse_dns_name(data, 0).unwrap();
        assert_eq!(name, "www.google.com");
        assert_eq!(len, 16); // 1+3+1+6+1+3+1
    }

    #[test]
    fn parse_dns_name_single_label() {
        let data = b"\x04test\x00";
        let (name, _) = parse_dns_name(data, 0).unwrap();
        assert_eq!(name, "test");
    }

    #[test]
    fn parse_dns_name_empty() {
        let data = b"\x00";
        assert!(parse_dns_name(data, 0).is_none());
    }

    #[test]
    fn parse_dns_query_valid() {
        // Minimal DNS query for "example.com" type A
        let mut pkt = Vec::new();
        // Header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1
        pkt.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: \x07example\x03com\x00 type=A(1) class=IN(1)
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let (id, domain, qtype) = parse_dns_query(&pkt).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1); // A record
    }

    #[test]
    fn parse_dns_query_response_rejected() {
        // DNS response (QR bit set)
        let pkt = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        assert!(parse_dns_query(&pkt).is_none());
    }

    #[test]
    fn parse_dns_query_too_short() {
        assert!(parse_dns_query(&[0; 5]).is_none());
    }

    #[test]
    fn qtype_names() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(16), "TXT");
        assert_eq!(qtype_name(255), "ANY");
        assert_eq!(qtype_name(999), "OTHER");
    }
}
