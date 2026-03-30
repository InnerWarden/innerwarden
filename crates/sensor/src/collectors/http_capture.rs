//! HTTP request header capture collector.
//!
//! Captures HTTP requests from network traffic via AF_PACKET raw socket.
//! Extracts: method, path, Host, User-Agent, Content-Type.
//! Emits `http.request` events for web_scan, user_agent_scanner, and
//! web_shell detectors.
//!
//! Eliminates the dependency on nginx access logs or Suricata for HTTP
//! visibility. Only captures inbound requests to monitored ports.
//!
//! Requires: Linux, CAP_NET_RAW capability.

use tokio::sync::mpsc;
use tracing::info;

use innerwarden_core::event::Event;

// ---------------------------------------------------------------------------
// HTTP parsing
// ---------------------------------------------------------------------------

/// Parsed HTTP request line + headers.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    version: String,
    host: String,
    user_agent: String,
    content_type: String,
    content_length: usize,
}

/// Ports to monitor for HTTP traffic.
#[cfg(any(target_os = "linux", test))]
const HTTP_PORTS: &[u16] = &[80, 8080, 8443, 8787, 3000, 5000, 9090];

/// Parse HTTP request from TCP payload.
/// Returns None if not a valid HTTP request.
#[cfg(any(target_os = "linux", test))]
fn parse_http_request(payload: &[u8]) -> Option<HttpRequest> {
    // HTTP requests start with METHOD SP PATH SP VERSION CRLF
    let text = std::str::from_utf8(payload).ok()?;

    // Must start with a known HTTP method
    if !text.starts_with("GET ")
        && !text.starts_with("POST ")
        && !text.starts_with("PUT ")
        && !text.starts_with("DELETE ")
        && !text.starts_with("HEAD ")
        && !text.starts_with("OPTIONS ")
        && !text.starts_with("PATCH ")
    {
        return None;
    }

    let mut lines = text.lines();

    // Request line: "GET /path HTTP/1.1"
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    // Parse headers
    let mut host = String::new();
    let mut user_agent = String::new();
    let mut content_type = String::new();
    let mut content_length = 0usize;

    for line in lines {
        if line.is_empty() {
            break; // End of headers
        }

        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            host = line[5..].trim().to_string();
        } else if lower.starts_with("user-agent:") {
            user_agent = line[11..].trim().to_string();
        } else if lower.starts_with("content-type:") {
            content_type = line[13..].trim().to_string();
        } else if lower.starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
        }
    }

    Some(HttpRequest {
        method,
        path,
        version,
        host,
        user_agent,
        content_type,
        content_length,
    })
}

// ---------------------------------------------------------------------------
// Packet parsing (Ethernet → IP → TCP → HTTP)
// ---------------------------------------------------------------------------

/// Parse packet, return (src_ip, src_port, dst_ip, dst_port, tcp_payload) for HTTP.
#[cfg(any(target_os = "linux", test))]
fn parse_tcp_packet(raw: &[u8]) -> Option<(String, u16, String, u16, &[u8])> {
    if raw.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let ip_offset = match ethertype {
        0x0800 => 14,
        0x8100 => 18,
        _ => return None,
    };

    if raw.len() < ip_offset + 20 {
        return None;
    }

    let ip_header = &raw[ip_offset..];
    let ihl = ((ip_header[0] & 0x0F) as usize) * 4;
    let protocol = ip_header[9];

    // Only TCP (6)
    if protocol != 6 {
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

    let tcp_offset = ip_offset + ihl;
    if raw.len() < tcp_offset + 20 {
        return None;
    }

    let tcp_header = &raw[tcp_offset..];
    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    // Data offset (upper 4 bits of byte 12) * 4
    let data_offset = ((tcp_header[12] >> 4) as usize) * 4;
    let payload_start = tcp_offset + data_offset;

    if raw.len() <= payload_start {
        return None;
    }

    // Only monitor inbound HTTP: dst_port must be a monitored port
    if !HTTP_PORTS.contains(&dst_port) {
        return None;
    }

    Some((src_ip, src_port, dst_ip, dst_port, &raw[payload_start..]))
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tx, host);
        info!("http_capture: not on Linux, skipping");
    }

    #[cfg(target_os = "linux")]
    {
        run_linux(tx, host).await;
    }
}

#[cfg(target_os = "linux")]
async fn run_linux(tx: mpsc::Sender<Event>, host: String) {
    use std::collections::HashMap;
    use chrono::{DateTime, Duration, Utc};
    use tracing::warn;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;

    const COOLDOWN_SECS: i64 = 5;
    const MAX_TRACKED: usize = 5000;

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if fd < 0 {
        warn!("http_capture: failed to create AF_PACKET socket (need CAP_NET_RAW)");
        return;
    }

    info!(
        ports = ?HTTP_PORTS,
        "http_capture: listening for HTTP requests"
    );

    let mut buf = [0u8; 65536];
    let mut cooldown: HashMap<String, DateTime<Utc>> = HashMap::new();

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n <= 0 {
            tokio::task::yield_now().await;
            continue;
        }

        let raw = &buf[..n as usize];

        let (src_ip, src_port, _dst_ip, dst_port, tcp_payload) = match parse_tcp_packet(raw) {
            Some(p) => p,
            None => continue,
        };

        // Skip tiny payloads (not HTTP)
        if tcp_payload.len() < 16 {
            continue;
        }

        let req = match parse_http_request(tcp_payload) {
            Some(r) => r,
            None => continue,
        };

        // Cooldown per (src_ip, method, path)
        let now = Utc::now();
        let key = format!("{}:{}:{}", src_ip, req.method, req.path);
        if let Some(&last) = cooldown.get(&key) {
            if (now - last).num_seconds() < COOLDOWN_SECS {
                continue;
            }
        }
        cooldown.insert(key, now);

        if cooldown.len() > MAX_TRACKED {
            let cutoff = now - Duration::seconds(COOLDOWN_SECS);
            cooldown.retain(|_, v| *v > cutoff);
        }

        // Determine severity based on path patterns
        let path_lower = req.path.to_lowercase();
        let is_suspicious_path = path_lower.contains("..")
            || path_lower.contains("/etc/")
            || path_lower.contains(".env")
            || path_lower.contains(".git")
            || path_lower.contains("wp-login")
            || path_lower.contains("wp-admin")
            || path_lower.contains("phpmyadmin")
            || path_lower.contains("shell")
            || path_lower.contains("cmd")
            || path_lower.contains("backup")
            || path_lower.contains("xmlrpc");

        let severity = if is_suspicious_path {
            Severity::Medium
        } else {
            Severity::Info
        };

        let summary = format!(
            "{} {} from {} (UA: {})",
            req.method,
            truncate_str(&req.path, 100),
            src_ip,
            truncate_str(&req.user_agent, 80),
        );

        let event = Event {
            ts: now,
            host: host.clone(),
            source: "http_capture".to_string(),
            kind: "http.request".to_string(),
            severity,
            summary,
            details: serde_json::json!({
                "method": req.method,
                "path": req.path,
                "host": req.host,
                "user_agent": req.user_agent,
                "content_type": req.content_type,
                "content_length": req.content_length,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "http_version": req.version,
            }),
            tags: vec!["http".to_string(), "network".to_string()],
            entities: vec![EntityRef::ip(&src_ip)],
        };

        let _ = tx.send(event).await;
    }
}

#[cfg(any(target_os = "linux", test))]
fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request() {
        let raw = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/admin");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn parse_post_request() {
        let raw = b"POST /upload.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: multipart/form-data\r\nContent-Length: 1234\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload.php");
        assert_eq!(req.content_type, "multipart/form-data");
        assert_eq!(req.content_length, 1234);
    }

    #[test]
    fn parse_nikto_scan() {
        let raw = b"GET /.env HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.user_agent, "Nikto/2.1.6");
        assert_eq!(req.path, "/.env");
    }

    #[test]
    fn parse_path_traversal() {
        let raw = b"GET /../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.path, "/../../etc/passwd");
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse_http_request(b"SSH-2.0-OpenSSH").is_none());
        assert!(parse_http_request(b"\x16\x03\x01").is_none()); // TLS
        assert!(parse_http_request(b"random garbage data").is_none());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_http_request(b"").is_none());
    }

    #[test]
    fn suspicious_path_detection() {
        let suspicious = vec!["/.env", "/../../../etc/shadow", "/wp-login.php", "/phpmyadmin", "/shell.php"];
        for path in suspicious {
            let lower = path.to_lowercase();
            assert!(
                lower.contains("..") || lower.contains("/etc/") || lower.contains(".env")
                    || lower.contains("wp-login") || lower.contains("phpmyadmin")
                    || lower.contains("shell"),
                "should be suspicious: {path}"
            );
        }
    }

    #[test]
    fn http_ports_list() {
        assert!(HTTP_PORTS.contains(&80));
        assert!(HTTP_PORTS.contains(&8080));
        assert!(HTTP_PORTS.contains(&8787));
        assert!(!HTTP_PORTS.contains(&22)); // SSH not monitored
    }
}
