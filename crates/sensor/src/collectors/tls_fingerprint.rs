//! JA3/JA4 TLS fingerprinting collector.
//!
//! Captures TLS ClientHello messages from network traffic and computes
//! JA3 and JA4 fingerprint hashes. These fingerprints identify the TLS
//! implementation used by a process — malware (Cobalt Strike, Metasploit,
//! custom C2) has distinctive TLS fingerprints even when connecting to
//! legitimate domains over HTTPS.
//!
//! **JA3**: MD5 of `TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`
//!   - Original paper: https://github.com/salesforce/ja3
//!
//! **JA4**: `TLSVersion_SNI-presence_CipherCount_ExtCount_ALPN`
//!   - Modern replacement with better collision resistance
//!   - Spec: https://github.com/FoxIO-LLC/ja4
//!
//! Uses AF_PACKET raw socket on Linux (requires CAP_NET_RAW).
//! Falls back gracefully when not available (macOS, unprivileged).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::mpsc;
use tracing::{info, warn};

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

// ---------------------------------------------------------------------------
// TLS parsing structures
// ---------------------------------------------------------------------------

/// Parsed TLS ClientHello message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// TLS version from the record layer (e.g., 0x0301 = TLS 1.0).
    pub record_version: u16,
    /// TLS version from the handshake (e.g., 0x0303 = TLS 1.2).
    pub handshake_version: u16,
    /// Cipher suite values.
    pub cipher_suites: Vec<u16>,
    /// Extension type values.
    pub extensions: Vec<u16>,
    /// Supported Groups (elliptic curves) from extension 0x000a.
    pub elliptic_curves: Vec<u16>,
    /// EC Point Formats from extension 0x000b.
    pub ec_point_formats: Vec<u8>,
    /// Server Name Indication (SNI) from extension 0x0000.
    pub sni: String,
    /// ALPN protocols from extension 0x0010.
    pub alpn: Vec<String>,
    /// Source IP.
    pub src_ip: String,
    /// Destination IP.
    pub dst_ip: String,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

/// Computed fingerprints for a ClientHello.
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub ja3_hash: String,
    pub ja3_raw: String,
    pub ja4: String,
    pub sni: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
}

// ---------------------------------------------------------------------------
// Known malicious JA3 hashes
// ---------------------------------------------------------------------------

/// Known malicious JA3 hashes (Cobalt Strike, Metasploit, etc.)
const KNOWN_MALICIOUS_JA3: &[(&str, &str)] = &[
    ("72a589da586844d7f0818ce684948eea", "Cobalt Strike Default"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike 4.x"),
    ("e7d705a3286e19ea42f587b344ee6865", "Metasploit Meterpreter"),
    ("6734f37431670b3ab4292b8f60f29984", "Trickbot"),
    ("4d7a28d6f2263ed61de88ca66eb2e557", "AsyncRAT"),
    ("51c64c77e60f3980eea90869b68c58a8", "Cobalt Strike HTTPS"),
    ("b386946a5a44d1ddcc843bc75336dfce", "Emotet"),
    ("3b5074b1b5d032e5620f69f9f700ff0e", "IcedID"),
    ("c12f54a3f91dc7bafd92c258b7b5c57b", "Qakbot"),
    ("e35df3e00ca4ef31d42b34bebaa2f86e", "SolarWinds SUNBURST"),
];

// GREASE values (should be ignored in JA3 computation per spec)
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run the TLS fingerprint collector.
///
/// On Linux with CAP_NET_RAW, opens an AF_PACKET socket to capture TLS
/// ClientHello packets. On other platforms or without privileges, returns
/// immediately (graceful degradation).
pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    _poll_seconds: u64,
) {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        if let Err(e) = run_linux(tx, host).await {
            warn!("TLS fingerprint collector failed: {e} (requires CAP_NET_RAW)");
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    {
        info!("TLS fingerprint collector: requires Linux + ebpf feature (CAP_NET_RAW)");
        let _ = (tx, host, _poll_seconds);
        tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn run_linux(
    tx: mpsc::Sender<Event>,
    host: String,
) -> anyhow::Result<()> {
    use std::os::fd::FromRawFd;

    // Open AF_PACKET socket (ETH_P_IP = 0x0800)
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        anyhow::bail!("failed to create AF_PACKET socket (need CAP_NET_RAW)");
    }

    info!("TLS fingerprint collector started (AF_PACKET raw socket)");

    let mut buf = vec![0u8; 65536];
    let mut cooldowns: HashMap<String, DateTime<Utc>> = HashMap::new();
    let cooldown = Duration::seconds(60);

    // Use tokio::task::spawn_blocking for the raw socket reads
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Spawn blocking reader thread
    std::thread::spawn(move || {
        loop {
            let mut buf = vec![0u8; 65536];
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                break;
            }
            buf.truncate(n as usize);
            if packet_tx.blocking_send(buf).is_err() {
                break;
            }
        }
        unsafe { libc::close(fd) };
    });

    while let Some(packet) = packet_rx.recv().await {
        let now = Utc::now();

        // Parse Ethernet → IP → TCP → TLS ClientHello
        let hello = match parse_packet(&packet) {
            Some(h) => h,
            None => continue,
        };

        // Compute fingerprints
        let fp = compute_fingerprints(&hello);

        // Cooldown per src_ip+dst_ip (avoid flooding)
        let key = format!("{}:{}", fp.src_ip, fp.dst_ip);
        if let Some(last) = cooldowns.get(&key) {
            if now - *last < cooldown {
                continue;
            }
        }
        cooldowns.insert(key, now);

        // Check against known malicious fingerprints
        let malicious = KNOWN_MALICIOUS_JA3
            .iter()
            .find(|(hash, _)| *hash == fp.ja3_hash);

        let severity = if malicious.is_some() {
            Severity::Critical
        } else {
            Severity::Info
        };

        let summary = if let Some((_, name)) = malicious {
            format!(
                "MALICIOUS TLS fingerprint: {} ({}) from {} → {}:{}",
                name, &fp.ja3_hash[..12], fp.src_ip, fp.dst_ip, fp.dst_port
            )
        } else {
            format!(
                "TLS ClientHello: {} → {}:{} (JA3: {}, SNI: {})",
                fp.src_ip,
                fp.dst_ip,
                fp.dst_port,
                &fp.ja3_hash[..12],
                if fp.sni.is_empty() { "none" } else { &fp.sni }
            )
        };

        // Only emit events for malicious fingerprints or High severity events
        // (to avoid flooding with every HTTPS connection)
        if malicious.is_none() {
            continue;
        }

        let ev = Event {
            ts: now,
            host: host.clone(),
            source: "tls_fingerprint".to_string(),
            kind: if malicious.is_some() {
                "tls.malicious_fingerprint".to_string()
            } else {
                "tls.client_hello".to_string()
            },
            severity,
            summary,
            details: serde_json::json!({
                "ja3_hash": fp.ja3_hash,
                "ja3_raw": fp.ja3_raw,
                "ja4": fp.ja4,
                "sni": fp.sni,
                "src_ip": fp.src_ip,
                "dst_ip": fp.dst_ip,
                "dst_port": fp.dst_port,
                "malicious_match": malicious.map(|(_, name)| name),
            }),
            tags: {
                let mut t = vec!["tls".to_string(), "network".to_string()];
                if malicious.is_some() {
                    t.push("malware".to_string());
                    t.push("c2".to_string());
                }
                t
            },
            entities: vec![
                EntityRef::ip(&fp.src_ip),
                EntityRef::ip(&fp.dst_ip),
            ],
        };

        if tx.send(ev).await.is_err() {
            break;
        }

        // Prune old cooldowns
        if cooldowns.len() > 10000 {
            let cutoff = now - cooldown;
            cooldowns.retain(|_, ts| *ts > cutoff);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Packet parsing (Ethernet → IP → TCP → TLS)
// ---------------------------------------------------------------------------

/// Parse a raw Ethernet frame looking for a TLS ClientHello.
pub fn parse_packet(data: &[u8]) -> Option<ClientHello> {
    // Ethernet header: 14 bytes (dst[6] + src[6] + ethertype[2])
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None; // Not IPv4
    }

    // IP header
    let ip_start = 14;
    if data.len() < ip_start + 20 {
        return None;
    }
    let ip_version = (data[ip_start] >> 4) & 0xF;
    if ip_version != 4 {
        return None;
    }
    let ip_header_len = ((data[ip_start] & 0xF) as usize) * 4;
    let protocol = data[ip_start + 9];
    if protocol != 6 {
        return None; // Not TCP
    }
    let src_ip = format!(
        "{}.{}.{}.{}",
        data[ip_start + 12],
        data[ip_start + 13],
        data[ip_start + 14],
        data[ip_start + 15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        data[ip_start + 16],
        data[ip_start + 17],
        data[ip_start + 18],
        data[ip_start + 19]
    );

    // TCP header
    let tcp_start = ip_start + ip_header_len;
    if data.len() < tcp_start + 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);
    let tcp_header_len = (((data[tcp_start + 12] >> 4) & 0xF) as usize) * 4;

    // TLS record
    let tls_start = tcp_start + tcp_header_len;
    if data.len() < tls_start + 5 {
        return None;
    }
    let content_type = data[tls_start];
    if content_type != 0x16 {
        return None; // Not TLS Handshake
    }
    let record_version = u16::from_be_bytes([data[tls_start + 1], data[tls_start + 2]]);
    let record_len = u16::from_be_bytes([data[tls_start + 3], data[tls_start + 4]]) as usize;

    let hs_start = tls_start + 5;
    if data.len() < hs_start + 4 || data.len() < hs_start + record_len {
        return None;
    }
    let hs_type = data[hs_start];
    if hs_type != 0x01 {
        return None; // Not ClientHello
    }

    // Parse ClientHello
    parse_client_hello(&data[hs_start..], record_version, src_ip, dst_ip, src_port, dst_port)
}

/// Parse the ClientHello handshake message.
pub fn parse_client_hello(
    data: &[u8],
    record_version: u16,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
) -> Option<ClientHello> {
    if data.len() < 42 {
        return None;
    }

    // Skip handshake type (1) + length (3)
    let mut pos = 4;

    // Client version (2 bytes)
    let handshake_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes)
    pos += 32;

    // Session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher Suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_len > data.len() {
        return None;
    }
    let mut cipher_suites = Vec::new();
    let mut i = 0;
    while i + 1 < cipher_len {
        let cs = u16::from_be_bytes([data[pos + i], data[pos + i + 1]]);
        if !GREASE_VALUES.contains(&cs) {
            cipher_suites.push(cs);
        }
        i += 2;
    }
    pos += cipher_len;

    // Compression Methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut sni = String::new();
    let mut alpn = Vec::new();

    if pos + 2 <= data.len() {
        let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if !GREASE_VALUES.contains(&ext_type) {
                extensions.push(ext_type);
            }

            let ext_data_end = (pos + ext_len).min(data.len());

            match ext_type {
                // SNI (Server Name Indication)
                0x0000 => {
                    if pos + 5 <= ext_data_end {
                        let name_len =
                            u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                        if pos + 5 + name_len <= ext_data_end {
                            sni = String::from_utf8_lossy(&data[pos + 5..pos + 5 + name_len])
                                .to_string();
                        }
                    }
                }
                // Supported Groups (elliptic curves)
                0x000a => {
                    if pos + 2 <= ext_data_end {
                        let list_len =
                            u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                        let mut j = 2;
                        while j + 1 < 2 + list_len && pos + j + 1 < ext_data_end {
                            let curve =
                                u16::from_be_bytes([data[pos + j], data[pos + j + 1]]);
                            if !GREASE_VALUES.contains(&curve) {
                                elliptic_curves.push(curve);
                            }
                            j += 2;
                        }
                    }
                }
                // EC Point Formats
                0x000b => {
                    if pos < ext_data_end {
                        let fmt_len = data[pos] as usize;
                        for k in 1..=fmt_len {
                            if pos + k < ext_data_end {
                                ec_point_formats.push(data[pos + k]);
                            }
                        }
                    }
                }
                // ALPN
                0x0010 => {
                    if pos + 2 <= ext_data_end {
                        let list_len =
                            u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                        let mut j = 2;
                        while j < 2 + list_len && pos + j < ext_data_end {
                            let proto_len = data[pos + j] as usize;
                            j += 1;
                            if pos + j + proto_len <= ext_data_end {
                                let proto = String::from_utf8_lossy(
                                    &data[pos + j..pos + j + proto_len],
                                )
                                .to_string();
                                alpn.push(proto);
                                j += proto_len;
                            } else {
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }

            pos = ext_data_end;
        }
    }

    Some(ClientHello {
        record_version,
        handshake_version,
        cipher_suites,
        extensions,
        elliptic_curves,
        ec_point_formats,
        sni,
        alpn,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

// ---------------------------------------------------------------------------
// Fingerprint computation
// ---------------------------------------------------------------------------

/// Compute JA3 and JA4 fingerprints from a parsed ClientHello.
pub fn compute_fingerprints(hello: &ClientHello) -> TlsFingerprint {
    // JA3: MD5 of "TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats"
    let ja3_raw = format!(
        "{},{},{},{},{}",
        hello.handshake_version,
        join_u16(&hello.cipher_suites),
        join_u16(&hello.extensions),
        join_u16(&hello.elliptic_curves),
        join_u8(&hello.ec_point_formats),
    );

    let ja3_hash = md5_hex(ja3_raw.as_bytes());

    // JA4: "t{version}{sni}{ciphers_count}{ext_count}_{alpn}"
    let version_str = match hello.handshake_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_flag = if hello.sni.is_empty() { "i" } else { "d" };
    let alpn_str = hello
        .alpn
        .first()
        .map(|a| {
            if a.len() >= 2 {
                format!("{}{}", &a[..1], &a[a.len() - 1..])
            } else {
                a.clone()
            }
        })
        .unwrap_or_else(|| "00".to_string());

    let ja4 = format!(
        "t{version_str}{sni_flag}{:02}{:02}_{alpn_str}",
        hello.cipher_suites.len().min(99),
        hello.extensions.len().min(99),
    );

    TlsFingerprint {
        ja3_hash,
        ja3_raw,
        ja4,
        sni: hello.sni.clone(),
        src_ip: hello.src_ip.clone(),
        dst_ip: hello.dst_ip.clone(),
        dst_port: hello.dst_port,
    }
}

pub fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Simple MD5 implementation for JA3 (the spec requires MD5).
/// We implement it here to avoid adding a dependency.
pub fn md5_hex(data: &[u8]) -> String {
    // Using a minimal MD5 for JA3 hash computation.
    // MD5 is cryptographically broken but JA3 spec mandates it.
    let digest = md5_compute(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal MD5 implementation (RFC 1321).
pub fn md5_compute(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: padding
    let orig_len_bits = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Process each 512-bit chunk
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g]))
                .rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_empty() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_hello() {
        assert_eq!(md5_hex(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn md5_abc() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn grease_values_filtered() {
        assert!(GREASE_VALUES.contains(&0x0a0a));
        assert!(GREASE_VALUES.contains(&0xfafa));
        assert!(!GREASE_VALUES.contains(&0x0035)); // AES-256-CBC
    }

    #[test]
    fn ja3_computation() {
        let hello = ClientHello {
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![0xc02c, 0xc02b, 0x009f, 0x009e],
            extensions: vec![0x0000, 0x000a, 0x000b, 0x000d],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0],
            sni: "example.com".into(),
            alpn: vec!["h2".into(), "http/1.1".into()],
            src_ip: "10.0.0.1".into(),
            dst_ip: "93.184.216.34".into(),
            src_port: 12345,
            dst_port: 443,
        };

        let fp = compute_fingerprints(&hello);

        // JA3 raw should be: version,ciphers,extensions,curves,ec_formats
        assert!(fp.ja3_raw.starts_with("771,")); // 0x0303 = 771
        assert!(!fp.ja3_hash.is_empty());
        assert_eq!(fp.ja3_hash.len(), 32); // MD5 hex is 32 chars

        // JA4 should include version, SNI flag, counts
        assert!(fp.ja4.starts_with("t12d")); // TLS 1.2, SNI present (d)
        assert!(fp.ja4.contains("_h2")); // ALPN first="h2" → first+last chars = "h2"
    }

    #[test]
    fn ja4_no_sni() {
        let hello = ClientHello {
            record_version: 0x0301,
            handshake_version: 0x0304,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0x002b],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
            sni: String::new(),
            alpn: vec![],
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 54321,
            dst_port: 443,
        };

        let fp = compute_fingerprints(&hello);
        assert!(fp.ja4.starts_with("t13i")); // TLS 1.3, no SNI (i)
    }

    #[test]
    fn known_malicious_ja3_list() {
        assert!(!KNOWN_MALICIOUS_JA3.is_empty());
        // All hashes should be 32 char hex
        for (hash, _) in KNOWN_MALICIOUS_JA3 {
            assert_eq!(hash.len(), 32, "JA3 hash should be 32 hex chars: {hash}");
        }
    }

    #[test]
    fn parse_packet_too_short() {
        assert!(parse_packet(&[0; 10]).is_none());
    }

    #[test]
    fn parse_packet_not_ipv4() {
        let mut data = vec![0u8; 20];
        // Ethertype = 0x86DD (IPv6)
        data[12] = 0x86;
        data[13] = 0xDD;
        assert!(parse_packet(&data).is_none());
    }

    #[test]
    fn join_functions() {
        assert_eq!(join_u16(&[1, 2, 3]), "1-2-3");
        assert_eq!(join_u16(&[]), "");
        assert_eq!(join_u8(&[0, 1]), "0-1");
    }
}
