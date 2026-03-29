//! Syslog CEF (Common Event Format) output sink.
//!
//! Sends events and incidents to a remote syslog server in ArcSight CEF
//! format, enabling integration with any SIEM that supports syslog.
//!
//! CEF format: `CEF:0|InnerWarden|Sensor|{version}|{id}|{name}|{severity}|{extension}`
//!
//! Configuration in sensor.toml:
//! ```toml
//! [sinks.syslog]
//! enabled = true
//! host = "siem.corp"
//! port = 514
//! protocol = "udp"  # "udp" or "tcp"
//! ```

use std::io::Write;
use std::net::{TcpStream, UdpSocket};

use chrono::Utc;
use tracing::{debug, warn};

use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// CEF writer
// ---------------------------------------------------------------------------

/// Syslog CEF sink configuration.
pub struct SyslogCefConfig {
    pub host: String,
    pub port: u16,
    pub protocol: SyslogProtocol,
}

#[derive(Debug, Clone, Copy)]
pub enum SyslogProtocol {
    Udp,
    Tcp,
}

/// Syslog CEF writer — sends events in CEF format to a remote syslog server.
pub struct SyslogCefWriter {
    config: SyslogCefConfig,
    udp_socket: Option<UdpSocket>,
    tcp_stream: Option<TcpStream>,
    version: String,
}

impl SyslogCefWriter {
    /// Create a new CEF writer. Connects immediately.
    pub fn new(config: SyslogCefConfig, version: &str) -> Self {
        let mut writer = Self {
            config,
            udp_socket: None,
            tcp_stream: None,
            version: version.to_string(),
        };
        writer.connect();
        writer
    }

    fn connect(&mut self) {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        match self.config.protocol {
            SyslogProtocol::Udp => match UdpSocket::bind("0.0.0.0:0") {
                Ok(sock) => {
                    if let Err(e) = sock.connect(&addr) {
                        warn!(addr, "syslog UDP connect failed: {e}");
                    } else {
                        self.udp_socket = Some(sock);
                    }
                }
                Err(e) => warn!("syslog UDP bind failed: {e}"),
            },
            SyslogProtocol::Tcp => match TcpStream::connect(&addr) {
                Ok(stream) => {
                    self.tcp_stream = Some(stream);
                }
                Err(e) => warn!(addr, "syslog TCP connect failed: {e}"),
            },
        }
    }

    /// Send an event as a CEF syslog message.
    pub fn write_event(&mut self, event: &Event) {
        let cef = format_event_cef(event, &self.version);
        self.send(&cef);
    }

    /// Send an incident as a CEF syslog message.
    pub fn write_incident(&mut self, incident: &Incident) {
        let cef = format_incident_cef(incident, &self.version);
        self.send(&cef);
    }

    fn send(&mut self, message: &str) {
        // Wrap in syslog format: <priority>timestamp hostname message
        let priority = 14; // facility=user (1), severity=info (6) → 1*8+6=14
        let syslog_msg = format!(
            "<{priority}>{} {} innerwarden: {message}\n",
            Utc::now().format("%b %d %H:%M:%S"),
            hostname(),
        );

        match self.config.protocol {
            SyslogProtocol::Udp => {
                if let Some(ref sock) = self.udp_socket {
                    if let Err(e) = sock.send(syslog_msg.as_bytes()) {
                        debug!("syslog UDP send failed: {e}");
                    }
                }
            }
            SyslogProtocol::Tcp => {
                if let Some(ref mut stream) = self.tcp_stream {
                    if let Err(e) = stream.write_all(syslog_msg.as_bytes()) {
                        debug!("syslog TCP send failed: {e}");
                        // Reconnect on next send
                        self.tcp_stream = None;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CEF formatting
// ---------------------------------------------------------------------------

/// Format an Event as a CEF message.
///
/// CEF:0|InnerWarden|Sensor|version|signatureId|name|severity|extension
pub fn format_event_cef(event: &Event, version: &str) -> String {
    let severity = cef_severity(&event.severity);
    let sig_id = cef_escape(&event.kind);
    let name = cef_escape(&event.summary);

    let mut ext = format!(
        "rt={} src={} shost={} cs1={} cs1Label=source",
        event.ts.timestamp_millis(),
        extract_ip(&event.entities),
        cef_escape(&event.host),
        cef_escape(&event.source),
    );

    // Add key details
    if let Some(pid) = event.details.get("pid").and_then(|v| v.as_u64()) {
        ext.push_str(&format!(" dpid={pid}"));
    }
    if let Some(comm) = event.details.get("comm").and_then(|v| v.as_str()) {
        ext.push_str(&format!(" dproc={}", cef_escape(comm)));
    }
    if let Some(dst_ip) = event.details.get("dst_ip").and_then(|v| v.as_str()) {
        ext.push_str(&format!(" dst={dst_ip}"));
    }
    if let Some(dst_port) = event.details.get("dst_port").and_then(|v| v.as_u64()) {
        ext.push_str(&format!(" dpt={dst_port}"));
    }

    format!("CEF:0|InnerWarden|Sensor|{version}|{sig_id}|{name}|{severity}|{ext}")
}

/// Format an Incident as a CEF message.
pub fn format_incident_cef(incident: &Incident, version: &str) -> String {
    let severity = cef_severity(&incident.severity);
    let sig_id = cef_escape(&incident.incident_id);
    let name = cef_escape(&incident.title);

    let ext = format!(
        "rt={} src={} shost={} msg={}",
        incident.ts.timestamp_millis(),
        extract_ip(&incident.entities),
        cef_escape(&incident.host),
        cef_escape(&incident.summary),
    );

    format!("CEF:0|InnerWarden|Sensor|{version}|{sig_id}|{name}|{severity}|{ext}")
}

fn cef_severity(sev: &Severity) -> u8 {
    match sev {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 7,
        Severity::Critical => 10,
    }
}

fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', " ")
        .replace('\r', "")
}

fn extract_ip(entities: &[innerwarden_core::entities::EntityRef]) -> String {
    entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone())
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_event() -> Event {
        Event {
            ts: Utc::now(),
            host: "test-host".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::High,
            summary: "bash connected to 1.2.3.4:4444".into(),
            details: serde_json::json!({
                "pid": 1234,
                "comm": "bash",
                "dst_ip": "1.2.3.4",
                "dst_port": 4444,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        }
    }

    fn make_incident() -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: "c2_callback:1.2.3.4:2026-03-29T12:00Z".into(),
            severity: Severity::Critical,
            title: "C2 callback to 1.2.3.4".into(),
            summary: "Process bash connected to known C2 server".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        }
    }

    #[test]
    fn event_cef_format() {
        let cef = format_event_cef(&make_event(), "0.6.0");
        assert!(cef.starts_with("CEF:0|InnerWarden|Sensor|0.6.0|"));
        assert!(cef.contains("network.outbound_connect"));
        assert!(cef.contains("|7|")); // High = 7
        assert!(cef.contains("dst=1.2.3.4"));
        assert!(cef.contains("dpt=4444"));
        assert!(cef.contains("dproc=bash"));
    }

    #[test]
    fn incident_cef_format() {
        let cef = format_incident_cef(&make_incident(), "0.6.0");
        assert!(cef.starts_with("CEF:0|InnerWarden|Sensor|0.6.0|"));
        assert!(cef.contains("|10|")); // Critical = 10
        assert!(cef.contains("C2 callback"));
        assert!(cef.contains("src=1.2.3.4"));
    }

    #[test]
    fn cef_escaping() {
        assert_eq!(cef_escape("pipe|here"), "pipe\\|here");
        assert_eq!(cef_escape("equals=here"), "equals\\=here");
        assert_eq!(cef_escape("back\\slash"), "back\\\\slash");
        assert_eq!(cef_escape("new\nline"), "new line");
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(cef_severity(&Severity::Debug), 0);
        assert_eq!(cef_severity(&Severity::Info), 1);
        assert_eq!(cef_severity(&Severity::Low), 3);
        assert_eq!(cef_severity(&Severity::Medium), 5);
        assert_eq!(cef_severity(&Severity::High), 7);
        assert_eq!(cef_severity(&Severity::Critical), 10);
    }
}
