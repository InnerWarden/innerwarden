//! Per-agent session tracking for behavioral anomaly detection.

use std::collections::HashMap;
use std::time::Instant;

use crate::threats;

const MAX_CALLS_PER_MINUTE: u32 = 30;
const MAX_FAILURES_PER_SESSION: u32 = 5;
const MAX_SENSITIVE_PER_SESSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Layer {
    Warn,
    Shadow,
    Kill,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub layer: Layer,
    pub reason: String,
}

pub struct SessionTracker {
    call_times: Vec<Instant>,
    failures: u32,
    sensitive_accesses: Vec<String>,
    read_files: HashMap<String, Instant>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            call_times: Vec::new(),
            failures: 0,
            sensitive_accesses: Vec::new(),
            read_files: HashMap::new(),
        }
    }

    pub fn record_call(&mut self) -> Option<Alert> {
        let now = Instant::now();
        self.call_times.push(now);
        let cutoff = now - std::time::Duration::from_secs(60);
        self.call_times.retain(|t| *t > cutoff);

        if self.call_times.len() as u32 > MAX_CALLS_PER_MINUTE {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{}/min exceeds limit ({})", self.call_times.len(), MAX_CALLS_PER_MINUTE),
            });
        }
        None
    }

    pub fn record_failure(&mut self) -> Option<Alert> {
        self.failures += 1;
        if self.failures > MAX_FAILURES_PER_SESSION {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{} failures in session", self.failures),
            });
        }
        None
    }

    pub fn record_file_access(&mut self, path: &str) -> Option<Alert> {
        if threats::check_sensitive_path(path).is_none() {
            return None;
        }
        self.sensitive_accesses.push(path.to_string());
        self.read_files.insert(path.to_string(), Instant::now());

        if self.sensitive_accesses.len() as u32 > MAX_SENSITIVE_PER_SESSION {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{} sensitive accesses", self.sensitive_accesses.len()),
            });
        }
        Some(Alert {
            layer: Layer::Warn,
            reason: format!("sensitive file: {path}"),
        })
    }

    pub fn check_exfil(&self, tool_name: &str, args: &str) -> Option<Alert> {
        if self.read_files.is_empty() {
            return None;
        }
        let is_outbound = ["send", "post", "fetch", "request", "webhook", "email", "upload"]
            .iter()
            .any(|k| tool_name.contains(k));
        if !is_outbound {
            return None;
        }

        for (path, read_time) in &self.read_files {
            if read_time.elapsed() > std::time::Duration::from_secs(300) {
                continue;
            }
            if args.contains(path) {
                return Some(Alert {
                    layer: Layer::Kill,
                    reason: format!("EXFIL: read '{path}' then outbound '{tool_name}'"),
                });
            }
        }

        let recent: Vec<_> = self.read_files.keys().take(3).cloned().collect();
        if !recent.is_empty() {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("outbound '{tool_name}' after reading: {}", recent.join(", ")),
            });
        }
        None
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit() {
        let mut s = SessionTracker::new();
        for _ in 0..35 {
            s.record_call();
        }
        assert!(s.record_call().is_some());
    }

    #[test]
    fn sensitive_tracking() {
        let mut s = SessionTracker::new();
        let alert = s.record_file_access("/home/user/.ssh/id_rsa");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().layer, Layer::Warn);
    }

    #[test]
    fn exfil_detection() {
        let mut s = SessionTracker::new();
        s.record_file_access("/home/user/.ssh/id_rsa");
        let alert = s.check_exfil("send_message", "/home/user/.ssh/id_rsa");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().layer, Layer::Kill);
    }

    #[test]
    fn normal_no_exfil() {
        let s = SessionTracker::new();
        assert!(s.check_exfil("fetch", "https://api.com").is_none());
    }
}
