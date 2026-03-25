//! Safe sudoers drop-in management.
//!
//! Write flow:
//! 1. Write content to a secure temp file (O_EXCL, 0600)
//! 2. Validate with `visudo -cf <tempfile>`  (fails fast — never installs invalid rules)
//! 3. `install -o root -g root -m 440 <tempfile> /etc/sudoers.d/<name>`
//! 4. Cleanup temp file

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};

pub struct SudoersDropIn {
    /// File name inside /etc/sudoers.d/ (no path separators)
    pub name: String,
    /// Full sudoers rule content
    pub content: String,
}

impl SudoersDropIn {
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
        }
    }

    pub fn path(&self) -> Result<PathBuf> {
        ensure!(
            !self.name.is_empty()
                && !self.name.contains('/')
                && !self.name.contains("..")
                && self
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "sudoers drop-in name must be a simple filename (got '{}')",
            self.name
        );
        Ok(PathBuf::from(format!("/etc/sudoers.d/{}", self.name)))
    }

    #[allow(dead_code)]
    pub fn is_installed(&self) -> bool {
        self.path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Write the drop-in, validate with visudo, and install atomically.
    /// If dry_run is true, only prints what would happen.
    pub fn install(&self, dry_run: bool) -> Result<()> {
        let dest = self.path()?;

        if dry_run {
            return Ok(());
        }

        // Write to secure temp file (unique name, exclusive create)
        let mut tmp = tempfile::Builder::new()
            .prefix("innerwarden-sudoers-")
            .tempfile_in("/tmp")
            .context("failed to create secure temp file for sudoers")?;

        tmp.write_all(self.content.as_bytes())
            .context("failed to write sudoers content to temp file")?;

        let tmp_path = tmp.path().to_path_buf();

        // Validate with visudo
        let validate = Command::new("visudo")
            .args(["-cf", &tmp_path.display().to_string()])
            .output();

        match validate {
            Err(e) => {
                bail!("failed to run visudo: {e}");
            }
            Ok(out) if !out.status.success() => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!("visudo validation failed for sudoers drop-in:\n{stderr}");
            }
            Ok(_) => {}
        }

        // Install atomically: `install` preserves permissions correctly
        let install = Command::new("install")
            .args([
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "440",
                &tmp_path.display().to_string(),
                &dest.display().to_string(),
            ])
            .output()
            .with_context(|| "failed to run install command")?;

        if !install.status.success() {
            let stderr = String::from_utf8_lossy(&install.stderr);
            bail!("failed to install sudoers drop-in: {stderr}");
        }

        Ok(())
    }

    /// Remove the drop-in file.
    pub fn remove(&self, dry_run: bool) -> Result<()> {
        let dest = self.path()?;
        if !dest.exists() {
            return Ok(());
        }
        if dry_run {
            return Ok(());
        }
        std::fs::remove_file(&dest).with_context(|| format!("failed to remove {}", dest.display()))
    }
}

/// Returns the sudoers rule for a given block-ip backend.
pub fn block_ip_rule(backend: &str) -> Option<String> {
    // Minimal sudoers: only the exact subcommands Inner Warden needs.
    // No wildcard access to `ufw disable`, `iptables -F`, etc.
    let rule = match backend {
        "ufw" => {
            "\
            innerwarden ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from *, \\\n  \
            /usr/sbin/ufw delete deny from *, \\\n  \
            /usr/sbin/ufw status\n"
        }
        "iptables" => {
            "\
            innerwarden ALL=(ALL) NOPASSWD: \\\n  \
            /sbin/iptables -A INPUT -s * -j DROP, \\\n  \
            /sbin/iptables -D INPUT -s * -j DROP, \\\n  \
            /sbin/iptables -L INPUT -n\n"
        }
        "nftables" => {
            "\
            innerwarden ALL=(ALL) NOPASSWD: \\\n  \
            /usr/sbin/nft add element inet innerwarden-blocked blocked-ips *, \\\n  \
            /usr/sbin/nft delete element inet innerwarden-blocked blocked-ips *, \\\n  \
            /usr/sbin/nft list set inet innerwarden-blocked blocked-ips\n"
        }
        _ => return None,
    };
    Some(format!(
        "# Managed by innerwarden-ctl — do not edit manually\n\
         # Generated for capability: block-ip (backend: {backend})\n\
         # Minimal permissions: deny/delete/status only — no disable, flush, or reset\n\
         {rule}"
    ))
}

/// Returns the sudoers rule for the search-protection nginx skill.
pub fn search_protection_nginx_rule() -> String {
    "# Managed by innerwarden-ctl — do not edit manually\n\
     # Generated for capability: search-protection\n\
     innerwarden ALL=(ALL) NOPASSWD: \\\n  \
     /usr/bin/install -o root -g root -m 644 /tmp/innerwarden-nginx-* /etc/nginx/innerwarden-blocklist.conf, \\\n  \
     /usr/sbin/nginx -t, \\\n  \
     /usr/sbin/nginx -s reload\n"
        .to_string()
}

/// Returns the sudoers rule for suspend-user-sudo skill.
pub fn suspend_user_sudo_rule() -> String {
    "# Managed by innerwarden-ctl — do not edit manually\n\
     # Generated for capability: sudo-protection\n\
     innerwarden ALL=(ALL) NOPASSWD: \\\n  \
     /usr/bin/install -o root -g root -m 440 /tmp/innerwarden-sudoers-* /etc/sudoers.d/innerwarden-*, \\\n  \
     /usr/sbin/visudo -cf /tmp/innerwarden-sudoers-*, \\\n  \
     /bin/rm -f /etc/sudoers.d/zz-innerwarden-deny-*\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ip_rule_known_backends() {
        assert!(block_ip_rule("ufw").is_some());
        assert!(block_ip_rule("iptables").is_some());
        assert!(block_ip_rule("nftables").is_some());
    }

    #[test]
    fn block_ip_rule_unknown_backend_returns_none() {
        assert!(block_ip_rule("unknown-backend").is_none());
    }

    #[test]
    fn drop_in_path_is_correct() {
        let d = SudoersDropIn::new("innerwarden-test", "# test\n");
        assert_eq!(
            d.path().unwrap(),
            PathBuf::from("/etc/sudoers.d/innerwarden-test")
        );
    }

    #[test]
    fn drop_in_path_rejects_traversal() {
        let d = SudoersDropIn::new("../evil", "# test\n");
        assert!(d.path().is_err());
    }

    #[test]
    fn drop_in_path_rejects_slash() {
        let d = SudoersDropIn::new("foo/bar", "# test\n");
        assert!(d.path().is_err());
    }

    #[test]
    fn drop_in_path_rejects_empty() {
        let d = SudoersDropIn::new("", "# test\n");
        assert!(d.path().is_err());
    }

    #[test]
    fn drop_in_path_rejects_special_chars() {
        let d = SudoersDropIn::new("foo;bar", "# test\n");
        assert!(d.path().is_err());
    }
}
