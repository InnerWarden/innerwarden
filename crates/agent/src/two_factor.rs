//! Pluggable two-factor authentication for sensitive InnerWarden actions.
//!
//! Supports TOTP (Google Authenticator, Authy, 1Password) and a "none" mode
//! for backward compatibility. Dashboard confirmation can be added later.
//!
//! The 2FA system is reusable beyond Telegram (dashboard, API, future apps).

use std::collections::HashMap;
use tracing::warn;

// ---------------------------------------------------------------------------
// Two-factor method enum
// ---------------------------------------------------------------------------

/// The operator's chosen 2FA method.
#[derive(Debug, Clone, PartialEq)]
pub enum TwoFactorMethod {
    /// No 2FA - actions execute immediately (default, v1 behavior).
    None,
    /// TOTP via Google Authenticator, Authy, etc.
    Totp,
    /// Dashboard confirmation (future).
    Dashboard,
}

impl TwoFactorMethod {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "totp" => Self::Totp,
            "dashboard" => Self::Dashboard,
            _ => Self::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Totp => "TOTP",
            Self::Dashboard => "dashboard",
        }
    }
}

// ---------------------------------------------------------------------------
// TOTP provider
// ---------------------------------------------------------------------------

/// TOTP provider using HMAC-SHA1, 6-digit codes, 30-second period.
/// Compatible with Google Authenticator, Authy, 1Password, etc.
pub struct TotpProvider {
    secret: Vec<u8>,
}

impl TotpProvider {
    /// Create a new TOTP provider from a base32-encoded secret.
    pub fn new(secret_base32: &str) -> Option<Self> {
        let secret = base32_decode(secret_base32)?;
        if secret.len() < 10 {
            return Option::None;
        }
        Some(Self { secret })
    }

    /// Verify a 6-digit TOTP code. Allows +/- 1 time step for clock skew.
    pub fn verify(&self, code: &str) -> bool {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let user_code: u32 = match code.parse() {
            Ok(c) => c,
            Err(_) => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let time_step = now / 30;

        // Check current step and +/- 1 for clock skew tolerance
        for offset in [0i64, -1, 1] {
            let step = (time_step as i64 + offset) as u64;
            if self.generate_code(step) == user_code {
                return true;
            }
        }
        false
    }

    /// Generate the otpauth:// URI for QR code scanning.
    pub fn generate_uri(&self, account: &str, issuer: &str) -> String {
        let secret_b32 = base32_encode(&self.secret);
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            percent_encode(issuer),
            percent_encode(account),
            secret_b32,
            percent_encode(issuer),
        )
    }

    /// Generate a random 20-byte secret and return its base32 encoding.
    pub fn generate_secret() -> String {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 20];
        OsRng.fill_bytes(&mut bytes);
        base32_encode(&bytes)
    }

    /// Generate TOTP code for a given time step.
    fn generate_code(&self, time_step: u64) -> u32 {
        let msg = time_step.to_be_bytes();

        // HMAC-SHA1
        let hash = hmac_sha1(&self.secret, &msg);

        // Dynamic truncation
        let offset = (hash[19] & 0x0f) as usize;
        let code = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        code % 1_000_000
    }
}

// ---------------------------------------------------------------------------
// Pending actions (in-memory only, no persistence)
// ---------------------------------------------------------------------------

/// A sensitive action waiting for 2FA verification.
#[derive(Debug, Clone)]
pub struct PendingAction {
    /// What action to execute after verification.
    pub action_type: PendingActionType,
    /// Operator who initiated the action.
    pub operator: String,
    /// When the pending action was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When it expires (5 minutes from creation).
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 2FA method being used for this action.
    pub method: TwoFactorMethod,
}

/// Types of sensitive actions that can be pending 2FA.
#[derive(Debug, Clone)]
pub enum PendingActionType {
    AllowlistProcess(String),
    AllowlistIp(String),
    UndoAllowlist { section: String, key: String },
    AutoFpAllowlist { section: String, entity: String },
}

/// Tracks pending 2FA actions and brute force protection state.
pub struct TwoFactorState {
    /// Pending actions keyed by operator name.
    pub pending: HashMap<String, PendingAction>,
    /// Failed attempt counts per operator per hour.
    failed_attempts: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    /// Max failed attempts per hour before lockout.
    max_failures_per_hour: u32,
}

impl TwoFactorState {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            failed_attempts: HashMap::new(),
            max_failures_per_hour: 3,
        }
    }

    /// Check if an operator is locked out due to too many failed attempts.
    pub fn is_locked_out(&self, operator: &str) -> bool {
        if let Some(attempts) = self.failed_attempts.get(operator) {
            let one_hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
            let recent = attempts.iter().filter(|t| **t > one_hour_ago).count();
            recent >= self.max_failures_per_hour as usize
        } else {
            false
        }
    }

    /// Record a failed 2FA attempt.
    pub fn record_failure(&mut self, operator: &str) {
        let attempts = self
            .failed_attempts
            .entry(operator.to_string())
            .or_default();
        attempts.push(chrono::Utc::now());
        // Prune old entries
        let one_hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
        attempts.retain(|t| *t > one_hour_ago);
        warn!(
            operator = operator,
            recent_failures = attempts.len(),
            "2FA: failed attempt recorded"
        );
    }

    /// Store a pending action for an operator.
    pub fn set_pending(&mut self, operator: &str, action: PendingAction) {
        self.pending.insert(operator.to_string(), action);
    }

    /// Remove and return the pending action for an operator.
    pub fn take_pending(&mut self, operator: &str) -> Option<PendingAction> {
        self.pending.remove(operator)
    }

    /// Clean up expired pending actions (call periodically).
    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now();
        self.pending.retain(|_, a| a.expires_at > now);

        // Also clean up old failure records
        let one_hour_ago = now - chrono::Duration::hours(1);
        for attempts in self.failed_attempts.values_mut() {
            attempts.retain(|t| *t > one_hour_ago);
        }
        self.failed_attempts.retain(|_, a| !a.is_empty());
    }
}

impl Default for TwoFactorState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA1 (minimal implementation for TOTP, no external dep)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA1(key, message).
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    // SHA-1 block size is 64 bytes
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // Hash the key if it's too long
        let hasher = sha1_hash(key);
        key_block[..20].copy_from_slice(&hasher);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // Inner hash: SHA1(ipad || message)
    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha1_hash(&inner_data);

    // Outer hash: SHA1(opad || inner_hash)
    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    sha1_hash(&outer_data)
}

/// Simple SHA-1 implementation for TOTP.
/// TOTP requires SHA-1 (RFC 6238), not SHA-256.
#[allow(clippy::needless_range_loop)]
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    // We need SHA-1 for TOTP. Using a minimal implementation.
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;

    // Padding
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ---------------------------------------------------------------------------
// Base32 encoding/decoding (RFC 4648, no padding required)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let input: String = input
        .trim()
        .chars()
        .filter(|c| *c != '=' && *c != ' ')
        .flat_map(|c| c.to_uppercase())
        .collect();
    if input.is_empty() {
        return Option::None;
    }

    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut output = Vec::new();

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            _ => return Option::None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(output)
}

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[idx] as char);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[idx] as char);
    }
    result
}

/// Minimal percent-encoding for URI components.
fn percent_encode(s: &str) -> String {
    let mut result = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '~' {
            result.push(ch);
        } else {
            for byte in ch.to_string().as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base32_known_values() {
        // RFC 4648 test vectors
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn totp_provider_creation() {
        let secret = base32_encode(&[0u8; 20]);
        let provider = TotpProvider::new(&secret);
        assert!(provider.is_some());

        // Too short secret should fail
        let short_secret = base32_encode(&[0u8; 5]);
        let provider = TotpProvider::new(&short_secret);
        assert!(provider.is_none());
    }

    #[test]
    fn totp_code_generation_deterministic() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let provider = TotpProvider { secret };
        // At time step 0, should produce a deterministic code
        let code = provider.generate_code(0);
        assert!(code < 1_000_000);
        // Same step should produce same code
        assert_eq!(code, provider.generate_code(0));
        // Different step should produce different code (with high probability)
        let code2 = provider.generate_code(1);
        assert!(code2 < 1_000_000);
    }

    #[test]
    fn totp_verify_rejects_bad_input() {
        let secret = base32_encode(&[0x42u8; 20]);
        let provider = TotpProvider::new(&secret).unwrap();
        assert!(!provider.verify(""));
        assert!(!provider.verify("12345")); // too short
        assert!(!provider.verify("1234567")); // too long
        assert!(!provider.verify("abcdef")); // non-numeric
    }

    #[test]
    fn totp_generate_uri_format() {
        let secret = base32_encode(&[0x42u8; 20]);
        let provider = TotpProvider::new(&secret).unwrap();
        let uri = provider.generate_uri("admin@server", "InnerWarden");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("InnerWarden"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn two_factor_state_lockout() {
        let mut state = TwoFactorState::new();
        assert!(!state.is_locked_out("alice"));

        state.record_failure("alice");
        assert!(!state.is_locked_out("alice"));

        state.record_failure("alice");
        assert!(!state.is_locked_out("alice"));

        state.record_failure("alice");
        assert!(state.is_locked_out("alice")); // 3 failures = locked

        // Bob should not be locked out
        assert!(!state.is_locked_out("bob"));
    }

    #[test]
    fn two_factor_state_pending_actions() {
        let mut state = TwoFactorState::new();

        let action = PendingAction {
            action_type: PendingActionType::AllowlistProcess("sshd".to_string()),
            operator: "alice".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            method: TwoFactorMethod::Totp,
        };

        state.set_pending("alice", action);
        assert!(state.pending.contains_key("alice"));

        let taken = state.take_pending("alice");
        assert!(taken.is_some());
        assert!(!state.pending.contains_key("alice"));
    }

    #[test]
    fn two_factor_state_cleanup_expired() {
        let mut state = TwoFactorState::new();

        let expired_action = PendingAction {
            action_type: PendingActionType::AllowlistIp("1.2.3.4".to_string()),
            operator: "alice".to_string(),
            created_at: chrono::Utc::now() - chrono::Duration::minutes(10),
            expires_at: chrono::Utc::now() - chrono::Duration::minutes(5),
            method: TwoFactorMethod::Totp,
        };

        state.set_pending("alice", expired_action);
        assert!(state.pending.contains_key("alice"));

        state.cleanup_expired();
        assert!(!state.pending.contains_key("alice"));
    }

    #[test]
    fn sha1_hash_known_value() {
        // SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let hash = sha1_hash(b"abc");
        assert_eq!(
            hash,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn method_from_str() {
        assert_eq!(TwoFactorMethod::from_str("none"), TwoFactorMethod::None);
        assert_eq!(TwoFactorMethod::from_str("totp"), TwoFactorMethod::Totp);
        assert_eq!(TwoFactorMethod::from_str("TOTP"), TwoFactorMethod::Totp);
        assert_eq!(
            TwoFactorMethod::from_str("dashboard"),
            TwoFactorMethod::Dashboard
        );
        assert_eq!(TwoFactorMethod::from_str("unknown"), TwoFactorMethod::None);
    }

    #[test]
    fn generate_secret_length() {
        let secret = TotpProvider::generate_secret();
        assert!(!secret.is_empty());
        // 20 bytes = 32 base32 chars
        assert!(secret.len() >= 32);
        let decoded = base32_decode(&secret).unwrap();
        assert_eq!(decoded.len(), 20);
    }
}
