# Plan: Telegram Triage v2

## Implementation Order

Feature C (auto-learn) first because it's the simplest and highest value. Then B (undo) because it's needed before 2FA. Then A (2FA) because it's the most complex and benefits from B being done.

## Feature C: Auto-Learn (2h)

### Files
| File | Changes |
|---|---|
| `crates/agent/src/neural_lifecycle.rs` | Read fp-reports during training, set weight=0 for matching events |
| `crates/agent/src/main.rs` | After 3+ same-pattern FPs, send suggestion to Telegram |

### Approach
In `train_nightly()`, before training:
1. Read all `fp-reports-*.jsonl` from last 7 days
2. Build a set of (detector, comm/ip) pairs that are confirmed FP
3. During feature extraction, if event matches a confirmed FP pair, reduce its weight in training (multiply features by 0.1 instead of 1.0)
4. This teaches the autoencoder that these patterns are "normal"

For auto-suggest:
1. In the narrative tick, count FP reports by (detector, entity) pair
2. If count >= 3 and entity not already in allowlist, send Telegram suggestion
3. Suggestion has [Yes] [No] buttons
4. Yes = append to allowlist.toml

## Feature B: Undo (3h)

### Files
| File | Changes |
|---|---|
| `crates/agent/src/telegram.rs` | Add /undo command handler, show recent additions, remove buttons |
| `crates/agent/src/main.rs` | Wire /undo callback, implement allowlist rewrite |

### Approach
Track additions in `allowlist-history.jsonl`:
```json
{"ts":"...","key":"openclaw","section":"processes","reason":"...","operator":"Maicon","action":"add"}
{"ts":"...","key":"openclaw","section":"processes","operator":"Maicon","action":"remove"}
```

Undo = read current allowlist.toml, parse sections, remove the entry, rewrite file. Use temp file + rename for atomicity.

/undo command shows last 10 "add" entries that don't have a matching "remove". Each gets a button.

## Feature A: 2FA (5h)

### Files
| File | Changes |
|---|---|
| `crates/agent/src/two_factor.rs` | New module: TwoFactorProvider trait + TOTP + Dashboard + Email implementations |
| `crates/agent/src/config.rs` | Add [security] section with two_factor_method, totp_secret, etc. |
| `crates/agent/src/telegram.rs` | Intercept sensitive actions, challenge, verify |
| `crates/agent/src/main.rs` | Wire 2FA into allowlist/mode_change/disable flows |
| `crates/agent/src/dashboard.rs` | Add /api/2fa/pending endpoint for dashboard confirmation |
| `crates/ctl/src/main.rs` | Add `innerwarden configure 2fa` command with QR display |

### TOTP Implementation
Use `totp-rs` crate (pure Rust, no C deps):
```rust
use totp_rs::{Algorithm, TOTP, Secret};

let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)?;
let is_valid = totp.check_current(user_code)?;
```

QR code for setup: generate otpauth:// URI, render as ASCII art (or URL to chart API).

### Pending Actions Store
```rust
struct PendingAction {
    id: String,
    action: SensitiveAction,  // AllowlistAdd, ModeChange, DisableDetector
    operator: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    two_factor_method: TwoFactorMethod,
}
```

Stored in memory (HashMap), expires after 5 minutes. Max 10 pending per operator.

### Brute Force Protection
Track failed attempts per operator per hour. After 3 failures, lock for 15 minutes. Log all attempts.

## Dependencies

```
Feature C (auto-learn)
    ↓
Feature B (undo)
    ↓
Feature A (2FA)
    ↓
Integration testing
```

## Verification

1. `cargo test --workspace` passes
2. `make spec-check` passes
3. Manual: enable TOTP, tap Allow, enter wrong code (rejected), enter right code (accepted)
4. Manual: /undo shows recent additions, remove one, verify allowlist.toml updated
5. Manual: report 3+ FPs for same detector, verify auto-suggest message appears
6. Manual: after nightly training, verify autoencoder weights adjusted for FP patterns
