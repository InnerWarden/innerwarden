# Feature: Telegram Triage v2 — 2FA, Undo, Auto-Learn

## Origin
Follow-up to 001-telegram-interactive-triage. User feedback: need 2FA for security, undo for mistakes, and auto-learning from FP reports.

## Problem
v1 lets anyone with the bot token allowlist anything. No way to undo. FP reports are collected but not used.

---

## Feature A: Pluggable 2FA for Sensitive Actions

### Concept
Any action marked as "sensitive" requires a second factor before executing. The 2FA system is pluggable, so the operator chooses the method. This system is reusable beyond Telegram (dashboard, API, future Phantom app).

### Methods (operator chooses during setup)
1. **TOTP** (Google Authenticator, Authy) — operator scans QR during setup, enters 6-digit code for each sensitive action. Works offline, no extra infra.
2. **Dashboard confirmation** — action appears as pending on the dashboard with Approve/Deny buttons. Requires dashboard access.
3. **Email code** — 6-digit code sent via email. Requires SMTP config.
4. **None** — disabled (default for new installs, zero friction).

### What is "sensitive"
- Allowlist a process or IP (adds permanent exception)
- Switch from watch to auto-protect mode
- Disable a detector
- Future: any action the operator marks as sensitive

### Flow
```
Operator taps "Allow this" on Telegram
    → InnerWarden checks if 2FA is enabled
    → If no: executes immediately (v1 behavior)
    → If TOTP: "Enter your 6-digit code"
        → Operator types code in Telegram
        → InnerWarden validates against shared secret
        → If valid: executes + audit log
        → If invalid: "Wrong code. Try again or /cancel"
    → If Dashboard: "Confirm on dashboard within 5 minutes"
        → Pending action appears on dashboard
        → Operator clicks Approve on dashboard
        → Executes + audit log
    → If Email: sends code, same flow as TOTP
```

### Post-Action Confirmation + 2FA Nudge
Every allowlist confirmation includes a 2FA reminder if 2FA is not enabled:

```
✅ "openclaw" added to allowlist. Won't alert on this again.

⚠️ Allowlist changes are not protected by 2FA.
Anyone with your bot token can silence alerts.
[Enable 2FA]  [Dismiss]
```

After 2FA is enabled, the confirmation changes to:
```
✅ "openclaw" added to allowlist (verified by TOTP).
```

No warning, no nudge. Clean confirmation.

The [Enable 2FA] button triggers `innerwarden configure 2fa` instructions
(or links to the dashboard setup page if dashboard is available).

This nudge also appears on:
- Mode change (watch → auto-protect)
- Detector disable
- Any other sensitive action

### Config
```toml
[security]
two_factor_method = "none"  # none, totp, dashboard, email
totp_secret = ""            # base32 encoded, set during setup
email = ""                  # for email method
sensitive_actions = ["allowlist", "mode_change", "disable_detector"]
```

### Setup
```
innerwarden configure 2fa

  Choose your second factor:
  1. TOTP (Google Authenticator)
  2. Dashboard confirmation
  3. Email code
  4. None (disabled)

  Choose [1-4]: 1

  Scan this QR code with your authenticator app:
  [QR displayed as ASCII]

  Enter the 6-digit code to verify: 123456
  ✅ 2FA enabled with TOTP
```

### Reusability
The 2FA module is a standalone component (`crates/agent/src/two_factor.rs`) with a trait:
```rust
trait TwoFactorProvider {
    fn challenge(&self) -> Challenge;
    fn verify(&self, response: &str) -> bool;
}
```
Any future feature (Phantom app, dashboard admin actions, API auth) can use the same trait.

---

## Feature B: Undo Allowlist via Telegram

### Concept
Operator can remove an entry they added from the allowlist. Shows recent additions with a button to remove.

### Flow
```
/undo  or  "Undo" button in /menu

  Recent allowlist additions:
  1. [X] openclaw (added 2h ago by Maicon)
  2. [X] 34.9.16.104 (added 1h ago by Maicon)

  Tap to remove:
  [Remove openclaw]  [Remove 34.9.16.104]
```

### Implementation
- Track additions in `allowlist-history.jsonl` (who, when, what, via which channel)
- Undo = rewrite allowlist.toml without the removed entry
- 2FA required if enabled (removing from allowlist is also sensitive)
- Telegram command: `/undo` or button in /menu

---

## Feature C: Auto-Learn from FP Reports

### Concept
FP reports (`fp-reports-YYYY-MM-DD.jsonl`) feed into two systems:
1. **Autoencoder training**: events marked as FP become "confirmed normal" in training set
2. **Spec updates**: after N FP reports for the same detector pattern, suggest adding a test case to the spec

### Auto-learn flow
```
Operator taps "Not a threat" on Telegram
    → Logged to fp-reports.jsonl (v1, done)
    → Next 3 AM training cycle:
        → Autoencoder reads fp-reports
        → Events matching FP reports get weight=0 (confirmed benign)
        → Model learns these patterns are normal
    → After 3+ FP reports for same detector+pattern:
        → Agent suggests: "ssh_bruteforce from 10.0.0.0/8 reported as FP 5 times. 
           Add to allowlist permanently? [Yes] [No]"
        → If Yes: auto-adds to allowlist.toml
```

### Spec integration
- Monthly: generate a report of top FP patterns from fp-reports
- Each pattern becomes a candidate `false_positive_fixes` entry in the detector spec
- Operator reviews and approves via Telegram or dashboard

---

## Requirements

### Functional
- R1: 2FA is pluggable (TOTP, dashboard, email, none)
- R2: 2FA is optional, default OFF
- R3: TOTP works with Google Authenticator, Authy, 1Password
- R4: Undo shows last 10 allowlist additions
- R5: Undo rewrites allowlist.toml correctly
- R6: Auto-learn feeds FP reports to autoencoder training
- R7: Auto-learn suggests permanent allowlist after 3+ same-pattern FPs
- R8: All actions audited (who, when, what, via which channel, 2FA method)

### Non-Functional
- NF1: TOTP secret stored encrypted in agent.env (not plaintext in toml)
- NF2: 2FA timeout: 5 minutes to respond
- NF3: Max 3 failed 2FA attempts per hour (brute force protection)
- NF4: Undo is atomic (no partial rewrites of allowlist.toml)
- NF5: Auto-learn never auto-allowlists without operator confirmation

### Success Criteria
- SC1: Operator can enable 2FA in < 2 minutes
- SC2: 2FA adds < 10 seconds to allowlist action
- SC3: Undo works correctly even with concurrent allowlist writes
- SC4: After 1 week of FP reports, autoencoder FP rate drops measurably
