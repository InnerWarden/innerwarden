# Tasks: Telegram Triage v2

## Epic C: Auto-Learn from FP Reports

### C1: Feed FP reports to autoencoder training
- [ ] In neural_lifecycle.rs train_nightly(), read fp-reports-*.jsonl
- [ ] Build HashSet of (detector, comm_or_ip) confirmed FP pairs
- [ ] During feature extraction, reduce weight for matching events (x0.1)
- [ ] Log: "autoencoder: incorporated N FP reports into training"

### C2: Auto-suggest permanent allowlist
- [ ] In narrative tick, count FP reports by (detector, entity) from last 7 days
- [ ] If count >= 3 and entity not in allowlist, send Telegram suggestion
- [ ] Suggestion buttons: [Yes, add permanently] [No, keep monitoring]
- [ ] Yes callback: append to allowlist.toml + confirmation message

### C3: Tests for auto-learn
- [ ] Test FP report reading and weight reduction
- [ ] Test suggestion threshold (< 3 = no suggest, >= 3 = suggest)

---

## Epic B: Undo Allowlist

### B1: Allowlist history tracking
- [ ] Create allowlist-history.jsonl writer (append on every add/remove)
- [ ] Modify v1 allowlist add to also write history entry
- [ ] Fields: ts, key, section, reason, operator, action (add/remove)

### B2: /undo Telegram command
- [ ] Add /undo command routing (like /menu, /status)
- [ ] Show last 10 "add" entries without matching "remove"
- [ ] Each entry gets a [Remove] inline button
- [ ] Callback: `undo:{key}:{section}`

### B3: Atomic allowlist rewrite
- [ ] Read current allowlist.toml, parse all sections
- [ ] Remove target entry
- [ ] Write to temp file, rename over original (atomic)
- [ ] Write "remove" entry to history
- [ ] Send confirmation: "Removed {key} from allowlist"

### B4: Tests for undo
- [ ] Test history write on add
- [ ] Test atomic rewrite preserves other entries
- [ ] Test remove non-existent entry (graceful error)

---

## Epic A: Pluggable 2FA

### A1: TwoFactor trait + TOTP implementation
- [ ] Create crates/agent/src/two_factor.rs
- [ ] Trait: challenge() -> Challenge, verify(response) -> bool
- [ ] TOTP impl using totp-rs crate
- [ ] Add totp-rs to Cargo.toml

### A2: Config
- [ ] Add [security] section to config.rs
- [ ] Fields: two_factor_method, totp_secret, sensitive_actions
- [ ] Parse method: none/totp/dashboard/email
- [ ] Default: none

### A3: Setup wizard
- [ ] Add `innerwarden configure 2fa` command in ctl
- [ ] TOTP: generate secret, show QR as ASCII, verify first code
- [ ] Store secret encrypted in agent.env (not plaintext toml)

### A4: Telegram integration
- [ ] Intercept sensitive actions before execution
- [ ] If 2FA enabled: send challenge message, wait for response
- [ ] TOTP: "Enter your 6-digit code" → validate
- [ ] Dashboard: "Confirm on dashboard within 5 minutes" → poll pending
- [ ] Timeout: 5 minutes, then cancel
- [ ] Brute force: max 3 failures per hour per operator

### A5: Dashboard pending actions
- [ ] GET /api/2fa/pending — list pending actions
- [ ] POST /api/2fa/approve/{id} — approve pending action
- [ ] POST /api/2fa/deny/{id} — deny pending action
- [ ] Actions expire after 5 minutes

### A6: Tests for 2FA
- [ ] Test TOTP generation and validation
- [ ] Test brute force lockout (4th attempt blocked)
- [ ] Test timeout (expired action rejected)
- [ ] Test none method (passthrough, no challenge)

---

## Dependencies

```
C1 → C2 → C3
B1 → B2 → B3 → B4
A1 → A2 → A3 → A4 → A5 → A6
C before B (history format needed)
B before A (undo needs to work before 2FA protects it)
```

## Estimated Effort
- Epic C: 2h
- Epic B: 3h
- Epic A: 5h
- Total: ~10h
