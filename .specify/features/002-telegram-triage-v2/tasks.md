# Tasks: Telegram Triage v2

## Epic C: Auto-Learn from FP Reports — CONCLUIDA

### C1: Feed FP reports to autoencoder training
- [x] In neural_lifecycle.rs train_nightly(), read fp-reports-*.jsonl
- [x] Build HashSet of (detector, comm_or_ip) confirmed FP pairs
- [x] During feature extraction, reduce weight for matching events (x0.1)
- [x] Log: "autoencoder: incorporated N FP reports into training"

### C2: Auto-suggest permanent allowlist
- [x] In narrative tick, count FP reports by (detector, entity) from last 7 days
- [x] If count >= 3 and entity not in allowlist, send Telegram suggestion
- [x] Suggestion buttons: [Yes, add permanently] [No, keep monitoring]
- [x] Yes callback: append to allowlist.toml + confirmation message

Implementado em `narrative_autofp.rs`.

### C3: Tests for auto-learn
- [x] Test FP report reading and weight reduction
- [x] Test suggestion threshold (< 3 = no suggest, >= 3 = suggest)

---

## Epic B: Undo Allowlist — CONCLUIDA

### B1: Allowlist history tracking
- [x] Create allowlist-history.jsonl writer (append on every add/remove)
- [x] Modify v1 allowlist add to also write history entry
- [x] Fields: ts, key, section, reason, operator, action (add/remove)

### B2: /undo Telegram command
- [x] Add /undo command routing (like /menu, /status)
- [x] Show last 10 "add" entries without matching "remove"
- [x] Each entry gets a [Remove] inline button
- [x] Callback: `undo:{key}:{section}`

### B3: Atomic allowlist rewrite
- [x] Read current allowlist.toml, parse all sections
- [x] Remove target entry
- [x] Write to temp file, rename over original (atomic)
- [x] Write "remove" entry to history
- [x] Send confirmation: "Removed {key} from allowlist"

Implementado em `telegram.rs`: `remove_from_allowlist()` (l.2880), temp + rename (l.2917-2933).

### B4: Tests for undo
- [ ] Test history write on add
- [ ] Test atomic rewrite preserves other entries
- [ ] Test remove non-existent entry (graceful error)

Nota: funcoes existem e sao testadas indiretamente, mas nao ha testes unitarios dedicados para undo.

---

## Epic A: Pluggable 2FA — PARCIALMENTE CONCLUIDA

### A1: TwoFactor trait + TOTP implementation
- [x] Create crates/agent/src/two_factor.rs
- [x] Trait: challenge() -> Challenge, verify(response) -> bool
- [x] TOTP impl using pure-Rust SHA-1 (sem dep externa)
- [x] 12 testes unitarios (generation, verification, lockout, pending, expiry, cleanup)

### A2: Config
- [x] Add [security] section to config.rs
- [x] Fields: two_factor_method, totp_secret
- [x] Parse method: none/totp/dashboard
- [x] Default: none

### A3: Setup wizard
- [x] Add `innerwarden configure 2fa` command in ctl (`commands/ops.rs`)
- [x] TOTP: generate secret, show QR as ASCII, verify first code

### A4: Telegram integration
- [ ] Intercept sensitive actions before execution (TwoFactorState existe em AgentState mas nunca e consumido no fluxo)
- [ ] If 2FA enabled: send challenge message, wait for response
- [ ] TOTP: "Enter your 6-digit code" → validate
- [ ] Timeout: 5 minutes, then cancel
- [ ] Brute force: max 3 failures per hour per operator

### A5: Dashboard pending actions
- [ ] GET /api/2fa/pending — list pending actions
- [ ] POST /api/2fa/approve/{id} — approve pending action
- [ ] POST /api/2fa/deny/{id} — deny pending action
- [ ] Actions expire after 5 minutes

### A6: Tests for 2FA
- [x] Test TOTP generation and validation
- [x] Test brute force lockout (4th attempt blocked)
- [x] Test timeout (expired action rejected)
- [x] Test none method (passthrough, no challenge)
- [ ] Testes de integracao com fluxo Telegram (depende de A4)
- [ ] Testes de endpoints dashboard (depende de A5)

---

## Resumo

| Epic | Status | Pendente |
|------|--------|----------|
| C — Auto-Learn | ✅ Concluida | — |
| B — Undo | ✅ Funcional, faltam testes unitarios dedicados | B4 |
| A — 2FA | Parcial: trait/config/setup prontos, integracao pendente | A4, A5 |

## Proximos passos

1. **A4**: Integrar `TwoFactorState` no fluxo de callbacks do Telegram (allowlist, undo, mode change)
2. **A5**: Endpoints dashboard para aprovacao de 2FA
3. **B4**: Testes unitarios para undo (baixa prioridade, funcionalidade ja opera)

Auditado em 2026-04-04.
