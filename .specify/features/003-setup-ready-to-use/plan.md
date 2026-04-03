# Plan: Setup Ready To Use

## Approach
- Refactor `cmd_setup` into a short guided flow with explicit review and post-apply validation.
- Reuse the existing Telegram helper instead of rewriting its prompt sequence.
- Apply AI configuration directly inside setup so the wizard can stay in control of the experience.
- Reuse the existing `agent connect` selection flow at the end of setup.

## Files
- `crates/ctl/src/main.rs`

## Design Notes
- Keep the common path focused on four decisions: experience, AI, alerts, protection.
- Treat mesh as an explicit opt-in.
- Treat safe defaults as a separate pre-step with one confirmation.
- End with a checklist, not a “go run doctor now” instruction.

## Verification
- `cargo fmt --all`
- `cargo check -p innerwarden-ctl`
- targeted unit tests for setup helpers
