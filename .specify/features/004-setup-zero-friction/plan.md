# Plan: Setup Zero Friction (Day-0 Ready)

## Approach
- Keep current setup as base and add a strict `basic` path with minimal branching.
- Reuse existing detection/connect internals from `agent` commands for in-setup selection.
- Keep Telegram orchestration only; do not rewrite Telegram internals.
- Centralize apply phase so config writes and service restarts happen once.
- Add end-of-setup readiness evaluator with single remediation command.

## Files
- `crates/ctl/src/main.rs`

## Design Notes
- Prioritize deterministic UX over flexibility in `basic` mode.
- Maintain `advanced` mode for expert workflows.
- Keep copy consistent with command namespace (`notify`, `configure`, `agent`).

## Verification
- `cargo fmt --all`
- `cargo check -p innerwarden-ctl`
- targeted setup tests for:
  - basic path step count
  - auto-detected agent selection flow
  - single restart apply phase
  - readiness verdict rendering
