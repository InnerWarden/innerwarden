# Implementation Plan: Intelligent Notifications

**Branch**: `005-intelligent-notifications` | **Date**: 2026-04-04 | **Spec**: `spec.md`
**Input**: Feature specification from `.specify/features/005-intelligent-notifications/spec.md`

## Summary

Replace current per-channel batching (Telegram 60s `TelegramBatcher`) with a unified notification pipeline: grouping engine (detector+entity window), per-channel filter levels (all/actionable/critical/none), environment auto-profiling, digests, implicit feedback, and optional AI batch triage. Target: 108 notifications/9h → <10, zero missed real threats.

## Technical Context

**Language/Version**: Rust (edition 2021, workspace)
**Primary Dependencies**: tokio, serde, chrono, vm-detect (existing)
**Storage**: In-memory (grouping) + JSONL append-only (census, feedback) + JSON snapshot (profile)
**Testing**: `cargo test -p innerwarden-agent`
**Target Platform**: Linux server (production: Oracle Cloud Ubuntu)
**Project Type**: Daemon (innerwarden-agent)
**Performance Goals**: First alert within 2s, grouping bounded at 1000 active groups
**Constraints**: Zero additional config required for 90% noise reduction
**Scale/Scope**: Single operator, single server (v1)

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor is Deterministic | PASS — all changes in agent crate, sensor untouched |
| II. Zero FP Over Missing Detections | PASS — grouping suppresses duplicates, never suppresses first occurrence or Critical severity |
| III. Spec-Anchored Development | PASS — spec.md written first, plan follows spec |
| IV. User Experience First | PASS — zero config needed, plain language digests, dashboard always shows everything |
| V. English Commits, Portuguese Conversations | PASS — code and commits in English |
| VI. Test Before Commit | PASS — verification plan includes cargo test |
| VII. CLAUDE.md Local Only | PASS — no CLAUDE.md committed |
| VIII. Minimal Changes | PASS — scoped to notification pipeline, no unrelated refactoring |

## Project Structure

### Documentation (this feature)

```text
.specify/features/005-intelligent-notifications/
├── spec.md          # Feature specification with user stories
├── plan.md          # This file
└── tasks.md         # Implementation tasks
```

### Source Code (affected files)

```text
crates/agent/src/
├── notification_pipeline.rs   # NEW — IncidentGroup, GroupingEngine, ChannelFilter, DigestBuilder
├── environment_profile.rs     # NEW — EnvironmentProfile, bootstrap_profile(), run_census()
├── main.rs                    # MODIFIED — wire pipeline, replace batcher flush
├── incident_notifications.rs  # MODIFIED — dispatch through pipeline
├── telegram.rs                # MODIFIED — remove TelegramBatcher, add send_digest()
├── slack.rs                   # MODIFIED — add send_digest()
├── webhook.rs                 # MODIFIED — add send_digest()
├── web_push.rs                # MODIFIED — respect channel filter
├── config.rs                  # MODIFIED — NotificationPipelineConfig, ChannelFilterLevel, etc.
├── dashboard.rs               # MODIFIED — /api/incident-groups endpoint
└── incident_obvious.rs        # MODIFIED — signal auto_resolved to pipeline
```

**Structure Decision**: No new crates. Two new modules (`notification_pipeline.rs`, `environment_profile.rs`) inside existing `crates/agent/src/`. All other changes are modifications to existing files.

## Design Notes

### GroupingEngine (notification_pipeline.rs)
- Key: `"{detector}:{entity_type}:{entity_value}"`.
- `HashMap<String, IncidentGroup>` bounded at 1000 (LRU eviction on oldest `first_seen`).
- Window: 3600s default (configurable). Count threshold for early summary: 10.
- First incident in group → `notify_immediately = true`. Subsequent → counter only.
- Replaces `TelegramBatcher` entirely (the 60s window was a precursor).

### ChannelFilter (notification_pipeline.rs)
- Enum: `All | Actionable | Critical | None`.
- "Actionable" classification: auto_resolved=false AND (confidence < 0.9 OR severity >= Critical OR firmware/kernel anomaly).
- `incident_obvious.rs` auto-block → sets `auto_resolved = true` on group.
- Backward compat: if `level` not in config, defaults to current behavior (severity threshold).

### EnvironmentProfile (environment_profile.rs)
- `bootstrap_profile()`: vm-detect + /etc/passwd + systemctl + crontab → `environment-profile.json`.
- Effects: cloud → timing threshold x10, admin UIDs → discovery demoted to LOW, known services → expected lineages.
- Census: every 6h, diff against profile, log to `census-YYYY-MM-DD.jsonl`.
- Conservative mode: notify everything until profile ready (max 30 min at first boot).

### DigestBuilder (notification_pipeline.rs)
- Aggregates from closed groups: blocked IPs, review needed, suppressed, top attacker.
- Scheduled at `digest_hour` (default 9, local time).
- Each channel has independent digest config (daily/hourly/none).

### AI Batch Triage (optional, last)
- Disabled by default. At end of window, batch all groups into one prompt.
- AI classifies: URGENT / INFO / SUPPRESS.
- Fallback on API failure: per-group level classification (no AI needed).

### Implicit Feedback (notification_pipeline.rs)
- Track ignored notifications (no tap within 24h) in `notification-feedback.jsonl`.
- After 3 ignored of same detector+entity_type → auto-demote to INFO.
- Loaded at startup.

## Verification

- `cargo fmt --all`
- `cargo clippy -p innerwarden-agent -- -D warnings`
- `cargo test -p innerwarden-agent` — all existing + new tests pass
- Manual: deploy to production server, compare 9h notification count (target: <10 vs 108)
- Success criteria from spec: SC1 (<10/9h), SC2 (zero missed threats), SC3 (dashboard full picture), SC4 (new server works without tuning)

## Complexity Tracking

No constitution violations. No complexity justifications needed.
