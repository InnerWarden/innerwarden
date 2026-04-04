# Tasks: Intelligent Notifications

**Input**: Design documents from `.specify/features/005-intelligent-notifications/`
**Prerequisites**: plan.md (required), spec.md (required for user stories)

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story (US1–US7)
- Exact file paths included

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Config structs and types that all layers depend on.

- [x] T001 [P] [US1] Add `NotificationPipelineConfig` to `crates/agent/src/config.rs` — `group_window_secs` (3600), `group_count_threshold` (10)
- [x] T002 [P] [US2] Add `ChannelFilterLevel` enum (`All`, `Actionable`, `Critical`, `None`) and `level` field to Telegram/Slack/Webhook/WebPush config structs in `crates/agent/src/config.rs`
- [x] T003 [P] [US3] Add `DigestConfig` fields to channel configs in `crates/agent/src/config.rs` — `digest` (daily/hourly/none), `digest_hour` (9)
- [x] T004 [P] [US4] Add `EnvironmentConfig` to `crates/agent/src/config.rs` — `auto_profile` (true), `census_interval_hours` (6), `cloud_timing_multiplier` (10)

**Checkpoint**: All config structs ready. Backward compatible — missing fields use defaults.

---

## Phase 2: User Story 1 — Incident Grouping (Priority: P1)

**Goal**: One notification per attack campaign instead of one per incident.

**Independent Test**: Deploy to production, count Telegram notifications over 9h. Must drop from ~108 to <20.

- [x] T005 [US1] Create `crates/agent/src/notification_pipeline.rs` — `IncidentGroup` struct (first_seen, last_seen, count, severity_max, auto_resolved, sample_incident_id)
- [x] T006 [US1] Implement `GroupingEngine` — key generation (`detector:entity_type:entity_value`), insert, tick, group summary emission
- [x] T007 [US1] Implement sliding window logic — default 3600s, early summary at count threshold (10), window close summary
- [x] T008 [US1] Add LRU eviction at 1000 active groups (evict oldest `first_seen`)
- [x] T009 [US1] Wire `GroupingEngine` into `process_incidents` loop in `crates/agent/src/main.rs` — first-in-group notifies, rest suppressed
- [x] T010 [US1] Remove `TelegramBatcher` from `crates/agent/src/telegram.rs` — replaced by pipeline grouping
- [x] T011 [US1] Refactor `dispatch_incident_notifications` in `crates/agent/src/incident_notifications.rs` to use pipeline (check group state before sending)
- [x] T012 [US1] Add tests: grouping by key, window expiry, count threshold, LRU eviction, first-notify behavior, group summary format

**Checkpoint**: Grouping operational. Telegram noise reduced. All existing tests pass.

---

## Phase 3: User Story 2 — Channel Filter (Priority: P2)

**Goal**: Dashboard receives everything. Telegram receives only actionable items.

**Independent Test**: Set Telegram to `actionable`, verify auto-resolved incidents appear on dashboard but NOT on Telegram.

- [x] T013 [US2] Implement `classify_actionable()` in `notification_pipeline.rs` — auto_resolved → not actionable, confidence < 0.9 → actionable, Critical → always actionable, firmware/kernel → always actionable
- [x] T014 [US2] Modify `incident_obvious.rs` to signal `auto_resolved = true` back to pipeline group when obvious gate handles incident (+ abuseipdb + crowdsec gates)
- [x] T015 [US2] Apply channel filter in `incident_notifications.rs` dispatch — skip notification if group doesn't meet channel's `level`
- [x] T016 [US2] Ensure backward compat: if `level` not set in config, behave like current code (severity threshold only)
- [ ] T017 [US2] Add `/api/incident-groups` endpoint to `crates/agent/src/dashboard.rs` — list active groups with live counters and status
- [x] T018 [US2] Add tests: filter levels (all/actionable/critical/none), actionable classification, backward compat

**Checkpoint**: 90%+ noise reduction achieved. Dashboard full picture. Telegram actionable only.

---

## Phase 4: User Story 3 — Daily Digest (Priority: P3)

**Goal**: Daily summary of what the system handled. Operator sleeps well.

**Independent Test**: Trigger digest manually, verify summary content.

- [x] T019 [US3] Implement `DigestStats` in `notification_pipeline.rs` — accumulate suppressed_count, auto_resolved_groups, needs_review_groups from closed groups
- [x] T020 [US3] Add `format_daily_digest_enriched()` to `crates/agent/src/telegram.rs` — enriched digest with pipeline stats (suppressed, auto-resolved, needs review)
- [x] T021 [US3] Integrate enriched digest into `narrative_daily_summary.rs` — drain pipeline stats and pass to formatter
- [ ] T022 [US3] Add enriched digest to `crates/agent/src/slack.rs` (when Slack daily digest is implemented)
- [ ] T023 [US3] Add enriched digest to `crates/agent/src/webhook.rs` (when webhook digest is implemented)
- [x] T024 [US3] Add tests: digest stats accumulation, drain reset, enriched formatting (simple+technical, with/without pipeline data, needs review case)

**Checkpoint**: Operator gets daily summary. Low effort, high perceived value.

---

## Phase 5: User Story 4 — Environment Bootstrap Profiling (Priority: P4)

**Goal**: Auto-detect cloud/VM, admin UIDs, services. Suppress known noise without config.

**Independent Test**: Deploy on cloud VPS, verify timing threshold auto-adjusted.

- [x] T025 [US4] Create `crates/agent/src/environment_profile.rs` — `EnvironmentProfile` struct (platform, provider, human_uids, services, crons, profiled_at)
- [x] T026 [US4] Implement `bootstrap_profile()` — DMI for cloud/VM (9 providers), /etc/passwd for human UIDs, systemctl, crontab + /etc/crontab + /etc/cron.d
- [x] T027 [US4] Write `environment-profile.json` to `data_dir` on first boot. `load_or_bootstrap()` at agent startup.
- [x] T028 [US4] Apply environment adjustments — cloud suppresses LOW/MEDIUM timing anomalies, admin UID routine detection
- [x] T029 [US4] Conservative mode implicit — default profile suppresses nothing, bootstrap runs sync before first incident
- [x] T030 [US4] Tests: save/load, bootstrap file creation, cloud suppression, bare metal no suppression, admin routine, disabled profiling

**Checkpoint**: Cloud VPS noise (timing anomalies, admin discovery) suppressed automatically.

---

## Phase 6: User Story 5 — Periodic Census (Priority: P5)

**Goal**: Re-profile every 6h. Detect environment changes.

**Independent Test**: Add cron job, verify census logs the change.

- [ ] T031 [US5] Implement `run_census()` in `environment_profile.rs` — diff current state vs stored profile
- [ ] T032 [US5] Write diffs to `census-YYYY-MM-DD.jsonl` in data_dir
- [ ] T033 [US5] Generate alerts for suspicious changes: new UID (not from package), new cron
- [ ] T034 [US5] Schedule census tick in `main.rs` slow loop — every `census_interval_hours` (default 6)
- [ ] T035 [US5] Add tests: diff detection, alert generation for new UID/cron, no alert for removed service

**Checkpoint**: Continuous environment calibration operational.

---

## Phase 7: User Story 6 — Operator Feedback Loop (Priority: P6)

**Goal**: System learns from operator behavior over time.

**Independent Test**: Ignore 3 notifications of same type, verify 4th auto-demoted.

- [ ] T036 [US6] Track ignored notifications in `notification_pipeline.rs` — no operator tap within 24h
- [ ] T037 [US6] Implement auto-demotion: after 3 ignored of same detector+entity_type → demote to INFO
- [ ] T038 [US6] Persist feedback to `notification-feedback.jsonl` in data_dir
- [ ] T039 [US6] Load feedback at startup, apply demotions to pipeline
- [ ] T040 [US6] Add tests: ignore tracking, auto-demotion threshold, persistence round-trip, explicit "Not a threat" demotion

**Checkpoint**: Notification quality improves over time with zero operator effort.

---

## Phase 8: User Story 7 — AI Batch Triage (Priority: P7)

**Goal**: Reduce AI API cost. Optional, disabled by default.

**Independent Test**: Enable `batch_triage`, verify 1 API call per window.

- [ ] T041 [US7] Build batch prompt from all groups at end of window in `notification_pipeline.rs`
- [ ] T042 [US7] Parse AI response (URGENT / INFO / SUPPRESS per group)
- [ ] T043 [US7] Apply AI classification to drive Telegram notification for ambiguous groups
- [ ] T044 [US7] Add config: `batch_triage` (default false), `batch_window_secs` (3600) in `config.rs`
- [ ] T045 [US7] Implement fallback: if API fails, use per-group level classification
- [ ] T046 [US7] Add tests: prompt formatting, response parsing, fallback behavior

**Checkpoint**: AI cost reduced from N calls/window to 1. Optional feature, zero impact if disabled.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (US1 Grouping)**: Depends on T001 from Phase 1
- **Phase 3 (US2 Filter)**: Depends on Phase 2 (groups must exist to filter)
- **Phase 4 (US3 Digest)**: Depends on Phase 2 (aggregates from closed groups)
- **Phase 5 (US4 Profile)**: Depends on Phase 2 (pipeline must exist to apply multipliers)
- **Phase 6 (US5 Census)**: Depends on Phase 5 (profile must exist to diff against)
- **Phase 7 (US6 Feedback)**: Depends on Phase 3 (needs notification tracking)
- **Phase 8 (US7 AI Batch)**: Depends on Phase 2 + Phase 3 (groups + filter)

### Parallel Opportunities

- Phase 1: T001, T002, T003, T004 all in parallel (different config sections)
- Phase 4: T020, T021, T022 in parallel (different channel files)
- Phase 4, 5, 7, 8 can start after Phase 3 (independent of each other)

### Critical Path

```
Phase 1 → Phase 2 (Grouping) → Phase 3 (Filter) → deploy + validate SC1/SC2
                                     ↓
                              Phase 4 (Digest)
                              Phase 5 (Profile) → Phase 6 (Census)
                              Phase 7 (Feedback)
                              Phase 8 (AI Batch)
```

---

## Implementation Strategy

### MVP (Phase 1 + 2 + 3)

1. Complete Phase 1: Config structs
2. Complete Phase 2: Grouping engine
3. Complete Phase 3: Channel filter
4. **STOP and VALIDATE**: Deploy to production, measure SC1 (<10/9h) and SC2 (zero missed threats)
5. If validated, proceed to remaining phases

### Incremental Delivery

Each phase adds independent value:
- After Phase 2: noise reduced from 108 to ~20
- After Phase 3: noise reduced from ~20 to <10 (actionable only)
- After Phase 4: operator gets daily confidence summary
- After Phase 5+6: cloud FPs eliminated automatically
- After Phase 7: system learns and improves
- After Phase 8: AI cost optimized
