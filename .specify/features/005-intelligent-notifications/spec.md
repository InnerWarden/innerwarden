# Feature Specification: Intelligent Notifications

**Feature Branch**: `005-intelligent-notifications`
**Created**: 2026-04-04
**Status**: Planned
**Input**: Production server received 108 Telegram notifications in 9 hours — only ~3 needed human action.

## Origin

Production server received 108 Telegram notifications in 9 hours (2026-04-04). Most were noise: repeated SSH bruteforce from same IP (28x), timing anomalies from cloud hypervisor jitter (15x), discovery bursts from local admin (17x). Only ~3 incidents required human attention. Current system treats every incident as isolated event and notifies immediately.

## Problem

1. Every incident generates a Telegram notification regardless of context.
2. No grouping: same attacker IP triggers 28 separate alerts.
3. No environment awareness: cloud hypervisor jitter flagged as rootkit repeatedly.
4. No distinction between auto-resolved and needs-human-action.
5. Dashboard and Telegram receive identical notifications — no channel differentiation.
6. Operators on different servers will have different noise profiles, so hardcoded thresholds don't work.

## Goals

- Reduce Telegram noise by 90%+ without missing real threats.
- Dashboard receives everything (grouped, with status) — investigation tool.
- Telegram receives only actionable items — action tool.
- System adapts to each server's environment automatically.
- Zero configuration required for reasonable defaults. Advanced tuning available.

---

## User Scenarios & Testing

### User Story 1 — Incident Grouping (Priority: P1)

Operator receives one notification per attack campaign instead of one per incident. Same attacker IP hitting SSH bruteforce 28 times = 1 alert + counter, not 28 separate messages.

**Why this priority**: Highest impact on noise reduction. No dependencies. Immediately fixes the 108→~15 notification problem.

**Independent Test**: Deploy to production server, count Telegram notifications over 9h. Must drop from ~108 to <20 with zero missed Critical/High incidents.

**Acceptance Scenarios**:

1. **Given** SSH bruteforce from same IP, **When** 10 incidents fire within 1h, **Then** operator receives 1 immediate alert + 1 group summary (not 10 alerts).
2. **Given** first incident from a new attacker, **When** incident fires, **Then** operator receives immediate notification within 2 seconds.
3. **Given** group reaches count threshold (10), **When** threshold crossed, **Then** early group summary emitted without waiting for window close.

---

### User Story 2 — Channel Filter (Priority: P2)

Dashboard receives everything (investigation tool). Telegram receives only items that need human decision. Auto-blocked IPs with AbuseIPDB score 100 don't buzz the operator's phone.

**Why this priority**: Combined with grouping, this is the difference between "fewer alerts" and "only actionable alerts". Estimated 90%+ reduction.

**Independent Test**: Configure Telegram to `actionable`, verify auto-resolved incidents appear on dashboard but NOT on Telegram.

**Acceptance Scenarios**:

1. **Given** auto-blocked IP (obvious gate, AbuseIPDB 100), **When** incident fires, **Then** dashboard shows it, Telegram does NOT notify.
2. **Given** AI decided with confidence < 0.9, **When** incident fires, **Then** Telegram notifies (needs review).
3. **Given** Critical severity incident, **When** incident fires, **Then** Telegram ALWAYS notifies regardless of auto-resolution.

---

### User Story 3 — Daily Digest (Priority: P3)

Operator receives a daily summary of what the system handled overnight. Provides confidence that the system is working without needing to check the dashboard.

**Why this priority**: Low effort, high perceived value. Depends on grouping data from US1.

**Independent Test**: Trigger digest manually, verify summary includes blocked IPs, review-needed count, suppressed counts, top attacker.

**Acceptance Scenarios**:

1. **Given** configured `digest_hour = 9`, **When** 9:00 local time, **Then** Telegram sends daily digest with aggregated stats.
2. **Given** no incidents in last 24h, **When** digest fires, **Then** sends "all quiet" summary (not skipped).

---

### User Story 4 — Environment Calibration (Priority: P4)

System auto-detects cloud VPS, known admin UIDs, and running services. Cloud timing anomalies suppressed automatically. Admin discovery bursts demoted. No manual tuning needed.

**Why this priority**: Reduces FP without operator intervention. Depends on US1 grouping + US2 filtering.

**Independent Test**: Deploy on cloud VPS, verify timing anomaly threshold multiplied by 10x automatically. Verify local admin discovery demoted to LOW.

**Acceptance Scenarios**:

1. **Given** cloud VPS detected (via vm-detect), **When** timing anomaly fires, **Then** threshold multiplied by `cloud_timing_multiplier` (default 10x).
2. **Given** human UID 1001 detected, **When** discovery burst from uid 1001, **Then** severity demoted to LOW.
3. **Given** first boot with no profile, **When** agent starts, **Then** conservative mode (notify everything) for max 30 minutes until profile ready.

---

### User Story 5 — Periodic Census (Priority: P5)

System re-profiles the environment every 6 hours. Detects new services, UIDs, cron jobs. Alerts on suspicious changes.

**Why this priority**: Continuous calibration. Depends on US4 bootstrap profiling.

**Independent Test**: Add a new cron job, verify census detects it within 6h and logs the change.

**Acceptance Scenarios**:

1. **Given** new UID created (not from package install), **When** census runs, **Then** alert generated.
2. **Given** new cron job added, **When** census runs, **Then** alert generated.
3. **Given** service removed, **When** census runs, **Then** logged (no alert).

---

### User Story 6 — Operator Feedback Loop (Priority: P6)

System learns from operator behavior. Ignored notifications get auto-demoted after 3 instances. Explicit "Not a threat" taps immediately demote.

**Why this priority**: Learning over time. Builds on all previous layers.

**Independent Test**: Ignore 3 notifications of same type, verify 4th is auto-demoted.

**Acceptance Scenarios**:

1. **Given** operator ignores group notification 3 times (same detector+entity_type), **When** 4th instance fires, **Then** auto-demoted to INFO.
2. **Given** operator taps "Not a threat", **When** tapped, **Then** immediate demotion + FP report.

---

### User Story 7 — AI Batch Triage (Priority: P7)

Instead of AI call per incident, batch all groups at end of window into single prompt. Reduces API cost.

**Why this priority**: Optional optimization. Disabled by default. Depends on all other layers.

**Independent Test**: Enable `batch_triage`, verify 1 API call per window instead of N.

**Acceptance Scenarios**:

1. **Given** `batch_triage = true` and 5 groups in window, **When** window closes, **Then** 1 AI call classifies all 5 groups.
2. **Given** AI API fails, **When** batch triage attempted, **Then** fallback to per-group level classification (no AI needed).

---

## Architecture: 5 Layers

### Layer 1 — Incident Grouping (local, no AI, no network)

Group incidents by `detector + primary_entity` within a sliding time window.

Rules:
- Same detector + same entity (IP, user, syscall) = 1 group.
- Window: 1 hour (configurable via `notification_group_window_secs`, default 3600).
- First incident in group: notify immediately (per channel config).
- Subsequent incidents: increment counter, do NOT notify.
- On group close (window expires or count threshold): emit group summary.
- Count threshold for early summary: 10 (configurable).

Group data structure (in-memory):
```
key: "{detector}:{entity_type}:{entity_value}"
value: {
    first_seen: DateTime,
    last_seen: DateTime,
    count: u32,
    severity_max: Severity,
    auto_resolved: bool,
    sample_incident_id: String,
}
```

Dashboard receives: all groups with live counters (updated every tick).
Telegram receives: governed by Layer 3 filter.

### Layer 2 — Environment Calibration

#### 2a — Bootstrap profiling (runs once at setup or first boot)

Detects:
- Cloud/VM vs bare metal (via vm-detect crate, already exists).
- Active UIDs and their roles (human admin vs service account).
- Running services (systemd units).
- Cron jobs.

Outputs an environment profile stored at `data_dir/environment-profile.json`:
```json
{
  "platform": "cloud_vps",
  "provider": "oracle",
  "human_uids": [1001],
  "services": ["innerwarden-agent", "nginx", "node"],
  "crons": ["certbot-renew"],
  "profiled_at": "2026-04-04T10:00:00Z"
}
```

Effects on detection:
- `platform: cloud_vps` → timing anomaly threshold multiplied by 10x (jitter expected).
- `human_uids: [1001]` → discovery burst from uid 1001 demoted to LOW.
- `services: [node]` → `node → sh` lineage marked as expected.

#### 2b — Periodic census (runs every 6 hours)

Diffs against previous profile:
- New service detected → log + update baseline (no alert unless suspicious).
- Service removed → log.
- New UID → alert if not from package install.
- New cron → alert.

Stored as `data_dir/census-YYYY-MM-DD.jsonl` for audit trail.

### Layer 3 — Notification Channel Filter

Each notification channel has an independent filter level.

```toml
[notifications.telegram]
level = "actionable"       # default
digest = "daily"           # "daily", "hourly", "none"
digest_hour = 9            # hour (local time) for daily digest

[notifications.dashboard]
level = "all"              # default — dashboard always gets everything

[notifications.webhook]
level = "actionable"       # same options as telegram

[notifications.slack]
level = "critical"         # example: slack only for critical
```

Filter levels:
- `"all"` — every incident group (first event + summaries).
- `"actionable"` — only groups that need human decision (not auto-resolved, ambiguous, or above confidence threshold).
- `"critical"` — only HIGH/CRITICAL that are not auto-resolved.
- `"none"` — silent, only digest.

Classification of "actionable":
- Auto-blocked with AbuseIPDB score 100 → NOT actionable (resolved).
- Auto-blocked by obvious gate (reincident) → NOT actionable (resolved).
- AI decided with confidence >= 0.9 and auto-executed → NOT actionable.
- AI decided with confidence < 0.9 → ACTIONABLE (needs review).
- RequestConfirmation → ACTIONABLE.
- severity == Critical → ALWAYS actionable regardless of confidence.
- Firmware/kernel anomaly → ALWAYS actionable.

### Layer 4 — AI Batch Triage (optional, reduces cost)

Instead of calling AI per-incident, batch groups at end of window:

```
"In the last hour on this cloud VPS:
- 5x timing anomaly on process.prctl (cloud environment, likely jitter)
- 12x SSH bruteforce from 8 IPs (all auto-blocked, AbuseIPDB 100)
- 3x discovery burst from uid 1001 (local admin)
- 1x wget /etc/passwd → external IP (CRITICAL)

Classify each group: URGENT / INFO / SUPPRESS"
```

AI response drives Telegram notification for ambiguous cases.
Reduces API calls from N to 1 per window.
Optional: disabled by default, enabled with `[ai] batch_triage = true`.

### Layer 5 — Operator Feedback Loop

Already partially implemented (FP reports, auto-FP suggestions, allowlist via Telegram).

New addition: **implicit feedback**.
- Operator ignores a group notification (no tap for 24h) → system notes pattern.
- After 3 ignored instances of same detector+entity_type → auto-demote to INFO.
- Operator taps "Not a threat" → immediate demotion + FP report.
- Operator taps "Block" or "Allow" → positive signal, keep alerting similar.

Stored in `data_dir/notification-feedback.jsonl`.

---

## Digest Message

Daily (or hourly) summary sent to Telegram:

```
📊 Daily Security Digest (Apr 4)

🚫 42 IPs blocked (38 auto, 4 by operator)
⚠️ 3 incidents need review
✅ 15 timing anomalies suppressed (cloud profile)
🔇 12 discovery bursts suppressed (local admin)

Top attacker: 82.165.66.87 (28 attempts, blocked)
```

---

## Configuration

```toml
[notifications]
group_window_secs = 3600          # 1h grouping window
group_count_threshold = 10        # early summary at N events

[notifications.telegram]
level = "actionable"
digest = "daily"
digest_hour = 9

[notifications.dashboard]
level = "all"

[notifications.webhook]
level = "actionable"
digest = "none"

[environment]
auto_profile = true               # bootstrap profiling on first boot
census_interval_hours = 6         # periodic census
cloud_timing_multiplier = 10      # timing threshold multiplier for cloud

[ai]
batch_triage = false              # opt-in batch triage
batch_window_secs = 3600          # batch window for AI triage
```

All values have sane defaults. Zero config needed for a good experience.

---

## Functional Requirements

- R1: Incidents grouped by detector+entity within configurable window.
- R2: First incident in group notifies immediately (per channel level).
- R3: Subsequent incidents in group do NOT trigger individual notifications.
- R4: Group summary emitted on window close or count threshold.
- R5: Dashboard receives all groups with live counters.
- R6: Telegram (and other channels) filter by level: all/actionable/critical/none.
- R7: Environment profile generated on first boot, updated every census.
- R8: Cloud detection auto-adjusts timing anomaly thresholds.
- R9: Known admin UIDs auto-detected, their routine activity demoted.
- R10: Daily digest summarizes auto-resolved activity.
- R11: Operator feedback (explicit and implicit) adjusts future classification.

## Non-Functional Requirements

- NF1: Grouping must not delay first alert by more than 2 seconds.
- NF2: Memory for grouping: bounded at 1000 active groups max.
- NF3: Census must complete in < 5 seconds.
- NF4: AI batch triage (if enabled): 1 API call per window, not per incident.
- NF5: Zero additional config required for 90% noise reduction vs current behavior.
- NF6: All thresholds configurable for advanced operators.

## Success Criteria

- SC1: On the production server, notifications drop from ~108/9h to < 10/9h.
- SC2: Zero real threats (critical/high, not auto-resolved) are suppressed.
- SC3: Dashboard shows full incident picture with grouping and status.
- SC4: New server install produces reasonable notifications without tuning.

## Edge Cases

- E1: First boot with no profile yet → conservative mode (notify everything until profile ready, max 30 minutes).
- E2: Two different attackers hit same detector at same time → group by entity, not just detector.
- E3: Attacker changes IP mid-session → correlation engine links them, group follows.
- E4: Census detects malware disguised as service → new service alert triggers investigation.
- E5: All notification channels set to "none" → digest still shows on dashboard, no Telegram.
- E6: AI batch triage API fails → fall back to per-group level classification (no AI needed for actionable filter).

## Out of Scope

- Custom notification rules per detector (future — per-detector overrides).
- Mobile push notifications (Web Push already exists, separate feature).
- Multi-operator notification preferences (single operator assumed for v1).
- Notification deduplication across multiple InnerWarden nodes (mesh feature).

---

## Implementation Priority

1. **Layer 1 — Grouping** (highest impact, no dependencies).
2. **Layer 3 — Channel filter** (immediate value with grouping).
3. **Digest message** (low effort, high perceived value).
4. **Layer 2a — Bootstrap profiling** (reduces false positives).
5. **Layer 2b — Periodic census** (continuous calibration).
6. **Layer 5 — Implicit feedback** (learning over time).
7. **Layer 4 — AI batch triage** (optional optimization).
