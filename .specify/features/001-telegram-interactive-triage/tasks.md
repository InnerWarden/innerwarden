# Tasks: Telegram Interactive Triage

## Task 1: Add triage buttons to alerts
- [x] In `send_incident_alert()`, add a new keyboard row with "Allow this" + "Not a threat" buttons
- [x] Extract comm and IP from incident for callback data
- [x] Adapt button text per profile (simple vs technical)
- [x] Extend "What does this mean?" button to technical profile too

## Task 2: Implement allowlist writer
- [x] Create `append_to_allowlist(path, section, key, reason)` function in telegram.rs
- [x] Write to `[processes]` section for comm, `[ips]` section for IP
- [x] Include Telegram operator name and timestamp in reason
- [x] Handle file creation if allowlist.toml doesn't exist

## Task 3: Implement FP reporter
- [x] Create `log_false_positive(data_dir, incident_id, detector, reporter)` function
- [x] Write to `fp-reports-YYYY-MM-DD.jsonl`
- [x] Include ts, incident_id, detector, reporter, action fields

## Task 4: Wire callback handlers in main.rs
- [x] Handle `allow:proc:{comm}` callback: call append_to_allowlist, send confirmation
- [x] Handle `allow:ip:{ip}` callback: call append_to_allowlist, send confirmation
- [x] Handle `fp:{incident_id}` callback: call log_false_positive, send confirmation
- [x] Confirmation messages: "Allowed. Won't alert on this again." / "Reported. Thanks for the feedback."

## Task 5: Tests
- [x] Test append_to_allowlist creates/appends correctly
- [x] Test log_false_positive writes valid JSONL
- [x] Full workspace clippy + test pass

## Status: CONCLUIDA
Implementado em `crates/agent/src/telegram.rs`. Auditado em 2026-04-04.
