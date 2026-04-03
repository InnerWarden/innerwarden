# Tasks: Telegram Interactive Triage

## Task 1: Add triage buttons to alerts
- [ ] In `send_incident_alert()`, add a new keyboard row with "Allow this" + "Not a threat" buttons
- [ ] Extract comm and IP from incident for callback data
- [ ] Adapt button text per profile (simple vs technical)
- [ ] Extend "What does this mean?" button to technical profile too

## Task 2: Implement allowlist writer
- [ ] Create `append_to_allowlist(path, section, key, reason)` function in telegram.rs
- [ ] Write to `[processes]` section for comm, `[ips]` section for IP
- [ ] Include Telegram operator name and timestamp in reason
- [ ] Handle file creation if allowlist.toml doesn't exist

## Task 3: Implement FP reporter
- [ ] Create `log_false_positive(data_dir, incident_id, detector, reporter)` function
- [ ] Write to `fp-reports-YYYY-MM-DD.jsonl`
- [ ] Include ts, incident_id, detector, reporter, action fields

## Task 4: Wire callback handlers in main.rs
- [ ] Handle `allow:proc:{comm}` callback: call append_to_allowlist, send confirmation
- [ ] Handle `allow:ip:{ip}` callback: call append_to_allowlist, send confirmation
- [ ] Handle `fp:{incident_id}` callback: call log_false_positive, send confirmation
- [ ] Confirmation messages: "Allowed. Won't alert on this again." / "Reported. Thanks for the feedback."

## Task 5: Tests
- [ ] Test append_to_allowlist creates/appends correctly
- [ ] Test log_false_positive writes valid JSONL
- [ ] Full workspace clippy + test pass

## Dependencies
- Task 2, 3 before Task 4
- Task 1 before Task 4 (buttons must exist for callbacks)
- Task 5 after all others
