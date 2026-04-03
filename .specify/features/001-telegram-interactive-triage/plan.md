# Plan: Telegram Interactive Triage

## Architecture Decision

All changes are in the agent crate. The sensor is NOT modified (constitution principle: sensor is deterministic, no Telegram dependency). The agent writes to `allowlist.toml` which the sensor already reloads every 60s.

## Files to Modify

| File | Changes |
|---|---|
| `crates/agent/src/telegram.rs` | Add allowlist/FP buttons to `send_incident_alert()`, add callback handlers, add `append_to_allowlist()` helper |
| `crates/agent/src/main.rs` | Wire new callback handlers (allowlist, fp) in the approval result processing |

## Technical Approach

### Buttons Layout

Every alert gets a row of triage buttons below existing Block/Ignore/Investigate:

```
[Block IP]  [Ignore]          ← existing (WATCH/DRY-RUN mode)
[Allow this]  [Not a threat]  ← new row
[What does this mean?]        ← existing (simple) / new (technical)
```

### Callback Data Format (< 64 bytes)

- `allow:proc:{comm}` — allowlist a process name
- `allow:ip:{ip}` — allowlist an IP
- `fp:{incident_id_first_50_chars}` — report false positive

### Allowlist Writer

```rust
fn append_to_allowlist(path: &Path, section: &str, key: &str, reason: &str) -> Result<()>
```

Appends to `/etc/innerwarden/allowlist.toml`:
```toml
[processes]
"openclaw" = "Allowed via Telegram by operator (2026-04-02)"
```

Uses file locking (flock) to prevent concurrent writes. Creates file if missing.

### FP Reporter

```rust
fn log_false_positive(data_dir: &Path, incident_id: &str, detector: &str, reporter: &str)
```

Appends to `fp-reports-YYYY-MM-DD.jsonl`:
```json
{"ts":"2026-04-02T16:30:00Z","incident_id":"ssh_bruteforce:...","detector":"ssh_bruteforce","reporter":"Maicon","action":"reported_fp"}
```

### Entity Extraction

From the incident, extract what to allowlist:
- If incident has IP entity: offer `allow:ip:{ip}`
- If incident has comm in evidence: offer `allow:proc:{comm}`
- If both: show two buttons

## Verification

1. `cargo test --workspace` passes
2. `make spec-check` passes  
3. Manual: trigger test alert, tap "Allow this", verify process appears in allowlist.toml
4. Manual: trigger same alert again, verify it no longer fires (within 60s)
5. Manual: tap "Not a threat", verify fp-reports JSONL has entry
