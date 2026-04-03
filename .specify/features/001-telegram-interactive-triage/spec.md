# Feature: Telegram Interactive Triage

## Origin
From `ideias/telegram-interactive-triage.md`. Identified during Caldera validation (2026-04-01): operators cannot resolve false positives without changing code.

## Problem
When InnerWarden alerts on a false positive (e.g., OpenClaw reading .env, cargo build looking like ransomware), the operator has to SSH into the server, edit allowlist.toml, and wait for the sensor to reload. This is too slow and too technical for non-technical users.

## Solution
Add three interactive buttons to every Telegram alert:

### 1. Allowlist Button
- Adds the process name (comm) or IP to `/etc/innerwarden/allowlist.toml`
- Sensor reloads allowlist every 60s (already implemented)
- No code change, no restart, no SSH needed
- Button text: "Allow this" (simple profile) / "Add to allowlist" (technical)
- Callback: `allowlist:{detector}:{entity}` (entity = comm or IP)

### 2. Explain Button (extend existing)
- Already exists for simple profile ("What does this mean?")
- Extend to technical profile too
- Both profiles get the button

### 3. Report FP Button
- Logs the incident to `fp-reports-YYYY-MM-DD.jsonl` in data_dir
- Fields: ts, incident_id, detector, reporter (Telegram username), action taken
- Used for: training data for autoencoder, future spec updates, FP rate tracking
- Button text: "Not a threat" (simple) / "Report FP" (technical)
- Callback: `fp:{incident_id_short}`

## Requirements

### Functional
- R1: Every alert (both profiles) shows Allowlist + Report FP buttons
- R2: Allowlist button writes to allowlist.toml immediately
- R3: Allowlist supports both process names and IPs
- R4: Report FP logs to JSONL with reporter identity
- R5: Explain button available on both profiles (not just simple)
- R6: Sensor picks up allowlist changes within 60s (already works)

### Non-Functional
- NF1: No 2FA for v1 (simplicity first)
- NF2: No SSH required for any triage action
- NF3: Works offline (allowlist is local file, not API)
- NF4: Button callbacks must be < 64 bytes (Telegram limit)

### Success Criteria
- SC1: Operator can silence a false positive in < 10 seconds from phone
- SC2: Allowlisted items never trigger again
- SC3: FP reports accumulate for training data

## Out of Scope (v1)
- 2FA for allowlist actions (future: prevent bot token compromise)
- Undo/remove from allowlist via Telegram
- Graduated enforcement (LSM command blocking)
- Auto-learning from FP reports
