# Plan: Azure Training Sprint

**Branch**: `006-azure-training-sprint` | **Date**: 2026-04-05 | **Spec**: `spec.md`

## Approach

Everything in one session. Prepare locally, rent Azure spot VM, run all experiments, extract results. No multi-day timeline — this is a sprint measured in hours, not days.

Realistic time estimate based on today's delivery speed:
- CLI flag for network size: **15 min**
- CICIDS2017 converter: **45 min**
- Azure VM setup + test: **15 min**
- Run 10 experiments (parallel, 72 cores): **50 min compute, 0 min me**
- Autoencoder benchmark on CICIDS: **30 min compute, 15 min analysis**
- Results table + charts: **30 min**
- **Total: ~3 hours work + ~2 hours compute = done in one afternoon**

## Files

### New
- `innerwarden-gym/src/cicids.rs` — CICIDS2017 CSV → 48-dim features + Technique chains
- `innerwarden-gym/run-azure-sprint.sh` — automation script

### Modified
- `innerwarden-gym/src/main.rs` — `--hidden` flag, `cicids-convert` command, `autoencoder-benchmark` command
- `innerwarden-gym/src/selfplay.rs` — network size from CLI args
- `innerwarden-gym/src/anomaly.rs` — benchmark mode (ROC curve, F1 per category)
- `innerwarden-gym/src/lib.rs` — register cicids module

## Design Notes

### CICIDS2017 → 48-dim Features

CICIDS2017 CSV has 78 columns per flow. Map to our 48-dim format:

```
CICIDS columns → InnerWarden features:
- Protocol, Dst Port, Flow Duration → event kind distribution (slots 0-23)
- Flow Bytes/s, Flow Packets/s → outbound bytes, connection rate
- Fwd/Bwd packet lengths → sequence signals
- SYN/ACK/FIN flags → kill chain bigrams (scan → connect → establish)
- Label (BENIGN/DoS/Brute Force/etc) → ground truth for evaluation

Attack category → Technique chain:
- DoS/DDoS → [PortScan, DdosLaunch]
- SSH Brute Force → [SshBruteForce, ShellCommand]
- Web Attack XSS/SQL → [WebExploit, ShellCommand, DataCollection]
- Infiltration → [PortScan, WebExploit, ShellCommand, DataStaging, ExfilHttp]
- Botnet → [CredentialStuffing, CronExecution, ExfilDns]
- Port Scan → [PortScan, ServiceEnumeration]
```

### CLI --hidden Flag

```bash
# Current (hardcoded)
selfplay-v3 data.jsonl 5000000

# New
selfplay-v3 data.jsonl 5000000 --hidden 512,256,128
selfplay-parallel data.jsonl 5000000 v3 --hidden 512,256,128
```

Parse comma-separated list, pass to `DqnAgent::new_with_layers`.

### Autoencoder Benchmark Mode

```bash
cargo run --release -- autoencoder-benchmark cicids-benign.features cicids-attack.features
```

Output:
- Overall accuracy, precision, recall, F1
- Per-category F1 (DoS, Brute Force, Web Attack, etc)
- ROC curve data points (for plotting)
- Comparison with published baselines

### Azure Sprint Script

```bash
#!/bin/bash
# run-azure-sprint.sh — run on F72s_v2 spot VM
# Input: real-data/ directory with Caldera + CICIDS data
# Output: results/ directory with all experiment outputs

# Phase 1: Experiment matrix (parallel on 72 cores)
for config in configs/*.json; do
    cargo run --release -- selfplay-parallel ... &
done
wait

# Phase 2: Best config full run
BEST=$(python3 find_best.py results/)
cargo run --release -- selfplay-parallel $BEST 10000000

# Phase 3: Autoencoder benchmark
cargo run --release -- autoencoder-benchmark ...

# Phase 4: Export results
python3 generate_tables.py results/ > results/summary.md
```

## Verification

- `cargo test` — all existing tests pass
- `selfplay-parallel` on Mac (8 cores) shows >2x speedup over single-thread
- CICIDS converter produces correct feature count
- Autoencoder benchmark produces F1 scores

## Budget

$35 spot pricing for full sprint. $965 reserve.
