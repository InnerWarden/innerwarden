# Feature Specification: Azure Training Sprint

**Feature Branch**: `006-azure-training-sprint`
**Created**: 2026-04-05
**Status**: Draft
**Input**: $1000 Azure credits. University presentation Friday. Need publishable benchmark results + trained defender models.

## Origin

Self-play training on MacBook Pro (M3, 8 cores) is too slow for iteration. The v3 defender (active defenses) reached 52.7% win rate at 850K episodes but takes 4.5h per 1M run. Cannot test multiple configurations, bigger networks, or real datasets before Friday.

Azure Founders Hub approved $1000 credits. With proper VM selection and parallelization, each 1M-episode experiment drops from 4.5h to ~3 minutes on a 72-core VM.

## Problem

1. Self-play is single-threaded — only uses 1 of 8 Mac cores.
2. No real-world dataset validation — autoencoder only trained on production server data.
3. Cannot test network size variations (bigger networks need more compute).
4. No population-based training (multiple agents evolving simultaneously).
5. No publishable benchmark results on academic datasets.

## Goals

- Run 20+ experiment configurations in one sprint session.
- Train autoencoder on CICIDS2017 and measure F1 score (publishable benchmark).
- Find the best defender configuration (network size, reward structure, active defenses).
- Produce results table for university presentation.
- Spend < $150 of $1000 budget (preserve rest for ongoing research).

---

## Azure VM Selection (verified pricing, East US, April 2026)

### Primary VM: Self-play training (CPU-bound)

| VM | vCPUs | RAM | Price/h (standard) | Price/h (spot) | $1000 buys |
|---|---|---|---|---|---|
| **Standard_F48s_v2** | 48 | 96 GB | $2.03/h | $0.64/h | 493h / 1562h |
| **Standard_F72s_v2** | 72 | 144 GB | $3.05/h | $0.96/h | 328h / 1042h |
| Standard_D64pls_v5 | 64 | 128 GB | $2.18/h | $0.44/h | 459h / 2273h |
| Standard_D96as_v5 | 96 | 384 GB | $3.07/h | ~$0.92/h | 326h / 1087h |

**Recommendation**: **Standard_F72s_v2** (72 cores, compute-optimized, $3.05/h).
- Fsv2 is compute-optimized: higher single-core performance than D-series.
- 72 cores × rayon parallelization = ~72 parallel episodes.
- At ~100 ep/s per core = **~5.000-7.000 ep/s** (vs 85 on Mac).
- 1M episodes in **~2.5 minutes** (vs 3+ hours on Mac).
- **Spot pricing ($0.96/h)** reduces cost 68% — $1000 buys 1042 hours. Sprint needs ~10-20h.

**Alternative**: **Standard_D64pls_v5** (64 ARM cores, $0.44/h spot).
- ARM (Ampere Altra) — Rust compiles natively for aarch64.
- Spot at $0.44/h is extremely cheap: $1000 = 2273 hours.
- Slightly slower per-core but 64 cores compensate.
- Risk: spot VMs can be evicted (save checkpoints frequently).

### Secondary VM: Caldera validation (low-cost)

| VM | vCPUs | RAM | Price/h |
|---|---|---|---|
| **Standard_B2s** | 2 | 4 GB | $0.042/h |

Two B2s VMs: one with InnerWarden, one without. $0.08/h total. Negligible cost.

### GPU VM (future, not needed now)

| VM | vCPUs | GPU | VRAM | Price/h (standard) | Price/h (spot) |
|---|---|---|---|---|---|
| Standard_NC24ads_A100_v4 | 24 | 1× A100 80GB | 80 GB | $3.67/h | $0.68/h |
| Standard_NC48ads_A100_v4 | 48 | 2× A100 80GB | 160 GB | $7.35/h | ~$1.35/h |
| Standard_NC96ads_A100_v4 | 96 | 4× A100 80GB | 320 GB | $14.69/h | ~$2.70/h |

Not needed for current sprint (self-play is CPU). Reserved for future: CUDA port of neural network training, transformer-based defender, population-based with GPU acceleration.

---

## User Scenarios & Testing

### User Story 1 — Parallel Self-Play on Azure (Priority: P1)

Run the existing selfplay-parallel command on a 72-core Azure VM and verify it scales linearly with cores.

**Why this priority**: Without this, everything else is blocked. Must verify parallelization works before running experiments.

**Independent Test**: Run `selfplay-parallel` with 1M episodes on F72s_v2. Should complete in < 5 minutes. Should show ~5000+ ep/s in logs.

**Acceptance Scenarios**:

1. **Given** F72s_v2 VM provisioned, **When** `selfplay-parallel` runs with 72 cores, **Then** ep/s > 3000 (minimum 30x improvement over Mac).
2. **Given** experiment completes, **When** weights saved, **Then** can resume from checkpoint on next run.
3. **Given** spot VM, **When** VM evicted, **Then** last checkpoint weights preserved (saved every 50K episodes).

---

### User Story 2 — Experiment Matrix (Priority: P2)

Run 10+ configurations in parallel and identify the best defender setup.

**Why this priority**: The university presentation needs a comparison table showing systematic improvement.

**Independent Test**: Run 10 configs, generate comparison table showing win rates.

**Acceptance Scenarios**:

1. **Given** 10 experiment configs, **When** all complete (~25 min total), **Then** results saved to JSON files with comparable metrics.
2. **Given** results, **When** compared, **Then** at least one config outperforms v3 baseline (52.7% defender win rate).

**Experiments**:

| # | Name | Network | Seed | Episodes | What it tests |
|---|---|---|---|---|---|
| 1 | v3-base | [48→128→64→20] | Caldera | 5M | Baseline (same as Mac run) |
| 2 | v3-big | [48→256→128→20] | Caldera | 5M | More capacity |
| 3 | v3-huge | [48→512→256→128→20] | Caldera | 5M | Much more capacity |
| 4 | v3-fast-eps | [48→128→64→20] | Caldera | 5M | Faster epsilon decay (0.99999) |
| 5 | v3-stance-bonus | [48→128→64→20] | Caldera | 5M | +2.0 reward for new stance |
| 6 | v3-pre-waf | [48→128→64→20] | Caldera | 5M | WAF+SSH pre-enabled |
| 7 | v3-cicids | [48→256→128→20] | CICIDS2017 | 5M | Real dataset seed |
| 8 | v3-combined | [48→512→256→128→20] | All datasets | 10M | Maximum data + capacity |
| 9 | v3-pop4 | [48→128→64→20] ×4 | Mixed | 5M | Population: 4 atk × 4 def |
| 10 | v3-asym-eps | [48→128→64→20] | Caldera | 5M | Atk fast decay, def slow |

---

### User Story 3 — CICIDS2017 Autoencoder Benchmark (Priority: P3)

Train the autoencoder on CICIDS2017 benign traffic and measure detection rate on attack traffic. Produces a publishable metric.

**Why this priority**: Academic credibility. "Our autoencoder achieves X% F1 on CICIDS2017" is a concrete, comparable result.

**Independent Test**: Autoencoder trained on benign subset, tested on attack subset. F1 > 90%.

**Acceptance Scenarios**:

1. **Given** CICIDS2017 CSV downloaded, **When** converted to 48-dim features, **Then** produces 2.3M benign + 500K attack feature vectors.
2. **Given** autoencoder trained on benign, **When** tested on attack, **Then** ROC curve and F1 per attack category generated.
3. **Given** results, **When** compared to published benchmarks, **Then** competitive with or exceeds autoencoder baseline (95.1% accuracy from 2020 paper).

**Published benchmarks on CICIDS2017**:

| Method | Accuracy | F1 | Year |
|---|---|---|---|
| Random Forest | 98.8% | 98.0% | 2017 |
| Deep Learning | 99.2% | 98.7% | 2019 |
| Autoencoder anomaly | 95.1% | 93.2% | 2020 |
| **InnerWarden AE (target)** | **> 95%** | **> 93%** | **2026** |

---

### User Story 4 — CICIDS2017 Attacker Seed (Priority: P4)

Convert CICIDS2017 attack flows into Technique chains and use as additional seed for the self-play attacker.

**Why this priority**: More diverse attack seed = more robust defender. Currently seeded with 29 Caldera techniques only.

**Independent Test**: Converter produces Technique chains from CICIDS attack categories. Attacker seeded with 100+ unique patterns.

**Acceptance Scenarios**:

1. **Given** CICIDS2017 attack flows, **When** converted, **Then** produces chains for: DoS, DDoS, Brute Force, Web Attack, Infiltration, Botnet, Port Scan.
2. **Given** chains, **When** used as seed, **Then** attacker shows different behavior than Caldera-only seed (more diverse chains discovered).

---

### User Story 5 — CLI Network Size Flag (Priority: P1)

Add `--hidden` flag to selfplay commands so network architecture can be changed without code modifications.

**Why this priority**: Needed before experiment matrix. Currently network size is hardcoded.

**Independent Test**: `selfplay-v3 --hidden 512,256,128` creates defender with [48→512→256→128→20].

**Acceptance Scenarios**:

1. **Given** `--hidden 512,256,128` flag, **When** selfplay starts, **Then** defender network has layers [48, 512, 256, 128, 20].
2. **Given** no `--hidden` flag, **When** selfplay starts, **Then** default [48, 128, 64, 20] used (backward compatible).

---

## Functional Requirements

- R1: selfplay-parallel scales linearly with available CPU cores.
- R2: Experiment results saved as JSON with comparable metrics.
- R3: CICIDS2017 converter produces 48-dim feature vectors matching existing format.
- R4: Autoencoder benchmark produces ROC curve and F1 per attack category.
- R5: All experiments reproducible (seeds saved, configs in JSON).
- R6: Weights saved every 50K episodes (spot VM safety).
- R7: Network architecture configurable via CLI flag.

## Non-Functional Requirements

- NF1: Sprint compute cost < $150 of $1000 budget.
- NF2: Each 1M-episode experiment completes in < 5 minutes on F72s_v2.
- NF3: CICIDS2017 conversion completes in < 10 minutes.
- NF4: Results exportable as tables for presentation.

## Success Criteria

- SC1: Comparison table with 10+ configurations and clear winner.
- SC2: Autoencoder F1 on CICIDS2017 > 93% (beats published autoencoder baseline).
- SC3: Best defender configuration achieves < 25% attacker win rate (improves on v3's 29%).
- SC4: Total Azure spend < $150.
- SC5: Results ready for Friday presentation.

## Edge Cases

- E1: Spot VM evicted mid-experiment → checkpoints saved every 50K, resume from last.
- E2: CICIDS2017 too large for VM memory → stream conversion, don't load all at once.
- E3: Experiment fails to converge → still report results, negative result is publishable.

## Out of Scope

- CUDA port of neural network training (future, needs GPU VM).
- Transformer-based defender (future, needs more research).
- Multi-host simulation (future, needs environment redesign).
- Production deployment of trained model (separate feature).

---

## Implementation Priority

1. **CLI network size flag** (US5, blocks experiments)
2. **Verify parallelization on Azure** (US1, blocks everything)
3. **Experiment matrix** (US2, main deliverable)
4. **CICIDS2017 converter** (US3/US4, publishable result)
5. **Autoencoder benchmark** (US3, academic credibility)

## Budget Plan

| Item | VM | Hours | Cost |
|---|---|---|---|
| Self-play experiments (spot) | F72s_v2 | 20h | $19.20 |
| CICIDS conversion + autoencoder | F72s_v2 | 5h | $4.80 |
| Caldera validation | 2× B2s | 20h | $1.68 |
| Buffer (spot evictions, retries) | F72s_v2 | 10h | $9.60 |
| **Sprint total** | | **55h** | **$35.28** |
| **Reserve for ongoing** | | | **$964.72** |
