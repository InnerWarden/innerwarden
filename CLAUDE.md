# InnerWarden — Main Repo

Sensor (eBPF) + Agent (AI triage) + CTL (CLI). Repo principal, open source (BUSL-1.1).

## O que vive aqui

```
crates/
  sensor/       49 detectors, 40 eBPF hooks, 20 collectors
  agent/        AI pipeline, dashboard, skills, correlation, notifications
  ctl/          CLI: setup, configure, scan, harden, upgrade
  agent-guard/  AI agent protection (ATR rules, MCP inspection)
  core/         Shared types: Event, Incident, Severity
  sensor-ebpf/  eBPF bytecode (no_std, bpfel target)
  sensor-ebpf-types/  Shared eBPF ↔ userspace types
rules/
  sigma/        208 community Sigma rules (SigmaHQ)
  yara/         8 malware scanning rules
  atr/          71 AI agent threat rules (vendored)
modules/        Vertical security modules (manifests)
integrations/   Declarative integration recipes
```

## Comandos

```bash
make test         # todos os testes (~1900)
make build        # debug build
make check        # clippy + fmt
make replay-qa    # validacao E2E
```

## Estado (2026-04-02)

- 49 detectors, 40 eBPF hooks, 65 MITRE IDs, 30 correlation rules
- Server producao: ubuntu@130.162.171.105 (porta 49222)
- Branches: main = stable, develop = bleeding edge
- CI valida `main`, `develop` e pull requests com `make check`, `make test` e `make spec-check`
- Neural autoencoder: so no develop (nao vai pro release)

## Convencoes

- Commits em ingles
- Sensor: deterministico, zero HTTP/AI
- Agent: pode chamar APIs externas
- I/O errors em sinks: `warn!`, nao `?`
- `spawn_blocking` pra I/O sincrono em tasks Tokio

## Fonte De Verdade

- `CLAUDE.md` e o unico arquivo de navegacao e governanca do repo
- Nao criar `AGENTS.md` neste repo
- Specs de features vivem em `.specify/features/`
- Decisoes arquiteturais e de organizacao vivem em `docs/internal/adr/`

## Fluxo De Mudanca

Quando a mudanca for relevante para produto, arquitetura ou operacao:

1. Criar ou atualizar o spec em `.specify/features/<id>-<tema>/`
2. Registrar uma ADR se a mudanca criar regra nova, conceito novo ou trade-off permanente
3. Atualizar `CLAUDE.md` se a mudanca alterar mapa do repo, workflow, deploy ou convencoes
4. Rodar `make check` e `make test` antes de commit

## Taxonomia

- `command`: interface exposta no CLI
- `capability`: toggle operacional pequena, normalmente habilitada pelo CTL
- `module`: pacote vertical declarativo em `modules/`
- `integration`: conexao com sistema externo ou provider
- `rule`: logica declarativa de deteccao/correlacao/playbook
- `skill`: acao permitida ao agent/responder

ADR inicial: `docs/internal/adr/0001-project-taxonomy.md`

## Workstream Atual

### CTL Modularization — 2026-04-03

- **Branch**: `codex/phase1-governance`
- **PR**: `#54` contra `develop`
- **Objetivo**: transformar o `crates/ctl/src/main.rs` num roteador fino, com dominios bem definidos em `crates/ctl/src/commands/`

### Ja concluido nesta frente

1. Governanca base
- `.specify/` saiu do `gitignore`
- `CLAUDE.md` virou fonte unica de governanca
- ADR inicial de taxonomia criada em `docs/internal/adr/0001-project-taxonomy.md`
- CI passou a validar `develop`

2. Cortes de modularizacao ja entregues no `ctl`
- `commands/setup.rs`
- `commands/ai.rs`
- `commands/notify.rs`
- `commands/responder.rs`
- `commands/integrations.rs`
- `commands/status.rs`
- `commands/mesh.rs`
- `commands/module.rs`
- `commands/agent.rs`
- `commands/watchdog.rs`
- `commands/response.rs`
- `commands/history.rs`
- `commands/ops.rs`

3. Escopo funcional ja removido do `main.rs`
- setup
- AI/configuracao de provider
- notify, incluindo `web-push`
- responder
- integrations
- status/report/metrics/sensor-status
- mesh
- module
- agent
- watchdog
- response: `block`, `unblock`, `allowlist`, `suppress`
- history/data: `incidents`, `incidents --live`, `export`, `tail`, `decisions`, `entity`, `gdpr export`, `gdpr erase`
- ops/config: `configure menu`, `configure fail2ban`, `configure 2fa`, `tune`, `doctor`
- ops/runtime: `test` (pipeline smoke test)

### Estado atual

- `crates/ctl/src/main.rs` esta em `3153` linhas
- Ultimo corte aplicado: extracao de `cmd_tune`, `cmd_doctor`, `cmd_pipeline_test`, `cmd_backup` e `cmd_completions` para `commands/ops.rs`
- Todos os cortes foram validados com:
  - `cargo fmt --all`
  - `cargo check -p innerwarden-ctl`
  - `cargo test -p innerwarden-ctl`

### Ordem recomendada para continuar

1. Consolidar helpers compartilhados
- revisar o que ainda faz sentido ficar no root:
  - `require_sudo`
  - `resolve_data_dir`
  - `load_env_file`
  - `send_telegram_message_md`
  - `write_env_key`
  - `hostname`
- mover apenas quando a fronteira estiver clara; nao forcar acoplamento artificial

2. Depois do `ctl`
- iniciar a mesma estrategia no crate `agent`
- candidatos naturais:
  - `dashboard.rs`
  - integracoes/notifiers
  - partes grandes do `agent/src/main.rs`

### Regra de continuidade

- manter cortes pequenos, por dominio
- cada corte precisa terminar com branch limpa
- nao misturar reorganizacao com mudanca de comportamento
- validar sempre antes de commit
- se uma extracao ficar ambigua, preferir deixar helper no root temporariamente

### Ultimos commits desta frente

- `WIP` Extract ctl history/data commands into a dedicated module
- `WIP` Extract ctl ops/config setup commands into a dedicated module
- `1e09220` Move ctl web push setup into the notify module
- `023289d` Extract ctl response commands into a dedicated module
- `db2690e` Extract ctl watchdog commands into a dedicated module
- `93ad6c2` Extract ctl agent commands into a dedicated module
- `f18c27b` Extract ctl module commands into a dedicated module

## Docs detalhados

O handbook completo esta em `.claude/CLAUDE.md` (859 linhas).
Wiki: `innerwarden.wiki/` no monorepo.
