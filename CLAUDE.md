# InnerWarden — Main Repo

Sensor (eBPF) + Agent (AI triage) + CTL (CLI). Open source (Apache-2.0).

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

## Estado (2026-04-04)

- 49 detectors, 40 eBPF hooks, 65 MITRE IDs, 30 correlation rules
- Server producao: ver config local (nao expor no repo publico)
- Branches: main = stable, develop = bleeding edge
- CI: `make check` + `make test` + `make spec-check`
- Licenca: Apache-2.0 (migrado de BUSL-1.1 em 2026-04-03)
- Release atual: v0.9.2

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
- Decisoes arquiteturais vivem em `docs/internal/adr/`

## Fluxo De Mudanca

Toda mudanca relevante para produto, arquitetura ou operacao:

1. Spec primeiro: criar ou atualizar em `.specify/features/<id>-<tema>/`
2. ADR se criar regra, conceito ou trade-off permanente
3. Atualizar `CLAUDE.md` se alterar mapa do repo, workflow, deploy ou convencoes
4. `make check` e `make test` antes de commit
5. Nao misturar reorganizacao com mudanca de comportamento no mesmo commit

## Taxonomia

- `command`: interface exposta no CLI
- `capability`: toggle operacional (habilitada pelo CTL)
- `module`: pacote vertical declarativo em `modules/`
- `integration`: conexao com sistema externo ou provider
- `rule`: logica declarativa de deteccao/correlacao/playbook
- `skill`: acao permitida ao agent/responder

ADR: `docs/internal/adr/0001-project-taxonomy.md`

## Features — Status

| ID | Feature | Status |
|----|---------|--------|
| 001 | Telegram Interactive Triage | Concluida |
| 002 | Telegram Triage v2 (2FA + Undo + Auto-Learn) | Auto-Learn, Undo e 2FA Telegram concluidos. Pendente: dashboard 2FA endpoints (A5) |
| 003 | Setup Ready To Use | Concluida |
| 004 | Setup Zero Friction | Concluida |

## Divida tecnica

- **2FA dashboard endpoints (A5)**: TOTP funciona no Telegram. Falta implementar `GET /api/2fa/pending`, `POST /api/2fa/approve`, `POST /api/2fa/deny` para o metodo "dashboard".
- **Agent main.rs**: 4396 linhas. Modularizacao avancou muito mas `process_incidents` e `process_telegram_approval` ainda concentram orquestracao. Proximos candidatos: Telegram bot commands/status, integracoes.
- **CTL main.rs**: 2201 linhas. Aceitavel. Ponto de manutencao atingido.

## Docs detalhados

Handbook completo: `.claude/CLAUDE.md`
Wiki: `innerwarden.wiki/` no monorepo
