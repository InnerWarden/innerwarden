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

## Docs detalhados

O handbook completo esta em `.claude/CLAUDE.md` (859 linhas).
Wiki: `innerwarden.wiki/` no monorepo.
