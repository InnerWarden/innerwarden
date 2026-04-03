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
- `commands/core.rs`
- `commands/update.rs`
- `commands/capability.rs`
- `helpers.rs` (prompt/env/network/shared helpers extraidos)

3. Escopo funcional ja removido do `main.rs`
- setup
- AI/configuracao de provider + `ai install` (Ollama cloud)
- notify, incluindo `web-push`
- responder
- integrations
- status/report/metrics/sensor-status/navigator
- mesh
- module
- agent
- watchdog
- response: `block`, `unblock`, `allowlist`, `suppress`
- history/data: `incidents`, `incidents --live`, `export`, `tail`, `decisions`, `entity`, `gdpr export`, `gdpr erase`
- ops/config: `configure menu`, `configure fail2ban`, `configure sensitivity`, `configure 2fa`, `tune`, `doctor`
- ops/runtime: `test` (pipeline smoke test)
- core UX: `list`, `daily` e `welcome`
- capabilities: `enable` / `disable`

### Estado atual

- `crates/ctl/src/main.rs` esta em `2143` linhas
- Ultimo corte aplicado: extracao de `restart_agent` / `require_sudo` / `resolve_data_dir` para `helpers.rs`
- Todos os cortes foram validados com:
  - `cargo fmt --all`
  - `cargo check -p innerwarden-ctl`
  - `cargo test -p innerwarden-ctl`
- Fase 2 iniciada no `agent`:
  - novo modulo `crates/agent/src/bot_helpers.rs`
  - extraidos do `agent/main.rs`: `count_jsonl_lines`, `read_last_incidents`, `read_last_decisions`, `read_last_incidents_raw`
  - segundo corte no mesmo modulo: `TelegramTriageAction`, `parse_telegram_triage_action`, `sanitize_allowlist_process_name`, `format_time_ago`, `local_hostname_for_audit`, `write_telegram_triage_audit`
  - novo modulo `crates/agent/src/agent_context.rs` com `incident_detector`, `guardian_mode`, `build_agent_context`
  - novo modulo `crates/agent/src/bot_commands.rs` com `run_innerwarden_cli`, `format_capabilities`, `capabilities_keyboard`, `strip_ansi`
  - novo modulo `crates/agent/src/bot_actions.rs` com callbacks de execucao (`quick_block` e `hpot`)
  - novo modulo `crates/agent/src/incident_advisory.rs` com correlacao e alerta de advisory ignorado
  - novo modulo `crates/agent/src/incident_flow.rs` com pipeline-test + pre-gates de AI (allowlist, min severity, cooldown, budget)
  - novo modulo `crates/agent/src/incident_obvious.rs` com auto-block para detectores obvios (bypass de AI)
  - novo modulo `crates/agent/src/incident_notifications.rs` com cooldown + dispatch webhook/telegram/slack/web-push
  - novo modulo `crates/agent/src/incident_abuseipdb.rs` com gate de auto-block por reputacao (sem chamada de AI)
  - novo modulo `crates/agent/src/incident_crowdsec.rs` com gate de auto-block via threat list comunitaria
  - novo modulo `crates/agent/src/incident_honeypot_router.rs` com roteamento inteligente para honeypot listener
  - novo modulo `crates/agent/src/incident_enrichment.rs` com threat feed log + lookup GeoIP + enrich de perfil atacante
  - novo modulo `crates/agent/src/incident_ai_context.rs` com montagem de contexto AI (recent_events + related_incidents)
  - novo modulo `crates/agent/src/incident_ai_failure.rs` com fallback de erro do provider AI (telemetria + audit trail)
  - novo modulo `crates/agent/src/incident_post_decision.rs` com salvaguardas pos-decisao (protected IP sandbox, cooldown e estado de blocklist/reputacao)
  - novo modulo `crates/agent/src/incident_decision_eval.rs` com correlation boost + log canonico da decisao AI
  - novo modulo `crates/agent/src/incident_honeypot_suggestion.rs` com defer de escolha honeypot para operador via Telegram
  - novo modulo `crates/agent/src/incident_execution_gate.rs` com gate de execucao (trust rule + confidence + responder)
  - novo modulo `crates/agent/src/incident_audit_write.rs` com persistencia de decisao e espelhamento para attacker_intel
  - novo modulo `crates/agent/src/incident_action_report.rs` com envio de action report Telegram pos-execucao
  - novo modulo `crates/agent/src/incident_playbook.rs` com avaliacao e persistencia de execucao de playbooks
  - novo modulo `crates/agent/src/telemetry_tick.rs` com flush de snapshot de telemetria por tick
  - novo modulo `crates/agent/src/incident_reputation.rs` com lookup de reputacao AbuseIPDB para IP primario
  - novo modulo `crates/agent/src/incident_prelude.rs` com pre-orquestracao de correlacao temporal + auto-enable LSM
  - `probe_and_suggest` tambem movido para `bot_commands.rs`
  - novo handler `handle_telegram_bot_command` em `bot_commands.rs` para comandos bot-only (`__status__` ate `enable:<id>`)
  - novo handler `handle_telegram_triage_action` em `bot_helpers.rs` para triagem (`__allow_proc__`, `__allow_ip__`, `__fp__`)
  - novo handler `handle_pending_confirmation` em `bot_actions.rs` para fluxo approve/reject/always
  - `process_telegram_approval` agora delega o roteamento bot-only para `bot_commands`
  - `process_telegram_approval` agora delega tambem o roteamento de triagem para `bot_helpers`
  - `process_telegram_approval` agora delega callbacks de acao (`quick_block`/`hpot`) para `bot_actions`
  - `process_telegram_approval` agora delega tambem o fluxo de confirmacao pendente para `bot_actions`
  - `process_incidents` agora delega threshold + dispatch de notificacoes para `incident_notifications`
  - `process_incidents` agora delega correlacao de advisory ignorado para `incident_advisory`
  - `process_incidents` agora delega pipeline-test + pre-checks de AI para `incident_flow`
  - `process_incidents` agora delega o obvious-gate (block direto de reincidente) para `incident_obvious`
  - `process_incidents` agora delega o gate AbuseIPDB (auto-block por score) para `incident_abuseipdb`
  - `process_incidents` agora delega o gate CrowdSec (auto-block por feed comunitario) para `incident_crowdsec`
  - `process_incidents` agora delega o roteamento de honeypot para `incident_honeypot_router`
  - `process_incidents` agora delega threat feed + enriquecimento de identidade para `incident_enrichment`
  - `process_incidents` agora delega montagem de contexto AI para `incident_ai_context`
  - `process_incidents` agora delega tratamento de erro do provider AI para `incident_ai_failure`
  - `process_incidents` agora delega salvaguardas pos-decisao para `incident_post_decision`
  - `process_incidents` agora delega correlation boost + log da decisao AI para `incident_decision_eval`
  - `process_incidents` agora delega o fluxo de sugestao honeypot ao operador para `incident_honeypot_suggestion`
  - `process_incidents` agora delega o gate de execucao para `incident_execution_gate`
  - `process_incidents` agora delega a escrita do audit trail de decisao para `incident_audit_write`
  - `process_incidents` agora delega o action report pos-execucao para `incident_action_report`
  - `process_incidents` agora delega avaliacao/persistencia de playbooks para `incident_playbook`
  - loops de `incident_tick` e `narrative_tick` agora delegam flush de snapshot para `telemetry_tick`
  - `process_incidents` agora delega lookup de reputacao AbuseIPDB para `incident_reputation`
  - `process_incidents` agora delega o preambulo de correlacao/LSM para `incident_prelude`
  - `adaptive_block_ttl_secs` promovido para `pub(crate)` para reutilizacao modular
  - `is_trusted` promovido para `pub(crate)` para reutilizacao modular
  - `should_auto_enable_lsm` e `enable_lsm_enforcement` promovidos para `pub(crate)`
  - `crates/agent/src/main.rs` reduziu para `6194` linhas

### Ordem recomendada para continuar

1. Encerramento do `ctl`
- revisar se `main.rs` ainda precisa de novos cortes ou se ja atingiu ponto de manutencao aceitavel
- manter foco em cortes sem mudanca de comportamento

2. Depois do `ctl`
- continuar a mesma estrategia no crate `agent`
- proximos candidatos naturais:
  - fluxo de comandos/status do Telegram bot
  - integracoes/notifiers
  - partes grandes do `agent/src/main.rs`
 - observacao de baseline atual:
   - `cargo test -p innerwarden-agent` segue com 1 falha pre-existente (`tests::telegram_triage_fp_reports_write_audit_and_fp_log`)

### Regra de continuidade

- manter cortes pequenos, por dominio
- cada corte precisa terminar com branch limpa
- nao misturar reorganizacao com mudanca de comportamento
- validar sempre antes de commit
- se uma extracao ficar ambigua, preferir deixar helper no root temporariamente

### Ultimos commits desta frente

- `d7a7018` Extract shared ctl helpers into a dedicated module
- `ffcfe84` Extract ctl welcome command into core module
- `c5bcaef` Extract ctl sensitivity configure command into ops module
- `ab02fac` Extract ctl capability enable and disable commands
- `6d9640c` Extract ctl upgrade command into update module
- `d11601c` Extract ctl ai install command into ai module
- `288643d` Extract ctl navigator command into status module
- `2586b13` Extract ctl list and daily commands into core module
- `ff75b5d` Extract ctl backup and completions commands into ops module
- `0ad7d4a` Extract ctl pipeline test command into ops module
- `579d0d1` Extract ctl doctor and tune commands into ops module
- `009b480` Extract ctl history and ops setup commands into modules

## Docs detalhados

O handbook completo esta em `.claude/CLAUDE.md` (859 linhas).
Wiki: `innerwarden.wiki/` no monorepo.
