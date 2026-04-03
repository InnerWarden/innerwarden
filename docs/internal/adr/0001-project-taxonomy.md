# ADR 0001: Project Taxonomy

- Status: Accepted
- Date: 2026-04-03

## Context

InnerWarden cresceu em varias direcoes ao mesmo tempo: sensor, agent, ctl, modules, integrations, rules e protecao de AI agents. Sem uma taxonomia simples, features novas tendem a cair em arquivos grandes ou no lugar errado, o que aumenta acoplamento e reduz navegabilidade.

## Decision

O projeto passa a usar a seguinte taxonomia como regra de organizacao:

| Termo | O que e | Onde normalmente vive |
|---|---|---|
| `command` | Interface exposta ao operador no CLI | `crates/ctl/src/commands/*` ou modulo equivalente |
| `capability` | Toggle operacional pequeno, normalmente ativado/desativado pelo CTL | `crates/ctl/src/capabilities/*` |
| `module` | Pacote vertical declarativo que habilita coletores, detectores, skills ou notificadores | `modules/<id>/` |
| `integration` | Conexao com provider ou sistema externo | `crates/agent/src/*`, `integrations/*`, `modules/*-integration/` |
| `rule` | Logica declarativa de deteccao, correlacao ou resposta | `rules/*`, `specs/*` |
| `skill` | Acao que o responder/agent pode executar | `crates/agent/src/skills/*` |

## Placement Rules

1. Comando novo nao entra diretamente em arquivo monolitico se puder nascer em modulo proprio.
2. Integracao nova com provider externo deve ficar separada da logica de produto.
3. Quando uma feature ativa varias partes do sistema de forma declarativa, ela tende a ser `module`, nao `capability`.
4. Regra declarativa vai para `rules/` ou `specs/`; logica executavel fica nos crates Rust.
5. Mudancas que criem um conceito novo ou mudem essa taxonomia exigem nova ADR.

## Operational Rules

1. `CLAUDE.md` e a unica fonte de verdade de navegacao e governanca do repo.
2. Specs de features ficam versionados em `.specify/features/`.
3. ADRs vivem em `docs/internal/adr/`.

## Consequences

### Positive

- Fica mais facil saber onde uma feature nova deve entrar
- Reviews ficam mais previsiveis
- O projeto ganha memoria versionada de decisoes

### Negative

- Exige disciplina para nao voltar a concentrar mudancas em arquivos gigantes
- Algumas areas atuais ainda precisarao de refactor para refletir essa taxonomia por completo
