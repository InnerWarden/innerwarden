# ADRs

Architectural Decision Records guardam decisoes permanentes de arquitetura, organizacao e operacao do repo.

## Quando criar uma ADR

Criar uma ADR quando a mudanca:

- introduz um conceito novo no projeto
- define uma regra de organizacao ou governanca
- troca um trade-off estrutural por outro
- muda o fluxo oficial de desenvolvimento, deploy ou operacao

## Como nomear

- usar `NNNN-titulo-curto.md`
- exemplo: `0002-split-ctl-main.md`

## Fluxo

1. Escrever ou atualizar o spec em `.specify/features/<id>-<tema>/`
2. Criar a ADR se a mudanca tiver impacto duradouro
3. Atualizar `CLAUDE.md` se o mapa do repo ou o workflow oficial mudar
4. Rodar os checks antes de commit

## Status

- `Proposed`: ainda em discussao
- `Accepted`: virou regra ativa
- `Superseded`: substituida por ADR mais nova
