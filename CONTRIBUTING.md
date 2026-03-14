# Contributing

Thanks for contributing to InnerWarden.

## Before You Start

InnerWarden touches host telemetry, incident detection, and optional response automation. Please optimize for:

- deterministic sensor behavior
- fail-open behavior for collectors and sinks
- conservative defaults
- explicit documentation for any behavioral change

## Development Workflow

1. Create a topic branch.
2. Implement the change.
3. Run the local validation gate:

```bash
make check
make test
```

4. Update documentation affected by the change.
5. Open a pull request with a clear description of behavior, risk, and validation.

## Documentation Rule

If a change affects any of the following, update docs in the same PR:

- capabilities
- generated artifacts
- configuration
- deployment/update flow
- operational safety guidance

In practice, that often means updating one or more of:

- `README.md`
- `CLAUDE.md`
- files under `docs/`

## Commit Style

- Prefer concise commit messages in English.
- Keep commits coherent and reviewable.
- Avoid mixing unrelated refactors with behavior changes.

## Pull Request Expectations

Please include:

- what changed
- why it changed
- any migration or rollout impact
- commands you used to validate it

If you changed responder behavior, dashboard behavior, or incident schemas, call that out explicitly.

## Scope Guidance

Good contributions:

- detector improvements
- operational safety improvements
- documentation and rollout hardening
- test coverage and replay coverage
- dashboard investigation UX improvements

Changes that need extra care:

- auto-execution defaults
- new privileged response skills
- privacy-sensitive data collection
- schema-breaking output changes

## Questions

If you are unsure whether a change fits the project's current direction, open an issue or draft PR first.
