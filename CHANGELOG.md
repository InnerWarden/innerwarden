# Changelog

All notable changes to this project should be documented in this file.

The format is inspired by Keep a Changelog, adapted to the current `0.x` stage of the project.

## [Unreleased]

### Added

- public-facing repository docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`
- GitHub CI workflow plus issue and pull request templates
- documentation map in `docs/index.md`
- release notes convention via this changelog

### Changed

- `make check` is now green across the workspace
- crate metadata now includes repository/homepage/readme/keywords/categories
- example placeholders were normalized to generic values such as `demo-host`
- repository links were normalized to the canonical GitHub repository URL

### Internal

- maintainer-oriented docs were intentionally kept in-repo for now and are tracked in `docs/public-readiness-checklist.md`
