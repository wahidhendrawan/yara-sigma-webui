# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **YARA Sigma Studio refresh** — focused workbench layout with `.yar` import,
  mapping pipeline selector, restored SIEM/EDR query backend selector, and
  dedicated Sigma / Query / Report tabs.
- **Web API query output** — `/api/convert` validates backend names and returns
  the generated native query alongside Sigma YAML and quality metadata.
- **Multi-rule conversion** — `convert_all()` converts every YARA rule in a
  file. CLI writes one `.yml` per rule; the web API returns all rules; the UI
  shows a rule selector when a file contains more than one rule.
- **Conversion confidence score (0–100)** — surfaced in the report, API
  response, and UI (color-coded chip). Caps at 80 when hex/regex patterns are
  present since Sigma cannot match raw bytes.
- **GitHub Actions CI** — pytest matrix (3.9 / 3.12), CLI smoke test, and a
  Docker build + `/healthz` check.
- `CONTRIBUTING.md` and this `CHANGELOG.md`.

### Changed
- Updated web copy and documentation to describe the current Docker Compose
  workflow, file import, backend query generation, and 11-test validation suite.

## [3.0.0] - 2026-06-04

Consolidated release merging v1 and v2 into a single working package.

### Added
- Modular `yar2sig` library: `parser`, `ioc`, `emitter`, `backends`, `cli`.
- IOC classification (9 types) and MITRE ATT&CK tag extraction from `meta`.
- 4 mapping pipelines: `sysmon`, `winsec`, `linux`, `proxy`.
- 7 SIEM/EDR backends with `sigma-cli` native conversion + wildcard fallback.
- Modern web UI with live conversion, tabs, copy/download, samples.
- CLI (`convert` / `pipelines` / `query`) and installable package (`pyproject.toml`).
- Docker-Compose architecture: multi-stage image, gunicorn, bundled `sigma-cli`,
  hardened container (non-root, read-only FS, dropped caps, resource limits),
  `/healthz` endpoint.
- Test suite (pytest), sample rules, unified README.

### Fixed
- Broken relative imports from v2 (`..extractors`, `.parsers`, `.emitters`).
- URL strings being stripped by the `//` comment remover.
- Condition bleeding across rules in multi-rule files.

### Removed
- `version-1` and `version-2` branches (consolidated into `main`).

[Unreleased]: https://github.com/wahidhendrawan/yara-sigma-webui/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/wahidhendrawan/yara-sigma-webui/releases/tag/v3.0.0
