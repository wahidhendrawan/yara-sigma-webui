# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/),
versioning follows [SemVer](https://semver.org/).

## [3.2.0] - 2026-08-01

### Added
- **Sigma → YARA reverse converter** — `yar2sig reverse <input> [-o <output>]`
  converts Sigma rules back into YARA format. Supports single files,
  multi-document YAML, and batch directory conversion, with `--json` and
  `--verbose` output. Safely extracts patterns, handles boolean conditions,
  sanitizes rule names, and reports warnings for unsupported constructs.
- **Architecture guide** — `docs/architecture.md` documenting components,
  data flow, and extension points.

## [Unreleased]

## [4.0.0] - 2026-11-08

### Changed
- **Rewritten in Rust (4.0.0, breaking for library users)** — `yar2sig` is now one binary
  built with Cargo (`cargo build --release`). The `convert`, `pipelines`, `query` and
  `reverse` commands and flags, the mapping pipelines (now under `mappings/` and embedded
  at build time), the `POST /api/convert` and `/healthz` contracts, the security headers,
  the size and pattern limits, and the Docker Compose deployment are unchanged. The new
  `yar2sig serve` command (axum) replaces Flask + gunicorn; the Docker image still bundles
  `sigma-cli` for native queries and caps it with `YAR2SIG_SIGMA_CONCURRENCY` (now `2`).
  The Python package and its library API are removed; the crate exposes the same
  functions (`convert`, `convert_all`, `parser::parse_yara_rule`, `emitter::emit_sigma`,
  `emitter::to_detection_rules`, `backends::generate_query`, `sig2yar::*`). CI runs
  `cargo fmt`, `clippy` and `cargo test` instead of pytest and Codecov.
- Multi-field selections are joined as `1 of selN_*` instead of `(selN_1 or selN_2)`, and
  `sigma convert` runs with `--without-pipeline`: native sigma-cli queries now actually work
  (pySigma 0.11 crashed on the parenthesised form and the Splunk backend refused rules without
  a processing pipeline, so the API always fell back to wildcard queries). The QRadar
  target is `q_radar_aql` (the plugin's real name; `qradar` was never accepted).
- The reverse converter now keeps `1 of sel*` / `all of them` terms inside boolean conditions
  (`1 of selection_* and other`) instead of approximating the whole condition.

### Added
- **Detection-Rules layout in the web UI and API** — a checkbox (and `layout` /
  `attack` fields on `POST /api/convert`) returns the rule in the Detection-Rules
  repository layout; the download is named after the rule.
- **Detection-Rules export** — `yar2sig convert --format detection-rules [--attack T1059]`
  writes rules in the layout of the Detection-Rules repository (template key order,
  `modified`, `fields`, no `x_yar2sig` block, ATT&CK technique tag required) so they
  pass its `detection_rules lint`.
- **CLI JSON output** — `yar2sig convert --format json` emits a versioned,
  machine-readable conversion envelope for CI and SIEM pipelines while keeping
  YAML as the backward-compatible default. JSON directory output writes one
  result per file.
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
