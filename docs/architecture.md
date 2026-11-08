# Architecture: YARA → Sigma Converter (yar2sig)

## Purpose

`yar2sig` is a Rust binary (and crate) that converts YARA malware detection rules into Sigma rules and native SIEM/EDR queries. It bridges the gap between file/memory pattern matching (YARA) and log event detection (Sigma) via automatic IOC classification, configurable field mappings, and backend-specific query generation.

## Design & Components

### Core Modules

**Parser** (`src/parser.rs`)
- Extracts rule metadata (name, tags, meta fields), string patterns (text, hex, regex), and condition expressions
- Handles multi-rule files with comment stripping and brace-matching
- Validates complexity bounds (max 500 patterns, 10,000 chars each)
- Returns: `ParsedRule` with rule name, meta, string entries (value, type, modifiers), tags, condition

**IOC Classifier** (`src/ioc.rs`)
- Classifies plain-text patterns into types: `url`, `ip`, `hash`, `email`, `domain`, `registry`, `mutex`, `named_pipe`, `user_agent`, `path_or_filename`, `generic`
- Uses regex heuristics for each type; fallback to `generic`
- Used by mapping engine to select Sigma fields

**Emitter** (`src/emitter.rs`)
- Transforms parsed rule + mapping → Sigma rule as an ordered `serde_json::Value` (YAML-ready)
- Extracts MITRE ATT&CK techniques from meta fields → tags
- Generates detection selections per pattern with field/operator mapping
- Calculates quality score (0–100) based on pattern count, complexity, warnings
- Adds `x_yar2sig` metadata block with confidence, review flag, warnings

**Backends** (`src/backends.rs`)
- Attempts native conversion via `sigma-cli` (if installed) targeting Elastic, Splunk, Kusto, QRadar, etc.
- Falls back to escaped wildcard queries per backend (Lucene, SPL, KQL, SQL-like)
- Maps each backend to fallback field + escape rules; concurrent `sigma-cli` runs are capped by `YAR2SIG_SIGMA_CONCURRENCY`

**Reverse converter** (`src/sig2yar.rs`)
- Best-effort Sigma → YARA: scalar extraction, wildcard/regex handling, boolean condition parsing, explicit warnings

**CLI** (`src/cli.rs`) and **web server** (`src/web.rs`)
- clap subcommands `convert`, `pipelines`, `query`, `reverse`, `serve`
- axum routes `GET /`, `GET /healthz`, `POST /api/convert`; security headers, body/pattern limits, 503 when every sigma-cli slot is busy

**Mapping Pipeline** (`mappings/`)
- YAML files (sysmon, winsec, linux, proxy) define logsource + IOC-to-field mappings
- Example:
  ```yaml
  logsource:
    product: windows
    service: sysmon
  fallback_field: Image
  mappings:
    url:
      fields: [Image, CommandLine]
      op: contains
  ```
- `build.rs` embeds every `.yaml` file at build time; add new ones without code changes

### Data Flow

```
YARA Rule (text)
  ↓ [Parser]
Parsed Dict {name, strings, types, modifiers, condition}
  ↓ [IOC Classifier + Mapping]
Detection Selections {sel1, sel2, ...}
  ↓ [Emitter]
Sigma Rule Dict + Quality Metadata
  ↓ [YAML Dump] → CLI output
  ↓ [Backend] → SIEM/EDR Query
```

## Interfaces

### CLI

```bash
# List pipelines
yar2sig pipelines

# Convert single file (prints YAML)
yar2sig convert rule.yar -p sysmon

# Bulk convert directory
yar2sig convert rules/ -p winsec -o out/

# Generate SIEM query
yar2sig query rule.yar -b splunk

# JSON output
yar2sig convert rule.yar --format json

# Sigma -> YARA, and the web UI/API
yar2sig reverse rule.yml
yar2sig serve --host 127.0.0.1 --port 8000
```

### Library API

```rust
use yar2sig::{available_pipelines, backends::generate_query, convert};

let (sigma_rule, report) = convert("rule {...}", "sysmon")?;
available_pipelines();  // ["linux", "proxy", "sysmon", "winsec"]
generate_query("splunk", &sigma_rule, &patterns)?;
```

### Web API (`POST /api/convert`)

Request:
```json
{"rule": "rule {...}", "pipeline": "sysmon", "backend": "splunk"}
```

Response:
```json
{
  "sigma": "title: ...",
  "query": "...",
  "quality": {"confidence": "medium", "score": 70, ...},
  "report": ["Pattern -> IOC type -> fields ..."]
}
```

## Local Development

```bash
# Run tests, lint, format check
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Run the server from source
cargo run -- serve  # http://127.0.0.1:8000

# Docker
docker compose up -d  # http://127.0.0.1:8000
```

## Extension Points

1. **Add a new pipeline**: Drop a YAML file in `mappings/` with logsource + field mappings (embedded on the next build)
2. **Add IOC type**: Add regex + heuristic to `classify_pattern` in `src/ioc.rs`, update mapping entries
3. **Add backend**: Register in `BACKENDS` in `src/backends.rs`, implement fallback query escaping or sigma-cli target
4. **Custom conversion logic**: Wrap `emit_sigma` from `src/emitter.rs` in your own crate

## Quality Scoring

Each rule receives a confidence score (0–100):
- **Start**: 100 points
- **Deduct**: –70 (no patterns), –15 per hex/regex pattern, –5 per warning, –20 if complex condition
- **Label**: High (80+), Medium (55–79), Low (<55)
- Review required if score < 80 or warnings present

## Security Notes

- Web container runs as non-root, read-only FS, dropped capabilities
- Request body limit: 1.1 MB (MAX_RULE_BYTES = 1 MB)
- Pattern complexity bounds: 500 patterns, 10,000 chars each
- CSP header restricts inline scripts/styles; no external resources
