# Architecture: YARA → Sigma Converter (yar2sig)

## Purpose

`yar2sig` converts YARA malware detection rules into Sigma rules and native SIEM/EDR queries. It bridges the gap between file/memory pattern matching (YARA) and log event detection (Sigma) via automatic IOC classification, configurable field mappings, and backend-specific query generation.

## Design & Components

### Core Modules

**Parser** (`yar2sig/parser.py`)
- Extracts rule metadata (name, tags, meta fields), string patterns (text, hex, regex), and condition expressions
- Handles multi-rule files with comment stripping and brace-matching
- Validates complexity bounds (max 500 patterns, 10,000 chars each)
- Returns: parsed dict with rule name, strings, types, modifiers, condition

**IOC Classifier** (`yar2sig/ioc.py`)
- Classifies plain-text patterns into types: `url`, `ip`, `hash`, `email`, `domain`, `registry`, `mutex`, `named_pipe`, `user_agent`, `path_or_filename`, `generic`
- Uses regex heuristics for each type; fallback to `generic`
- Used by mapping engine to select Sigma fields

**Emitter** (`yar2sig/emitter.py`)
- Transforms parsed rule + mapping → Sigma rule dict (YAML-ready)
- Extracts MITRE ATT&CK techniques from meta fields → tags
- Generates detection selections per pattern with field/operator mapping
- Calculates quality score (0–100) based on pattern count, complexity, warnings
- Adds `x_yar2sig` metadata block with confidence, review flag, warnings

**Backends** (`yar2sig/backends.py`)
- Attempts native conversion via `sigma-cli` (if installed) targeting Elastic, Splunk, Kusto, QRadar, etc.
- Falls back to escaped wildcard queries per backend (Lucene, SPL, KQL, SQL-like)
- Maps each backend to fallback field + escape rules

**Mapping Pipeline** (`yar2sig/mappings/`)
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
- Auto-discovered; add new .yaml files without code changes

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
python -m yar2sig pipelines

# Convert single file (prints YAML)
python -m yar2sig convert rule.yar -p sysmon

# Bulk convert directory
python -m yar2sig convert rules/ -p winsec -o out/

# Generate SIEM query
python -m yar2sig query rule.yar -b splunk

# JSON output
python -m yar2sig convert rule.yar --format json
```

### Library API

```python
from yar2sig import convert, available_pipelines, generate_query

sigma_rule, report = convert("rule {...}", pipeline="sysmon")
available_pipelines()  # ['linux', 'proxy', 'sysmon', 'winsec']
generate_query("splunk", sigma_rule, patterns)
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
# Install dev dependencies
pip install -e ".[web,dev]"

# Run tests with coverage (70% floor)
pytest -q --cov=yar2sig --cov-report=term

# Run Flask dev server
python app.py  # http://127.0.0.1:5000

# Docker
docker compose up -d  # http://127.0.0.1:8000
```

## Extension Points

1. **Add a new pipeline**: Drop YAML file in `yar2sig/mappings/` with logsource + field mappings
2. **Add IOC type**: Add regex + heuristic to `ioc.py:classify_pattern()`, update mapping entries
3. **Add backend**: Register in `backends.py:BACKENDS` dict, implement fallback query escaping or sigma-cli target
4. **Custom conversion logic**: Subclass or wrap `emit_sigma()` in `emitter.py`

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
