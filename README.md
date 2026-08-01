[![CI](https://github.com/wahidhendrawan/yara-sigma-webui/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/yara-sigma-webui/actions/workflows/ci.yml)

# 🛡️ YARA → Sigma Converter (`yar2sig`)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Backends](https://img.shields.io/badge/SIEM%2FEDR%20backends-7-6366f1)](#-supported-backends)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)
[![Coverage](https://codecov.io/gh/wahidhendrawan/yara-sigma-webui/branch/main/graph/badge.svg)](https://codecov.io/gh/wahidhendrawan/yara-sigma-webui)
[![Version](https://img.shields.io/badge/version-3.0.0-informational)](pyproject.toml)

Convert **YARA rules** into **Sigma rules** and **native SIEM/EDR queries** —
with automatic IOC classification, MITRE ATT&CK tagging, configurable mapping
pipelines, a clean CLI, and a professional web workbench. Ships
**Docker-Compose-ready** with gunicorn and `sigma-cli` bundled for native
conversion out of the box.

```bash
docker compose up -d --build   # → http://127.0.0.1:8000
```

> This is the **consolidated v3** release. It merges the simplicity of v1 and
> the modular architecture of v2 into a single, working, tested, containerized
> package.

---

## ✨ Features

- **Modular library** (`yar2sig`) — parser, IOC classifier, Sigma emitter, and
  backend query generator are cleanly separated and independently testable.
- **IOC classification** — patterns are auto-classified as `url`, `ip`, `hash`,
  `email`, `domain`, `registry`, `mutex`, `user_agent`, `named_pipe`,
  `path_or_filename`, or `generic` and mapped to the right Sigma field per
  pipeline.
- **YARA parsing** — handles text, hex, and regex strings, multiple rules per
  file, rule tags, and `meta` fields.
- **MITRE ATT&CK tagging** — technique IDs (`T1059.001`) found in `meta` are
  auto-converted to `attack.t1059.001` tags.
- **Configurable pipelines** — YAML mapping specs under `yar2sig/mappings/`
  define how IOCs map to fields for each log source. Ships with **sysmon**,
  **winsec**, **linux**, and **proxy**. Add new ones without touching code.
- **7 SIEM/EDR backends** — Elastic, Splunk, **Microsoft Sentinel/Defender (KQL)**,
  QRadar, Carbon Black, SentinelOne, CrowdStrike. Uses `sigma-cli` for native
  conversion when installed; otherwise falls back to wildcard queries.
- **Bulk import** — convert entire YARA rule directories with `--dir` flag
  (`yar2sig convert dir/ --dir -o sigma-out/`).
- **Conversion report** — every conversion explains how each pattern was
  classified and mapped.
- **Conversion confidence** — generated rules include a `x_yar2sig` quality
  block with confidence score, warnings, and review-required status.
- **Safer fallback queries** — backend fallback queries escape quotes,
  backslashes, Lucene special characters, and SQL-like wildcard characters.
- **YARA Sigma Studio** — focused YARA-to-Sigma workbench with `.yar` import,
  mapping pipeline selection, SIEM query backend selection, Sigma/Query/Report
  tabs, confidence metrics, copy/download actions, sample rules, and
  `Ctrl+Enter` conversion.
- **CLI** — convert single files or whole directories; list pipelines; generate
  backend queries; reverse-convert Sigma YAML to best-effort YARA.
- **Sigma → YARA reverse conversion** — safe scalar extraction, escaped text and
  regex patterns, bounded output, explicit approximation reports, and YAML
  stream support.
- **Docker-Compose-ready** — hardened container (non-root, read-only FS,
  dropped capabilities, resource limits) running gunicorn, with `sigma-cli`
  and backend plugins baked in.

---

## 📦 Installation

### 🐳 Docker (recommended)

The image bundles **gunicorn** (production WSGI) and **sigma-cli** + backend
plugins, so native query conversion works out of the box.

```bash
docker compose up -d --build
# open http://127.0.0.1:8000
```

Change the port with `PORT=9000 docker compose up -d`. Stop with
`docker compose down`. Health: `curl localhost:8000/healthz`.

The container is hardened: non-root user, read-only root FS, dropped Linux
capabilities, `no-new-privileges`, and CPU/memory limits (1 CPU / 256 MB).

### 🐍 Local (Python)

```bash
git clone https://github.com/wahidhendrawan/yara-sigma-webui.git
cd yara-sigma-webui
pip install -r requirements.txt
python app.py            # dev server on http://127.0.0.1:5000
```

Or install as a package (gives you the `yar2sig` command):

```bash
pip install -e .
```

For a full local install with web, production server, and native Sigma backend
conversion support:

```bash
pip install -e ".[full]"
```

---

## 🖥️ Web UI

```bash
docker compose up -d --build   # http://127.0.0.1:8000  (recommended)
# or, for local dev:
python app.py                  # http://127.0.0.1:5000
```

Paste or import a `.yar` rule, pick a **mapping pipeline** and optional
**query backend**, hit **Convert** (or `Ctrl+Enter`). The web UI returns a
Sigma rule, a backend-specific SIEM/EDR query, and a conversion report in
separate tabs.

The web API validates pipeline/backend names and returns structured conversion
metadata plus query output:

```json
{
  "sigma": "title: Suspicious_Cmd...",
  "query": "_raw=\"*cmd.exe*\"",
  "quality": {
    "confidence": "medium",
    "confidence_score": 70,
    "review_required": true,
    "warnings": ["Complex YARA condition preserved only approximately: ..."]
  }
}
```

---

## ⌨️ CLI

```bash
# List available mapping pipelines
python -m yar2sig pipelines

# Convert a single file (prints YAML)
python -m yar2sig convert samples/malware.yar -p sysmon

# Convert a directory of rules into an output folder
python -m yar2sig convert rules/ -p winsec -o out/ -v

# Bulk import: force directory mode with --dir flag
python -m yar2sig convert yara-dump/ --dir -p linux -o sigma-output/

# Machine-readable output for CI/SIEM pipelines (one JSON document)
python -m yar2sig convert samples/malware.yar --format json > conversion.json

# Generate a native Splunk query
python -m yar2sig query samples/malware.yar -b splunk

# Generate a Microsoft Sentinel KQL query
python -m yar2sig query samples/malware.yar -b kusto

# Reverse: Convert Sigma YAML to YARA (best-effort)
python -m yar2sig reverse sigma-rule.yml -o yara-out/

# Reverse: Convert a directory of Sigma rules to YARA
python -m yar2sig reverse sigma-rules/ -o yara-out/

# Reverse: JSON format with conversion report
python -m yar2sig reverse sigma-rule.yml --format json

# Reverse: Verbose mode shows warnings
python -m yar2sig reverse sigma-rule.yml -v

# Reverse: Omit conversion warnings from YARA output
python -m yar2sig reverse sigma-rule.yml --no-comments
```

If installed via `pip install -e .`, replace `python -m yar2sig` with `yar2sig`.

### 🔄 Reverse Conversion (Sigma → YARA)

The `reverse` command provides **best-effort** Sigma-to-YARA conversion. Since Sigma describes **log events** and YARA scans **bytes**, conversion is inherently approximate. The converter:

- ✅ Extracts scalar/list detection values into escaped YARA strings or regex patterns
- ✅ Preserves basic `any`/`all`/`and`/`or` condition semantics where representable
- ✅ Sanitizes identifiers and enforces pattern limits (500 patterns, 10KB per pattern)
- ✅ Supports Sigma wildcards (`*`, `?`) → YARA regex conversion
- ✅ Handles `|re`, `|cased`, `|utf16`, `|wide`, and other modifiers
- ⚠️ Emits explicit warnings for approximations, unsupported features, and skipped values
- ⚠️ Adds conversion report as comments in YARA output (disable with `--no-comments`)
- ❌ Skips unsupported modifiers (`|cidr`, `|fieldref`, comparisons)
- ❌ Cannot represent negation, field references, or complex Sigma transformations

**Always review generated YARA rules before deployment.** The converter never silently claims exact equivalence.

---

## 🧩 Library API

### YARA → Sigma

```python
from yar2sig import convert, generate_query, available_pipelines

sigma_rule, report = convert(open("rule.yar").read(), pipeline="sysmon")
print(available_pipelines())   # ['linux', 'proxy', 'sysmon', 'winsec']

# native query for a backend
from yar2sig.parser import parse_yara_rule
parsed = parse_yara_rule(open("rule.yar").read())
print(generate_query("splunk", sigma_rule, parsed["strings"]))
```

### Sigma → YARA (Reverse)

```python
from yar2sig import convert_sigma_to_yara, convert_sigma_text, convert_sigma_file

# Convert a single parsed Sigma rule
sigma_rule = {
    "title": "Suspicious Process",
    "detection": {
        "selection": {"CommandLine": "powershell.exe -enc"},
        "condition": "selection"
    }
}
yara_source, report = convert_sigma_to_yara(sigma_rule)
print(yara_source)
for warning in report:
    print(f"  {warning}")

# Convert YAML text (supports multiple documents)
yaml_text = open("sigma-rules.yml").read()
results = convert_sigma_text(yaml_text)
for yara_source, report in results:
    print(yara_source)

# Convert from file
results = convert_sigma_file("rule.yml")
yara_source, report = results[0]

# Control limits and comments
yara_source, report = convert_sigma_to_yara(
    sigma_rule,
    max_patterns=100,           # default: 500
    max_pattern_length=5000,    # default: 10000 bytes
    include_comments=False      # default: True
)
```

**Exception handling:**

```python
from yar2sig import SigmaConversionError

try:
    results = convert_sigma_text(user_input)
except SigmaConversionError as e:
    print(f"Invalid Sigma rule: {e}")
```

---

## 🗂️ Mapping Pipelines

Each pipeline is a YAML file in `yar2sig/mappings/`:

```yaml
logsource:
  product: windows
  service: sysmon
fallback_field: Image
mappings:
  url:
    fields: [Image, CommandLine]
    op: contains
  ip:
    fields: [DestinationIp]
    op: equals
  # ...
```

To add a new pipeline (e.g. for Zeek, Okta, AWS CloudTrail), drop a new
`.yaml` file in that directory — it's picked up automatically.

| Pipeline | Log source | Use case |
|---|---|---|
| `sysmon` | Windows / Sysmon | Endpoint process/network/registry events |
| `winsec` | Windows Security | 4688 process creation, logons |
| `linux`  | Linux process_creation | Auditd / Sysmon-for-Linux |
| `proxy`  | Web proxy | URL/domain/UA-based detection |

---

## 🎯 Supported Backends

| Backend | Native (sigma-cli) | Fallback field |
|---|---|---|
| Elastic (Lucene/KQL) | ✅ `lucene` | `message` |
| Splunk SPL | ✅ `splunk` | `_raw` |
| Microsoft Sentinel / Defender (KQL) | ✅ `kusto` | `ProcessCommandLine` |
| IBM QRadar AQL | ✅ `qradar` | `payload` |
| VMware Carbon Black | fallback | `process_cmdline` |
| SentinelOne Deep Visibility | fallback | `SrcProcCmdLine` |
| CrowdStrike Falcon | fallback | `CommandLine` |

Install `sigma-cli` + the relevant backend plugin for native conversion.

---

## 🧪 Tests

```bash
pip install -e ".[web,dev]"
pytest -q --cov=yar2sig --cov-report=term
```

The test suite enforces a 70% branch-coverage floor for `yar2sig`.

The repository includes GitHub Actions CI for Python 3.9 and 3.12, plus a Docker
image build check.

---

## ⚠️ Disclaimer

YARA and Sigma operate on **different data models** — YARA matches file/memory
content, Sigma matches log events. This tool produces a **best-effort starting
point**, not a 1:1 translation. Always review generated rules and tune fields,
operators, and false positives for your environment before deploying.

---

## 📄 License

[GPL-3.0](LICENSE) © Wahid Hendrawan
