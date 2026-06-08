# 🛡️ YARA → Sigma Converter (`yar2sig`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Backends](https://img.shields.io/badge/SIEM%2FEDR%20backends-7-6366f1)](#-supported-backends)
[![Tests](https://img.shields.io/badge/tests-6%20passing-brightgreen)](tests/)
[![Version](https://img.shields.io/badge/version-3.0.0-informational)](pyproject.toml)

Convert **YARA rules** into **Sigma rules** and **native SIEM/EDR queries** —
with automatic IOC classification, MITRE ATT&CK tagging, configurable mapping
pipelines, a clean CLI, and a modern web UI. Ships **Docker-Compose-ready** with
gunicorn and `sigma-cli` bundled for native conversion out of the box.

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
  `email`, `domain`, `registry`, `mutex`, `path_or_filename`, or `generic` and
  mapped to the right Sigma field per pipeline.
- **YARA parsing** — handles text, hex, and regex strings, multiple rules per
  file, rule tags, and `meta` fields.
- **MITRE ATT&CK tagging** — technique IDs (`T1059.001`) found in `meta` are
  auto-converted to `attack.t1059.001` tags.
- **Configurable pipelines** — YAML mapping specs under `yar2sig/mappings/`
  define how IOCs map to fields for each log source. Ships with **sysmon**,
  **winsec**, **linux**, and **proxy**. Add new ones without touching code.
- **7 SIEM/EDR backends** — Elastic, Splunk, Microsoft Sentinel/Defender (Kusto),
  QRadar, Carbon Black, SentinelOne, CrowdStrike. Uses `sigma-cli` for native
  conversion when installed; otherwise falls back to wildcard queries.
- **Conversion report** — every conversion explains how each pattern was
  classified and mapped.
- **Conversion confidence** — generated rules include a `x_yar2sig` quality
  block with confidence score, warnings, and review-required status.
- **Safer fallback queries** — backend fallback queries escape quotes,
  backslashes, Lucene special characters, and SQL-like wildcard characters.
- **Modern web UI** — YARA-to-Sigma workbench with Sigma output, optional
  SIEM query tab, conversion report, confidence metrics, file import, copy &
  download buttons, built-in sample rules, and `Ctrl+Enter` conversion.
- **CLI** — convert single files or whole directories; list pipelines; generate
  backend queries.
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

Paste or import a YARA rule, pick a **mapping pipeline** and optional
**query backend**, hit **Convert** (or `Ctrl+Enter`). The web UI returns a
Sigma rule, a native query tab, and a conversion report.

The web API validates pipeline/backend names and returns structured conversion
metadata:

```json
{
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

# Generate a native Splunk query
python -m yar2sig query samples/malware.yar -b splunk
```

If installed via `pip install -e .`, replace `python -m yar2sig` with `yar2sig`.

---

## 🧩 Library API

```python
from yar2sig import convert, generate_query, available_pipelines

sigma_rule, report = convert(open("rule.yar").read(), pipeline="sysmon")
print(available_pipelines())   # ['linux', 'proxy', 'sysmon', 'winsec']

# native query for a backend
from yar2sig.parser import parse_yara_rule
parsed = parse_yara_rule(open("rule.yar").read())
print(generate_query("splunk", sigma_rule, parsed["strings"]))
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
pytest -q
```

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

[MIT](LICENSE) © Wahid Hendrawan
