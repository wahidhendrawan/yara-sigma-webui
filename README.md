# 🛡️ YARA → Sigma Converter (`yar2sig`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-6%20passing-brightgreen)](tests/)

Convert **YARA rules** into **Sigma rules** and **native SIEM/EDR queries** —
with automatic IOC classification, MITRE ATT&CK tagging, configurable mapping
pipelines, a clean CLI, and a modern web UI.

> This is the **consolidated v3** release. It merges the simplicity of v1 and
> the modular architecture of v2 into a single, working, tested package.

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
- **Modern web UI** — dark theme, live conversion, tabs for Sigma/Query/Report,
  copy & download buttons, built-in sample rules, `Ctrl+Enter` to convert.
- **CLI** — convert single files or whole directories; list pipelines; generate
  backend queries.

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

---

## 🖥️ Web UI

```bash
docker compose up -d --build   # http://127.0.0.1:8000  (recommended)
# or, for local dev:
python app.py                  # http://127.0.0.1:5000
```

Paste a YARA rule, pick a **pipeline** and a **backend**, hit **Convert**
(or `Ctrl+Enter`). You get the Sigma rule, a native query, and a conversion
report — each copyable/downloadable.

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
pip install pytest
pytest -q
```

---

## ⚠️ Disclaimer

YARA and Sigma operate on **different data models** — YARA matches file/memory
content, Sigma matches log events. This tool produces a **best-effort starting
point**, not a 1:1 translation. Always review generated rules and tune fields,
operators, and false positives for your environment before deploying.

---

## 📄 License

[MIT](LICENSE) © Wahid Hendrawan
