# 🛡️ YARA → Sigma Converter (`yar2sig`)

[![CI](https://github.com/wahidhendrawan/yara-sigma-webui/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/yara-sigma-webui/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wahidhendrawan/yara-sigma-webui?sort=semver)](https://github.com/wahidhendrawan/yara-sigma-webui/releases/latest)
[![License](https://img.shields.io/github/license/wahidhendrawan/yara-sigma-webui)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/wahidhendrawan/yara-sigma-webui/badge)](https://scorecard.dev/viewer/?uri=github.com/wahidhendrawan/yara-sigma-webui)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Backends](https://img.shields.io/badge/SIEM%2FEDR%20backends-7-6366f1)](#-supported-backends)

Convert **YARA rules** into **Sigma rules** and **native SIEM/EDR queries** —
with automatic IOC classification, MITRE ATT&CK tagging, configurable mapping
pipelines, a clean CLI, and a professional web workbench — all in **one Rust
binary**. Ships **Docker-Compose-ready** with `sigma-cli` bundled for native
conversion out of the box.

```bash
docker compose up -d --build   # → http://127.0.0.1:8000
```

> **v4 is a rewrite in Rust.** One static binary serves the CLI, the web UI and
> the JSON API. The CLI commands and flags, the mapping pipelines, the
> `POST /api/convert` contract and the Docker deployment are unchanged; the
> Python package and its library API are gone (see `CHANGELOG.md`).

---

## ✨ Features

- **One Rust binary** — parser, IOC classifier, Sigma emitter, backend query
  generator, CLI and web server in a single `yar2sig` executable with no runtime
  dependencies (`sigma-cli` is optional). Also usable as a Rust crate.
- **IOC classification** — patterns are auto-classified as `url`, `ip`, `hash`,
  `email`, `domain`, `registry`, `mutex`, `user_agent`, `named_pipe`,
  `path_or_filename`, or `generic` and mapped to the right Sigma field per
  pipeline.
- **YARA parsing** — handles text, hex, and regex strings, multiple rules per
  file, rule tags, and `meta` fields.
- **MITRE ATT&CK tagging** — technique IDs (`T1059.001`) found in `meta` are
  auto-converted to `attack.t1059.001` tags.
- **Configurable pipelines** — YAML mapping specs under `mappings/` define how
  IOCs map to fields for each log source and are embedded at build time. Ships
  with **sysmon**, **winsec**, **linux**, and **proxy**. Add new ones without
  touching code.
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
  dropped capabilities, resource limits) running the release binary, with
  `sigma-cli` and backend plugins baked in.

---

## 📦 Installation

### 🐳 Docker (recommended)

The image bundles the release binary and **sigma-cli** + backend plugins, so
native query conversion works out of the box.

```bash
docker compose up -d --build
# open http://127.0.0.1:8000
```

Change the port with `PORT=9000 docker compose up -d`. Stop with
`docker compose down`. Health: `curl localhost:8000/healthz`.

The container is hardened: non-root user, read-only root FS, dropped Linux
capabilities, `no-new-privileges`, and CPU/memory limits (1 CPU / 256 MB).

### 🦀 Local (Rust 1.85+)

```bash
git clone https://github.com/wahidhendrawan/yara-sigma-webui.git
cd yara-sigma-webui
cargo build --release
./target/release/yar2sig serve   # http://127.0.0.1:8000
```

Or put the `yar2sig` command on your PATH with `cargo install --path .`.

Native query conversion needs `sigma-cli` and its backend plugins on PATH;
`requirements.txt` pins them for the Docker image (`pip install -r requirements.txt`
installs the same set locally). Without them, fallback wildcard queries are generated.
`requirements.txt` is generated from `requirements.in` with
`pip-compile --strip-extras --output-file=requirements.txt requirements.in`.

---

## 🖥️ Web UI

```bash
docker compose up -d --build   # http://127.0.0.1:8000  (recommended)
# or, from a checkout:
cargo run --release -- serve   # http://127.0.0.1:8000 (--host/--port to change)
```

Tick **Detection-Rules layout** to get the rule in the layout of the
[Detection-Rules](https://github.com/wahidhendrawan/Detection-Rules) repository (see the CLI
section); the download is then named after the rule. The API takes the same options:
`{"layout": "detection-rules", "attack": ["T1059.001"]}` on `POST /api/convert`.

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
yar2sig pipelines

# Convert a single file (prints YAML)
yar2sig convert samples/malware.yar -p sysmon

# Convert a directory of rules into an output folder
yar2sig convert rules/ -p winsec -o out/ -v

# Bulk import: force directory mode with --dir flag
yar2sig convert yara-dump/ --dir -p linux -o sigma-output/

# Machine-readable output for CI/SIEM pipelines (one JSON document)
yar2sig convert samples/malware.yar --format json > conversion.json

# Write rules straight into a Detection-Rules checkout (github.com/wahidhendrawan/Detection-Rules)
yar2sig convert rules/ -p sysmon --format detection-rules --attack T1059.001 -o ../Detection-Rules/sigma/windows/

# Generate a native Splunk query
yar2sig query samples/malware.yar -b splunk

# Generate a Microsoft Sentinel KQL query
yar2sig query samples/malware.yar -b kusto

# Reverse: Convert Sigma YAML to YARA (best-effort)
yar2sig reverse sigma-rule.yml -o yara-out/

# Reverse: Convert a directory of Sigma rules to YARA
yar2sig reverse sigma-rules/ -o yara-out/

# Reverse: JSON format with conversion report
yar2sig reverse sigma-rule.yml --format json

# Reverse: Verbose mode shows warnings
yar2sig reverse sigma-rule.yml -v

# Reverse: Omit conversion warnings from YARA output
yar2sig reverse sigma-rule.yml --no-comments
```

`yar2sig` is `./target/release/yar2sig` after `cargo build --release`, or on PATH
after `cargo install --path .`.

### 📚 Detection-Rules export

`--format detection-rules` writes each rule in the layout of the
[Detection-Rules](https://github.com/wahidhendrawan/Detection-Rules) repository: its template key
order, `modified` and `fields` filled in, the `x_yar2sig` review block dropped (the report still
has it with `-v`), and at least one `attack.tNNNN` tag, which that repository's `detection_rules lint`
requires. Technique IDs found in the YARA `meta` are used; add missing ones with `--attack`. A rule
without any technique is reported on stderr and skipped, and the command exits 1.

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

The crate is not on crates.io; depend on it with
`yar2sig = { git = "https://github.com/wahidhendrawan/yara-sigma-webui" }`.

### YARA → Sigma

```rust
use yar2sig::backends::generate_query;
use yar2sig::parser::parse_yara_rule;
use yar2sig::{available_pipelines, convert, convert_all};

let text = std::fs::read_to_string("rule.yar")?;
let (sigma_rule, report) = convert(&text, "sysmon")?;   // first rule; convert_all for every rule
println!("{}", serde_yaml_ng::to_string(&sigma_rule)?); // sigma_rule is a serde_json::Value
println!("{:?}", available_pipelines());                 // ["linux", "proxy", "sysmon", "winsec"]

// native query for a backend (sigma-cli when on PATH, fallback otherwise)
let parsed = parse_yara_rule(&text, 500, 10_000)?;
println!("{}", generate_query("splunk", &sigma_rule, &parsed.values())?);
```

### Sigma → YARA (Reverse)

```rust
use yar2sig::sig2yar::{convert_sigma_file, convert_sigma_text, convert_sigma_to_yara, ReverseOptions};

// YAML text (supports multiple documents) or a file: one (yara_source, report) per rule
for (yara_source, report) in convert_sigma_text(&yaml_text, &ReverseOptions::default())? {
    println!("{yara_source}");
    for warning in &report {
        println!("  {warning}");
    }
}
let results = convert_sigma_file(std::path::Path::new("rule.yml"), &ReverseOptions::default())?;

// A single parsed rule (serde_yaml_ng::Value), with limits and comments under control
let options = ReverseOptions { max_patterns: 100, max_pattern_length: 5000, include_comments: false };
let (yara_source, report) = convert_sigma_to_yara(&sigma_rule, &options)?;
```

Invalid input and bound violations are `yar2sig::Error` (its message is the
`error` field the API returns); a saturated native backend is
`yar2sig::backends::BackendBusy`.

---

## 🗂️ Mapping Pipelines

Each pipeline is a YAML file in `mappings/`:

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
`.yaml` file in that directory — `build.rs` embeds every file on the next
`cargo build`, no code change needed.

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

Each native conversion runs `sigma-cli` as a subprocess. `YAR2SIG_SIGMA_CONCURRENCY`
caps how many run at once per server process (default: CPU count; the Docker
image sets `2`). When every slot is busy, `/api/convert` returns `503` with
`Retry-After`.

---

## 🧪 Tests

```bash
cargo test                                   # unit, CLI and HTTP API tests
cargo clippy --all-targets -- -D warnings    # lint
```

GitHub Actions CI runs `cargo fmt --check`, clippy, the tests, a CLI smoke test,
and a Docker image build + healthcheck.

---

## ⚠️ Disclaimer

YARA and Sigma operate on **different data models** — YARA matches file/memory
content, Sigma matches log events. This tool produces a **best-effort starting
point**, not a 1:1 translation. Always review generated rules and tune fields,
operators, and false positives for your environment before deploying.

---

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## 📄 License

[GPL-3.0](LICENSE) © Wahid Hendrawan
