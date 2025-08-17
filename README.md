# YARA → Sigma Converter (Version 2)

This repository contains a Python library and accompanying web
application for converting **YARA** rules into approximate
**Sigma** detection rules.  Version 2 is a significant overhaul of
the original proof‑of‑concept: it introduces a modular conversion
library (`yar2sig`), configurable mapping specifications (called
*pipelines*), a command‑line interface and a refreshed web UI.

## Key features

* **Modular architecture** – YARA parsing, IOC classification,
  mapping, Sigma emission and UI are cleanly separated into
  independent modules.  You can easily swap out the parser or add
  new mapping pipelines for different log sources.
* **Configurable pipelines** – Mapping behaviour is driven by
  YAML specifications stored under `yar2sig/mappings/pipelines`.  Each
  pipeline defines how extracted indicators map to Sigma fields for a
  particular log source (e.g. Sysmon, Windows Security).  New
  pipelines can be added without touching any code.
* **IOC heuristics** – Plain text patterns extracted from YARA
  strings are classified as URLs, domains, IPs, hashes, file paths
  or generic strings.  These types determine which Sigma fields are
  populated.  The classification heuristics are simple by design and
  should be reviewed for critical rules.
* **Conversion report** – Every conversion produces a list of
  human‑readable notes describing how each pattern was classified and
  mapped.  These notes are stored in the Sigma rule under the
  custom `x-conversion-notes` field and are displayed in the web UI
  and CLI output.
* **Command‑line interface** – Use `python -m yar2sig` to convert
  single files or directories of YARA rules into Sigma YAML.  The
  pipeline can be specified on the command line and the resulting
  files are written to disk.
* **Refreshed web interface** – The Flask application uses the
  library internally and exposes pipeline and back‑end selection
  controls.  Upload a `.yar` file or paste a rule, choose a
  pipeline and view the generated Sigma rule along with the
  conversion report.

## Installation

Install the required dependencies and this package.  We recommend
using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If you wish to install the package for use as a library or CLI:

```bash
pip install -e .
```

## Usage

### CLI

Convert a single YARA file using the default Sysmon pipeline and write
the resulting Sigma rule to `converted/`:

```bash
python -m yar2sig -i rules/example.yar -p sysmon -o converted
```

Convert all `.yar` files in a directory using the Windows Security
pipeline:

```bash
python -m yar2sig -i yara_rules/ -p winsec -o sigma_rules
```

### Web UI

Start the Flask development server:

```bash
python app.py
```

Navigate to <http://localhost:5000> in your browser.  Paste a YARA
rule or upload a `.yar` file, choose the target pipeline and see the
generated Sigma rule and conversion notes.  You can download the
Sigma YAML from the interface.

## Limitations

* Only plain‑text strings are extracted from YARA rules.  Hex and
  regular expression patterns are ignored.
* The IOC classification heuristics are intentionally simple.  They
  may misclassify edge cases; review the conversion notes and
  adjust the mapping specification if needed.
* Mapping specifications only cover a few common Windows sources
  (Sysmon and Windows Security) out of the box.  Support for
  additional log sources can be added by creating new YAML files
  under `yar2sig/mappings/pipelines`.

## Contributing

Contributions are welcome!  You can add new pipelines, improve the
parser, extend the IOC heuristics or enhance the UI.  Please open
issues or pull requests with your suggestions and bug reports.