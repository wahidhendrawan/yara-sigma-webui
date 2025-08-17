"""Web application for yar2sig version 2.

This Flask application provides a simple browser interface for the
YARA → Sigma converter.  Users can upload a `.yar` file or paste a
YARA rule into a text area, select the desired mapping pipeline and
view the generated Sigma rule along with a detailed conversion
report.  Additionally, users may choose a back‑end for sigma-cli
conversion and view queries (when sigma-cli is installed).  The
Sigma YAML can be downloaded directly from the page.
"""

from __future__ import annotations

import yaml
from flask import Flask, render_template, request, make_response

import os
import sys
from pathlib import Path

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Ensure the yar2sig package is discoverable at runtime.
#
# The web UI can be executed in a variety of contexts: directly from the
# repository, installed via pip, or deployed into a directory that may not
# include the `yar2sig` sources alongside app.py.  To avoid a
# `ModuleNotFoundError` when the package hasn't been installed, search
# upwards from the current file's directory for a `yar2sig` folder and
# append the discovered location(s) to `sys.path`.  When the package has
# been installed, this loop will have no effect and the standard import
# resolution will succeed.
_this_file = Path(__file__).resolve()
_base = _this_file.parent

# Prefer a local yar2sig directory relative to this file.  If the app is
# executed from its repository checkout, the yar2sig package will live
# alongside app.py.  Insert both the base directory and the package
# directory onto sys.path so Python can locate it.  When the app is
# installed normally (e.g. via pip) this block has no effect, and the
# standard site-packages resolution will apply.
if (_base / 'yar2sig').is_dir():
    sys.path.insert(0, str(_base))
    sys.path.insert(0, str(_base / 'yar2sig'))

# If the package isn't found immediately next to this file, search up
# through parent directories for a yar2sig folder.  This supports cases
# where the web UI is installed into a deeper directory (e.g. /opt).  The
# first matching parent directory is added to sys.path along with the
# package directory.  When the package has been installed via pip, this
# loop will exit without modification.
for parent in [_base] + list(_base.parents):
    candidate = parent / 'yar2sig'
    if candidate.is_dir():
        sys.path.insert(0, str(parent))
        sys.path.insert(0, str(candidate))
        break


# ---------------------------------------------------------------------------
# Local fallback implementation of the yar2sig API.
#
# If the yar2sig package is unavailable, provide minimalist implementations of
# the conversion functions directly in this module.  These implementations
# mirror the behaviour of the library's ``available_pipelines``,
# ``load_mapping``, ``parse_yara_rule``, ``emit_sigma`` and ``classify_pattern``
# functions.  They operate on the mapping YAML files stored under
# ``mappings/pipelines`` relative to this file.  When the full yar2sig package
# is available (for example via a pip installation), the import below will
# override these fallback definitions.
try:
    from yar2sig import available_pipelines, load_mapping  # type: ignore
    from yar2sig.parsers import parse_yara_rule  # type: ignore
    from yar2sig.emitters import emit_sigma  # type: ignore
except ModuleNotFoundError:
    import re
    import uuid
    import datetime
    from importlib import resources

    def _pipeline_path() -> Path:
        """Return the directory containing pipeline YAML mappings."""
        return _base / 'mappings' / 'pipelines'

    def available_pipelines() -> list[str]:
        dirpath = _pipeline_path()
        names: list[str] = []
        if dirpath.is_dir():
            for entry in dirpath.iterdir():
                if entry.suffix == '.yaml':
                    names.append(entry.stem)
        return sorted(names)

    def load_mapping(name: str) -> dict:
        path = _pipeline_path() / f'{name}.yaml'
        if not path.exists():
            raise FileNotFoundError(f"Pipeline '{name}' not found")
        with path.open('r', encoding='utf-8') as fh:
            return yaml.safe_load(fh) or {}

    def parse_yara_rule(text: str) -> dict:
        def remove_comments(s: str) -> str:
            s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
            s = re.sub(r'//.*', '', s)
            return s

        text_no_comments = remove_comments(text)
        name_match = re.search(r'(?m)^\s*rule\s+([^\s{]+)', text_no_comments)
        name = name_match.group(1) if name_match else 'ConvertedRule'
        meta: dict[str, str] = {}
        meta_section = re.search(
            r'meta\s*:\s*(.*?)\s*(strings|condition)\s*:',
            text_no_comments,
            flags=re.S | re.I,
        )
        if meta_section:
            body = meta_section.group(1)
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    key = key.strip()
                    val = val.strip().strip("\"' ")
                    meta[key] = val

        strings: list[str] = []
        strings_section = re.search(
            r'strings\s*:\s*(.*?)\s*condition\s*:',
            text_no_comments,
            flags=re.S | re.I,
        )
        if strings_section:
            body = strings_section.group(1)
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                if '=' in line:
                    _, val = line.split('=', 1)
                    val = val.strip()
                    str_match = re.search(r'"([^"\\]*(?:\\.[^"\\]*)*)"', val)
                    if str_match:
                        pattern = str_match.group(1)
                        strings.append(pattern)

        condition_text = ''
        condition_section = re.search(
            r'condition\s*:\s*(.*?)(?:rule\s+\w+|$)',
            text_no_comments,
            flags=re.S | re.I,
        )
        if condition_section:
            condition_text = condition_section.group(1).strip()

        cond_type = 'any'
        if re.search(r'\ball\s+of\b', condition_text, flags=re.I):
            cond_type = 'all'
        elif re.search(r'\bany\s+of\b', condition_text, flags=re.I):
            cond_type = 'any'

        return {
            'name': name,
            'meta': meta,
            'strings': strings,
            'cond_type': cond_type,
        }

    HASH_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')
    IP_V4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
    IP_V6_RE = re.compile(r'^[0-9a-fA-F:]{3,39}$')
    DOMAIN_RE = re.compile(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
    COMMON_FILE_EXTENSIONS = {
        'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'psm1',
        'vbs', 'js', 'scr', 'jar', 'zip', 'rar'
    }

    def classify_pattern(pattern: str) -> str:
        s = pattern.strip()
        if '://' in s:
            return 'url'
        if IP_V4_RE.match(s) or IP_V6_RE.match(s):
            return 'ip'
        if HASH_RE.match(s):
            return 'hash'
        if DOMAIN_RE.match(s):
            return 'domain'
        if any(s.lower().endswith(f'.{ext}') for ext in COMMON_FILE_EXTENSIONS):
            return 'path_or_filename'
        return 'generic_string'

    def emit_sigma(parsed: dict, mapping: dict) -> tuple[dict, list[str]]:
        name = parsed['name']
        strings = parsed['strings']
        cond_type = parsed['cond_type']
        notes: list[str] = []

        # Build selections according to mapping heuristics
        selections: list[dict] = []
        for pat in strings:
            cls = classify_pattern(pat)
            mp = mapping.get(cls, {})
            fields = mp.get('fields', [])
            op = mp.get('op', 'contains')
            if not fields:
                fields = ['message']
            for f in fields:
                selections.append({f"{f}|{op}": pat})
            if not mp:
                notes.append(f"No mapping for pattern '{pat}', using default field(s).")
        # Compose detection
        if cond_type == 'all':
            detection = {
                'selection': selections,
                'condition': ' and '.join([f's{idx}' for idx in range(len(selections))])
            }
        else:
            detection = {
                'selection': selections,
                'condition': ' or '.join([f's{idx}' for idx in range(len(selections))])
            }

        sigma_rule = {
            'title': f"Converted from YARA: {name}",
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': f"Auto‑converted from YARA rule {name}",
            'author': 'yar2sig',
            'date': datetime.date.today().isoformat(),
            'logsource': mapping.get('logsource', {}),
            'detection': detection,
            'level': 'medium',
        }
        return sigma_rule, notes


@app.route('/', methods=['GET', 'POST'])
def index() -> str:
    yara_text: str = ''
    sigma_text: str = ''
    notes: list[str] = []
    queries: list[str] = []
    # Supported back‑ends for sigma-cli conversion.  These correspond to
    # target identifiers accepted by sigma-cli.  If sigma-cli isn't
    # installed, queries will remain empty.
    BACKENDS = [
        'elasticsearch',  # Elastic Search / Kibana (KQL)
        'splunk',         # Splunk SPL
        'kusto',          # Microsoft Sentinel / Azure Data Explorer
        'qradar',         # IBM QRadar AQL
        'arcsight',       # Micro Focus ArcSight DSL
    ]
    selected_backend = BACKENDS[0]
    selected_pipeline = available_pipelines()[0] if available_pipelines() else ''

    if request.method == 'POST':
        yara_text = request.form.get('yara', '')
        uploaded = request.files.get('file')
        if uploaded and uploaded.filename:
            try:
                yara_bytes = uploaded.read()
                yara_text = yara_bytes.decode('utf-8', errors='ignore')
            except Exception:
                yara_text = ''
        selected_pipeline = request.form.get('pipeline', selected_pipeline)
        selected_backend = request.form.get('backend', selected_backend)
        parsed = parse_yara_rule(yara_text)
        try:
            mapping = load_mapping(selected_pipeline)
        except FileNotFoundError:
            mapping = load_mapping(available_pipelines()[0]) if available_pipelines() else {}
        sigma_rule, notes = emit_sigma(parsed, mapping)
        sigma_text = yaml.dump(sigma_rule, sort_keys=False, allow_unicode=True)
        # Attempt to convert to backend queries via sigma-cli
        try:
            import subprocess
            import tempfile
            with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.yml') as tmp_in:
                tmp_in.write(sigma_text)
                tmp_in.flush()
                result = subprocess.run(
                    [
                        'sigma-cli',
                        'convert',
                        '-t',
                        selected_backend,
                        '--compact',
                        tmp_in.name,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    queries = [q for q in result.stdout.splitlines() if q.strip()]
        except Exception:
            queries = []
    return render_template(
        'index.html',
        yara_text=yara_text,
        sigma_text=sigma_text,
        notes=notes,
        pipeline=selected_pipeline,
        pipelines=available_pipelines(),
        backend=selected_backend,
        backends=BACKENDS,
        queries=queries,
    )


@app.route('/download_sigma', methods=['POST'])
def download_sigma():
    content = request.form.get('sigma_data', '')
    response = make_response(content)
    response.headers['Content-Type'] = 'text/yaml; charset=utf-8'
    response.headers['Content-Disposition'] = 'attachment; filename=converted_sigma.yml'
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)