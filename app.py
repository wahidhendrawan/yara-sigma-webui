"""Web application for yar2sig version 2.

This Flask application provides a simple browser interface for the
YARA → Sigma converter.  Users can upload a `.yar` file or paste a
YARA rule into a text area, select the desired mapping pipeline and
view the generated Sigma rule along with a detailed conversion
report.  The Sigma YAML can be downloaded directly from the page.
"""

from __future__ import annotations

import yaml
from flask import Flask, render_template, request, make_response

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Adjust Python path for local development.
#
# When running this web UI directly from a cloned repository without
# installing the `yar2sig` package (e.g. via `pip install -e .`), Python
# may not know where to find the package.  To avoid a `ModuleNotFoundError`
# we explicitly add the repository root and the `yar2sig` subdirectory to
# `sys.path` before attempting to import from it.  This logic has no effect
# when the package has been installed properly.
_root = Path(__file__).resolve().parent
sys.path.append(str(_root))
sys.path.append(str(_root / 'yar2sig'))

from yar2sig import available_pipelines, load_mapping
from yar2sig.parsers import parse_yara_rule
from yar2sig.emitters import emit_sigma

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index() -> str:
    yara_text: str = ''
    sigma_text: str = ''
    notes: list[str] = []
    selected_pipeline = available_pipelines()[0] if available_pipelines() else ''

    if request.method == 'POST':
        # Get YARA from form or uploaded file
        yara_text = request.form.get('yara', '')
        uploaded = request.files.get('file')
        if uploaded and uploaded.filename:
            try:
                yara_bytes = uploaded.read()
                yara_text = yara_bytes.decode('utf‑8', errors='ignore')
            except Exception:
                yara_text = ''
        # Determine selected pipeline
        selected_pipeline = request.form.get('pipeline', selected_pipeline)
        # Parse and convert
        parsed = parse_yara_rule(yara_text)
        try:
            mapping = load_mapping(selected_pipeline)
        except FileNotFoundError:
            mapping = load_mapping(available_pipelines()[0]) if available_pipelines() else {}
        sigma_rule, notes = emit_sigma(parsed, mapping)
        sigma_text = yaml.dump(sigma_rule, sort_keys=False, allow_unicode=True)

    return render_template(
        'index.html',
        yara_text=yara_text,
        sigma_text=sigma_text,
        notes=notes,
        pipeline=selected_pipeline,
        pipelines=available_pipelines(),
    )


@app.route('/download_sigma', methods=['POST'])
def download_sigma():
    """Return the Sigma YAML as a downloadable file."""
    content = request.form.get('sigma_data', '')
    response = make_response(content)
    response.headers['Content-Type'] = 'text/yaml; charset=utf-8'
    response.headers['Content-Disposition'] = 'attachment; filename=converted_sigma.yml'
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)