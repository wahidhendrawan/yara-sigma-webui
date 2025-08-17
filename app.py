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
# -------------------------------------------------------------------------
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

# Import the yar2sig modules.  If they cannot be found, attempt a second
# import after modifying sys.path based on this file's location.  This
# caters for deployment environments where sys.path was not adjusted at
# module import time for some reason (e.g. older revisions of this file).
try:
    from yar2sig import available_pipelines, load_mapping
    from yar2sig.parsers import parse_yara_rule
    from yar2sig.emitters import emit_sigma
except ModuleNotFoundError:
    # Re-compute candidate paths relative to this file and insert them.
    _this = Path(__file__).resolve()
    _dir = _this.parent
    cand = _dir / 'yar2sig'
    if cand.is_dir():
        sys.path.insert(0, str(_dir))
        sys.path.insert(0, str(cand))
        from yar2sig import available_pipelines, load_mapping
        from yar2sig.parsers import parse_yara_rule
        from yar2sig.emitters import emit_sigma
    else:
        # Reraise the original error if the package still isn't found
        raise

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