"""Flask web UI for yar2sig.

Serves a single-page converter. POST /api/convert returns the Sigma
rule (YAML), conversion report, and native queries for all backends.
"""

from __future__ import annotations

import yaml
from flask import Flask, jsonify, render_template, request

from yar2sig import (
    BACKENDS,
    available_pipelines,
    generate_query,
    load_mapping,
)
from yar2sig.emitter import emit_sigma
from yar2sig.parser import parse_yara_rule

app = Flask(__name__)


@app.route("/")
def index():
    return render_template(
        "index.html",
        pipelines=available_pipelines(),
        backends={k: v[0] for k, v in BACKENDS.items()},
    )


@app.route("/healthz")
def healthz():
    return jsonify(status="ok", pipelines=available_pipelines())


@app.route("/api/convert", methods=["POST"])
def api_convert():
    data = request.get_json(silent=True) or {}
    text = (data.get("rule") or "").strip()
    pipeline = data.get("pipeline") or "sysmon"
    backend = data.get("backend") or "splunk"
    if not text:
        return jsonify(error="No YARA rule provided"), 400
    try:
        parsed = parse_yara_rule(text)
        rule, report = emit_sigma(parsed, load_mapping(pipeline))
        sigma_yaml = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
        query = generate_query(backend, rule, parsed.get("strings", []))
        return jsonify(
            sigma=sigma_yaml,
            report=report,
            query=query,
            parsed={
                "name": parsed["name"],
                "patterns": len(parsed.get("strings", [])),
                "tags": rule.get("tags", []),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc)), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
