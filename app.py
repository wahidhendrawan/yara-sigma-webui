"""Flask web UI for yar2sig.

Serves a single-page YARA to Sigma converter. POST /api/convert returns
the Sigma rule (YAML), conversion report, quality metadata, and an optional
native SIEM query for the selected backend.
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
MAX_RULE_BYTES = 1_000_000


def _error(message: str, status: int, **extra):
    payload = {"error": message}
    payload.update(extra)
    return jsonify(payload), status


@app.route("/")
def index():
    return render_template(
        "index.html",
        pipelines=available_pipelines(),
        backends={key: value[0] for key, value in BACKENDS.items()},
    )


@app.route("/healthz")
def healthz():
    return jsonify(status="ok", pipelines=available_pipelines(), backends=list(BACKENDS))


@app.route("/api/convert", methods=["POST"])
def api_convert():
    if request.content_length and request.content_length > MAX_RULE_BYTES:
        return _error("Request body is too large", 413, limit=MAX_RULE_BYTES)

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _error("JSON object expected", 400)

    text = (data.get("rule") or "").strip()
    pipeline = data.get("pipeline") or "sysmon"
    backend = data.get("backend") or "splunk"
    if not text:
        return _error("No YARA rule provided", 400)
    if pipeline not in available_pipelines():
        return _error("Unknown mapping pipeline", 400, available=available_pipelines())
    if backend not in BACKENDS:
        return _error("Unknown backend", 400, available=list(BACKENDS))

    try:
        parsed = parse_yara_rule(text)
        rule, report = emit_sigma(parsed, load_mapping(pipeline))
        sigma_yaml = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
        query = generate_query(backend, rule, parsed.get("strings", []))
        return jsonify(
            sigma=sigma_yaml,
            query=query,
            report=report,
            quality=rule.get("x_yar2sig", {}),
            parsed={
                "name": parsed["name"],
                "patterns": len(parsed.get("strings", [])),
                "condition": parsed.get("condition_raw", ""),
                "tags": rule.get("tags", []),
            },
        )
    except FileNotFoundError as exc:
        return _error(str(exc), 400)
    except ValueError as exc:
        return _error(str(exc), 422)
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("conversion failed")
        return _error("Conversion failed", 500, detail=str(exc))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
