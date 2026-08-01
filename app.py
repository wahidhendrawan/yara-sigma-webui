"""Flask web UI for yar2sig.

Serves a single-page YARA to Sigma converter. POST /api/convert returns
the Sigma rule (YAML), conversion report, quality metadata, and an optional
native SIEM query for the selected backend.
"""

from __future__ import annotations

import yaml
from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from yar2sig import (
    BACKENDS,
    available_pipelines,
    generate_query,
    load_mapping,
)
from yar2sig.emitter import emit_sigma
from yar2sig.parser import parse_yara_rule

MAX_RULE_BYTES = 1_000_000
MAX_REQUEST_BYTES = 1_100_000  # Allow bounded JSON framing around the rule
MAX_PATTERNS = 500  # Bound worst-case detection blocks per request
MAX_PATTERN_LENGTH = 10_000  # Bound worst-case pattern size

app = Flask(__name__)
# Hard body limit enforced up front, including huge Content-Length headers.
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES


@app.after_request
def set_security_headers(response):
    # SPA is self-contained with inline styles/scripts and no third-party resources
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.path == "/api/convert":
        response.headers["Cache-Control"] = "no-store"
    return response


def _error(message: str, status: int, **extra):
    payload = {"error": message}
    payload.update(extra)
    return jsonify(payload), status


@app.errorhandler(RequestEntityTooLarge)
def _handle_request_too_large(_exc: RequestEntityTooLarge):
    return _error("Request body is too large", 413, limit=MAX_RULE_BYTES)


@app.route("/")
def index():
    """Serve the static SPA frontend (no Jinja rendering needed)."""
    return app.send_static_file("index.html")


@app.route("/healthz")
def healthz():
    return jsonify(status="ok", pipelines=available_pipelines(), backends=list(BACKENDS))


@app.route("/api/convert", methods=["POST"])
def api_convert():
    if request.content_length and request.content_length > MAX_REQUEST_BYTES:
        return _error("Request body is too large", 413, limit=MAX_RULE_BYTES)

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _error("JSON object expected", 400)

    raw_rule = data.get("rule", "")
    pipeline = data.get("pipeline", "sysmon")
    backend = data.get("backend", "splunk")
    if raw_rule is None:
        raw_rule = ""
    if pipeline is None:
        pipeline = "sysmon"
    if backend is None:
        backend = "splunk"
    if not isinstance(raw_rule, str):
        return _error("Rule must be a string", 400)
    if not isinstance(pipeline, str) or not isinstance(backend, str):
        return _error("Pipeline and backend must be strings", 400)

    text = raw_rule.strip()
    if not text:
        return _error("No YARA rule provided", 400)
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        return _error("Rule text exceeds maximum size", 413, limit=MAX_RULE_BYTES)
    if pipeline not in available_pipelines():
        return _error("Unknown mapping pipeline", 400, available=available_pipelines())
    if backend not in BACKENDS:
        return _error("Unknown backend", 400, available=list(BACKENDS))

    try:
        parsed = parse_yara_rule(
            text,
            max_patterns=MAX_PATTERNS,
            max_pattern_length=MAX_PATTERN_LENGTH,
        )
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
    except Exception:  # noqa: BLE001
        app.logger.exception("conversion failed")
        return _error("Conversion failed", 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
