# Contributing to yar2sig

Thanks for your interest in improving the YARA → Sigma converter!

## Development setup

```bash
git clone https://github.com/wahidhendrawan/yara-sigma-webui.git
cd yara-sigma-webui
pip install -r requirements.txt pytest
pytest -q          # run the test suite
python app.py      # dev server on http://127.0.0.1:5000
```

Or with Docker:

```bash
docker compose up -d --build   # http://127.0.0.1:8000
```

## Project layout

```
yar2sig/
├─ parser.py    # YARA parsing (text/hex/regex, multi-rule, tags, meta)
├─ ioc.py       # IOC classification heuristics
├─ emitter.py   # Sigma emission + MITRE tagging + confidence scoring
├─ backends.py  # native query generation (sigma-cli + fallback)
├─ cli.py       # command-line interface
└─ mappings/    # one YAML pipeline per log source
app.py          # Flask web UI (+ /api/convert, /healthz)
templates/      # web UI
tests/          # pytest suite
```

## How to contribute

### Add a mapping pipeline
Drop a new `yar2sig/mappings/<name>.yaml` defining `logsource`,
`fallback_field`, and `mappings` per IOC type. It is auto-discovered — no
code change needed. Add a test asserting it loads.

### Improve IOC classification
Edit `yar2sig/ioc.py`. Add a case to `tests/test_convert.py::test_classify`
covering the new pattern.

### Add a backend
Add an entry to `BACKENDS` in `yar2sig/backends.py` and, if `sigma-cli`
supports it, set its target. Otherwise provide a fallback query format.

## Guidelines

- **Add a test** for every behavior change. Keep `pytest -q` green.
- Keep functions small and focused; the modules are intentionally decoupled.
- Follow the existing style (type hints, docstrings).
- Conventional commit messages are appreciated (`feat:`, `fix:`, `docs:`…).

## Pull requests

1. Fork and branch from `main`.
2. Make your change + tests.
3. Ensure `pytest -q` passes and `docker build .` succeeds.
4. Open a PR describing the change. CI runs tests, a CLI smoke test, and a
   Docker build/healthcheck automatically.

## Reporting issues

Include: the YARA rule (or a minimal repro), the pipeline/backend selected,
what you expected, and what you got. Sanitize any sensitive indicators.
