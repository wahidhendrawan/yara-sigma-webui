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
app.py          # Flask web UI (+ /api/convert, /healthz, backend validation)
templates/      # YARA Sigma Studio UI
tests/          # pytest suite
```

## Before contributing

- Search existing issues and pull requests before opening a new one.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Do not include secrets, private YARA rules, or other sensitive indicators in issues, tests, or pull requests.

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
Update `tests/test_convert.py` so `/api/convert` validates the backend and
returns a query for the new target.

### Update the web UI
Keep the browser workflow focused on YARA-to-Sigma conversion: `.yar` import,
mapping pipeline selection, optional SIEM/EDR query backend selection, and the
Sigma / Query / Report result tabs. Avoid adding unrelated SIEM ingestion or
rule-management scope unless it is backed by tests and documentation.

## Guidelines

- **Add a test** for every behavior change. Keep `pytest -q` green.
- Keep functions small and focused; the modules are intentionally decoupled.
- Follow the existing style (type hints, docstrings).
- Conventional commit messages are appreciated (`feat:`, `fix:`, `docs:`…).

## Pull requests

1. Fork and branch from `main`.
2. Make your change + tests.
3. Ensure `pytest -q --cov=yar2sig` passes and `docker build .` succeeds.
4. Update `README.md` or `CHANGELOG.md` when user-facing behavior changes.
5. Open a PR describing the problem, solution, testing, and any security or compatibility impact. CI runs tests, coverage, a CLI smoke test, and a Docker build/healthcheck automatically.

Keep commits focused. Pull requests should be reviewable and should not mix unrelated formatting or generated files into a functional change.

## Reporting issues

Include: the YARA rule (or a minimal repro), the pipeline/backend selected,
what you expected, and what you got. Sanitize any sensitive indicators.
