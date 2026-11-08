# Contributing to yar2sig

Thanks for your interest in improving the YARA → Sigma converter!

## Development setup

```bash
git clone https://github.com/wahidhendrawan/yara-sigma-webui.git
cd yara-sigma-webui
cargo test                    # run the test suite (needs Rust 1.85+)
cargo run -- serve            # dev server on http://127.0.0.1:8000
```

Or with Docker:

```bash
docker compose up -d --build   # http://127.0.0.1:8000
```

## Project layout

```
src/
├─ parser.rs    # YARA parsing (text/hex/regex, multi-rule, tags, meta)
├─ ioc.rs       # IOC classification heuristics
├─ emitter.rs   # Sigma emission + MITRE tagging + confidence scoring
├─ backends.rs  # native query generation (sigma-cli + fallback)
├─ sig2yar.rs   # best-effort Sigma -> YARA reverse conversion
├─ cli.rs       # command-line interface (clap)
├─ web.rs       # axum web UI + /api/convert + /healthz, security headers
└─ lib.rs       # crate API; pipelines embedded by build.rs
mappings/       # one YAML pipeline per log source
static/         # YARA Sigma Studio UI (embedded into the binary)
tests/          # CLI and HTTP API integration tests (unit tests live next to the code)
```

## Before contributing

- Search existing issues and pull requests before opening a new one.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Do not include secrets, private YARA rules, or other sensitive indicators in issues, tests, or pull requests.

## How to contribute

### Add a mapping pipeline
Drop a new `mappings/<name>.yaml` defining `logsource`, `fallback_field`, and
`mappings` per IOC type. `build.rs` embeds it on the next build — no code
change needed. Add it to the pipeline test in `src/lib.rs`.

### Improve IOC classification
Edit `src/ioc.rs`. Add a case to its `classify` test covering the new pattern.

### Add a backend
Add an entry to `BACKENDS` in `src/backends.rs` and, if `sigma-cli` supports
it, set its target. Otherwise provide a fallback query format. Update
`tests/web.rs` so `/api/convert` validates the backend and returns a query for
the new target.

### Update the web UI
Keep the browser workflow focused on YARA-to-Sigma conversion: `.yar` import,
mapping pipeline selection, optional SIEM/EDR query backend selection, and the
Sigma / Query / Report result tabs. Avoid adding unrelated SIEM ingestion or
rule-management scope unless it is backed by tests and documentation.

## Guidelines

- **Add a test** for every behavior change. Keep `cargo test` green.
- Keep functions small and focused; the modules are intentionally decoupled.
- Follow the existing style (`cargo fmt`, `cargo clippy --all-targets -- -D warnings` clean).
- Conventional commit messages are appreciated (`feat:`, `fix:`, `docs:`…).

## Pull requests

1. Fork and branch from `main`.
2. Make your change + tests.
3. Ensure `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and `docker build .` succeed.
4. Update `README.md` or `CHANGELOG.md` when user-facing behavior changes.
5. Open a PR describing the problem, solution, testing, and any security or compatibility impact. CI runs fmt, clippy, the tests, a CLI smoke test, and a Docker build/healthcheck automatically.

Keep commits focused. Pull requests should be reviewable and should not mix unrelated formatting or generated files into a functional change.

## Reporting issues

Include: the YARA rule (or a minimal repro), the pipeline/backend selected,
what you expected, and what you got. Sanitize any sensitive indicators.
