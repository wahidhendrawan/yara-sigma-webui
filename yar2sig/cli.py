"""Command-line interface for yar2sig.

Examples:
    python -m yar2sig convert rule.yar -p sysmon -o out/
    python -m yar2sig convert rules/ -p winsec -o out/
    python -m yar2sig pipelines
    python -m yar2sig query rule.yar -b splunk
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

import yaml

from . import (
    BACKENDS,
    available_pipelines,
    convert_all,
    generate_query,
    load_mapping,
)
from .emitter import emit_sigma
from .parser import parse_yara_rule
from .progress import ProgressReporter
from .sig2yar import SigmaConversionError, convert_sigma_file


def _json_envelope(pipeline: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the stable machine-readable CLI conversion envelope."""
    return {
        "schema_version": "1.0",
        "pipeline": pipeline,
        "results": results,
    }


def _convert(args: argparse.Namespace) -> int:
    inp = Path(args.input)
    files = list(inp.rglob("*.yar")) + list(inp.rglob("*.yara")) if inp.is_dir() else [inp]
    if not files:
        print(f"No YARA files found at {inp}", file=sys.stderr)
        return 1

    outdir = Path(args.output) if args.output else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    # Progress is sent to stderr and only enabled for directory output. This
    # keeps stdout clean for YAML/JSON pipelines and avoids mixing a progress
    # bar with streamed rule content.
    show_progress = not args.no_progress and outdir is not None and len(files) > 1
    json_results: list[dict[str, Any]] = []

    with ProgressReporter(total=len(files), enabled=show_progress) as progress:
        for f in files:
            results = convert_all(f.read_text(encoding="utf-8"), args.pipeline)
            for i, (rule, report) in enumerate(results):
                result = {
                    "source": str(f),
                    "rule": rule,
                    "report": report,
                }
                if args.format == "json":
                    text = json.dumps(
                        _json_envelope(args.pipeline, [result]),
                        indent=2,
                        ensure_ascii=False,
                    ) + "\n"
                    extension = "json"
                else:
                    text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
                    extension = "yml"

                if outdir:
                    suffix = f"_{i + 1}" if len(results) > 1 else ""
                    dest = outdir / f"{f.stem}{suffix}.{extension}"
                    dest.write_text(text, encoding="utf-8")
                    if not show_progress:
                        print(f"[+] {f.name} [{rule['title']}] -> {dest}")
                elif args.format == "json":
                    json_results.append(result)
                else:
                    if i:
                        print("---")
                    print(text)

                if args.verbose:
                    for line in report:
                        print(f"    # {line}", file=sys.stderr)

            progress.update(label=f.name)

    if args.format == "json" and not outdir:
        print(json.dumps(_json_envelope(args.pipeline, json_results), indent=2, ensure_ascii=False))
    return 0


def _pipelines(_: argparse.Namespace) -> int:
    for p in available_pipelines():
        m = load_mapping(p)
        ls = m.get("logsource", {})
        print(f"{p:12} {ls.get('product', '?')}/{ls.get('service', ls.get('category', '?'))}")
    return 0


def _query(args: argparse.Namespace) -> int:
    parsed = parse_yara_rule(Path(args.input).read_text(encoding="utf-8"))
    rule, _ = emit_sigma(parsed, load_mapping(args.pipeline))
    print(generate_query(args.backend, rule, parsed.get("strings", [])))
    return 0


def _reverse_envelope(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the stable machine-readable Sigma-to-YARA envelope."""
    return {"schema_version": "1.0", "direction": "sigma-to-yara", "results": results}


def _reverse(args: argparse.Namespace) -> int:
    """Convert Sigma YAML documents into best-effort YARA rules."""
    inp = Path(args.input)
    if inp.is_dir():
        files = sorted({*inp.rglob("*.yml"), *inp.rglob("*.yaml")})
    else:
        files = [inp]
    if not files:
        print(f"No Sigma YAML files found at {inp}", file=sys.stderr)
        return 1

    outdir = Path(args.output) if args.output else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    show_progress = not args.no_progress and outdir is not None and len(files) > 1
    json_results: list[dict[str, Any]] = []
    had_error = False

    with ProgressReporter(total=len(files), enabled=show_progress) as progress:
        for source in files:
            try:
                results = convert_sigma_file(
                    source,
                    include_comments=not args.no_comments,
                )
            except SigmaConversionError as exc:
                had_error = True
                print(f"[!] {source}: {exc}", file=sys.stderr)
                progress.update(label=source.name)
                continue
            except OSError as exc:
                had_error = True
                print(f"[!] {source}: cannot read file ({exc})", file=sys.stderr)
                progress.update(label=source.name)
                continue

            for index, (yara_text, report) in enumerate(results):
                record = {
                    "source": str(source),
                    "yara": yara_text,
                    "report": report,
                }
                if args.format == "json":
                    text = (
                        json.dumps(
                            _reverse_envelope([record]),
                            indent=2,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                    extension = "json"
                else:
                    text = yara_text
                    extension = "yar"

                if outdir:
                    suffix = f"_{index + 1}" if len(results) > 1 else ""
                    dest = outdir / f"{source.stem}{suffix}.{extension}"
                    dest.write_text(text, encoding="utf-8")
                    if not show_progress:
                        print(f"[+] {source.name} -> {dest}")
                elif args.format == "json":
                    json_results.append(record)
                else:
                    if index:
                        print("---")
                    print(text)

                if args.verbose:
                    for line in report:
                        print(f"    # {line}", file=sys.stderr)

            progress.update(label=source.name)

    if args.format == "json" and not outdir:
        print(json.dumps(_reverse_envelope(json_results), indent=2, ensure_ascii=False))
    return 1 if had_error else 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="yar2sig",
        description="YARA <-> Sigma converter (Sigma-to-YARA is best-effort)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="Convert YARA file/dir to Sigma")
    c.add_argument("input", help="YARA file (.yar) or directory for bulk import")
    c.add_argument("-p", "--pipeline", default="sysmon")
    c.add_argument("-o", "--output", help="Output directory (required for bulk import)")
    c.add_argument(
        "--format",
        choices=("yaml", "json"),
        default="yaml",
        help="Output format (default: yaml)",
    )
    c.add_argument("--dir", action="store_true", help="Force directory/bulk mode")
    c.add_argument("-v", "--verbose", action="store_true")
    c.add_argument("--no-progress", action="store_true", help="Disable progress bar for batch runs")
    c.set_defaults(func=_convert)

    pp = sub.add_parser("pipelines", help="List available mapping pipelines")
    pp.set_defaults(func=_pipelines)

    q = sub.add_parser("query", help="Generate a native SIEM query")
    q.add_argument("input")
    q.add_argument("-p", "--pipeline", default="sysmon")
    q.add_argument("-b", "--backend", default="splunk", choices=list(BACKENDS))
    q.set_defaults(func=_query)

    r = sub.add_parser("reverse", help="Convert Sigma YAML file/dir to YARA (best-effort)")
    r.add_argument("input", help="Sigma YAML file or directory")
    r.add_argument("-o", "--output", help="Output directory (writes to stdout if omitted)")
    r.add_argument(
        "--format",
        choices=("yar", "json"),
        default="yar",
        help="Output format (default: yar)",
    )
    r.add_argument("-v", "--verbose", action="store_true", help="Print conversion report to stderr")
    r.add_argument("--no-progress", action="store_true", help="Disable progress bar for batch runs")
    r.add_argument("--no-comments", action="store_true", help="Omit conversion warnings from YARA output")
    r.set_defaults(func=_reverse)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
