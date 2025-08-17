"""Command‑line interface for yar2sig.

This module provides a simple CLI for converting one or more YARA
rules into Sigma rules.  It accepts a file or directory as input
and writes the converted Sigma YAML to an output directory.  Users
can specify the mapping pipeline to use via a command line flag.  A
summary report of the conversion is printed to stdout.

Example:

.. code-block:: console

    python -m yar2sig --input rules.yar --pipeline sysmon --output converted/

The resulting Sigma file will be written to ``converted/rules.yml``.
"""

from __future__ import annotations

import argparse
import sys
import os
from pathlib import Path
import yaml

from .parsers import parse_yara_rule
from .emitters import emit_sigma
from . import load_mapping, available_pipelines


def convert_file(path: Path, pipeline: str, outdir: Path) -> None:
    """Convert a single YARA file to Sigma and write it to disk.

    Args:
        path: Path to the input YARA file.
        pipeline: Name of the mapping pipeline to use.
        outdir: Destination directory for the Sigma file.
    """
    text = path.read_text(encoding='utf‑8')
    parsed = parse_yara_rule(text)
    mapping = load_mapping(pipeline)
    sigma_rule, report = emit_sigma(parsed, mapping)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / (path.stem + '.yml')
    out_path.write_text(yaml.dump(sigma_rule, sort_keys=False, allow_unicode=True), encoding='utf‑8')
    print(f'Converted {path} -> {out_path}')
    for line in report:
        print(f'  - {line}')


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description='Convert YARA rules to Sigma using yar2sig.')
    parser.add_argument('-i', '--input', required=True, help='Path to a YARA file or directory containing YARA files')
    parser.add_argument('-p', '--pipeline', default='sysmon', help='Mapping pipeline to use (default: sysmon). Available: ' + ', '.join(available_pipelines()))
    parser.add_argument('-o', '--output', default='converted', help='Directory to write converted Sigma files')
    args = parser.parse_args(argv)

    in_path = Path(args.input)
    outdir = Path(args.output)
    if not in_path.exists():
        print(f'Input path {in_path} does not exist', file=sys.stderr)
        sys.exit(1)
    pipeline = args.pipeline
    try:
        load_mapping(pipeline)
    except FileNotFoundError:
        print(f'Pipeline {pipeline} not found. Available: {", ".join(available_pipelines())}', file=sys.stderr)
        sys.exit(1)

    if in_path.is_file():
        convert_file(in_path, pipeline, outdir)
    elif in_path.is_dir():
        any_converted = False
        for file in in_path.iterdir():
            if file.suffix.lower() in {'.yar', '.yara'}:
                convert_file(file, pipeline, outdir)
                any_converted = True
        if not any_converted:
            print(f'No .yar or .yara files found in {in_path}', file=sys.stderr)
            sys.exit(1)
    else:
        print(f'Input path {in_path} must be a file or directory', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()