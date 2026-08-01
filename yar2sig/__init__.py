"""yar2sig — YARA <-> Sigma conversion library.

Public API:
    parse_yara_rule(text)        -> parsed dict
    classify_pattern(pattern)    -> IOC type
    emit_sigma(parsed, mapping)  -> (sigma_rule, report)
    available_pipelines()        -> [names]
    load_mapping(name)           -> mapping dict
    convert(text, pipeline)      -> (sigma_rule, report)  [convenience]
    generate_query(backend, rule, patterns) -> native query
    BACKENDS                     -> dict of supported backends

    convert_sigma_to_yara(sigma_rule) -> (yara_text, report)  [reverse: Sigma -> YARA]
    convert_sigma_text(yaml_text)     -> [(yara_text, report), ...]
    convert_sigma_file(path)          -> [(yara_text, report), ...]
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .backends import BACKENDS, generate_query
from .emitter import emit_sigma
from .ioc import classify_pattern
from .parser import parse_yara_rule, split_rules
from .sig2yar import (
    SigmaConversionError,
    convert_sigma_file,
    convert_sigma_text,
    convert_sigma_to_yara,
)

__version__ = "3.1.0"

_PIPELINE_DIR = Path(__file__).resolve().parent / "mappings"


def available_pipelines() -> list[str]:
    return sorted(p.stem for p in _PIPELINE_DIR.glob("*.yaml"))


def load_mapping(name: str) -> dict[str, Any]:
    if not isinstance(name, str):
        raise ValueError("Pipeline name must be a string")
    pipelines = {path.stem: path for path in _PIPELINE_DIR.glob("*.yaml")}
    path = pipelines.get(name)
    if path is None:
        raise FileNotFoundError(f"Pipeline not found. Available: {available_pipelines()}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def convert(text: str, pipeline: str = "sysmon") -> tuple[dict[str, Any], list[str]]:
    """Convenience: parse YARA text and emit a Sigma rule via *pipeline*.

    Converts only the FIRST rule in *text*. Use :func:`convert_all` for
    files containing multiple YARA rules.
    """
    parsed = parse_yara_rule(text)
    mapping = load_mapping(pipeline)
    return emit_sigma(parsed, mapping)


def convert_all(text: str, pipeline: str = "sysmon") -> list[tuple[dict[str, Any], list[str]]]:
    """Convert EVERY YARA rule found in *text* into a Sigma rule.

    Returns a list of ``(sigma_rule, report)`` tuples — one per YARA rule.
    """
    mapping = load_mapping(pipeline)
    results: list[tuple[dict[str, Any], list[str]]] = []
    for block in split_rules(text):
        parsed = parse_yara_rule(block)
        results.append(emit_sigma(parsed, mapping))
    return results


__all__ = [
    "parse_yara_rule", "split_rules", "classify_pattern", "emit_sigma",
    "available_pipelines", "load_mapping", "convert", "convert_all",
    "generate_query", "BACKENDS", "__version__",
    "convert_sigma_to_yara", "convert_sigma_text", "convert_sigma_file",
    "SigmaConversionError",
]
