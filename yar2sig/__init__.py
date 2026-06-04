"""yar2sig — YARA → Sigma conversion library.

Public API:
    parse_yara_rule(text)        -> parsed dict
    classify_pattern(pattern)    -> IOC type
    emit_sigma(parsed, mapping)  -> (sigma_rule, report)
    available_pipelines()        -> [names]
    load_mapping(name)           -> mapping dict
    convert(text, pipeline)      -> (sigma_rule, report)  [convenience]
    generate_query(backend, rule, patterns) -> native query
    BACKENDS                     -> dict of supported backends
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .backends import BACKENDS, generate_query
from .emitter import emit_sigma
from .ioc import classify_pattern
from .parser import parse_yara_rule, split_rules

__version__ = "3.0.0"

_PIPELINE_DIR = Path(__file__).resolve().parent / "mappings"


def available_pipelines() -> list[str]:
    return sorted(p.stem for p in _PIPELINE_DIR.glob("*.yaml"))


def load_mapping(name: str) -> dict[str, Any]:
    path = _PIPELINE_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Pipeline '{name}' not found. Available: {available_pipelines()}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def convert(text: str, pipeline: str = "sysmon") -> tuple[dict[str, Any], list[str]]:
    """Convenience: parse YARA text and emit a Sigma rule via *pipeline*."""
    parsed = parse_yara_rule(text)
    mapping = load_mapping(pipeline)
    return emit_sigma(parsed, mapping)


__all__ = [
    "parse_yara_rule", "split_rules", "classify_pattern", "emit_sigma",
    "available_pipelines", "load_mapping", "convert",
    "generate_query", "BACKENDS", "__version__",
]
