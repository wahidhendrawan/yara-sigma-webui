"""Sigma rule emitter for yar2sig.

Takes a parsed YARA rule plus a mapping pipeline and produces a Sigma
rule dict (ready for YAML) and a human-readable conversion report.
"""

from __future__ import annotations

import datetime
import re
import uuid
from typing import Any

from .ioc import classify_pattern

# MITRE technique IDs sometimes embedded in YARA meta
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _select_field(mapping: dict, ioc_type: str) -> tuple[str, str]:
    m = mapping.get("mappings", {})
    spec = m.get(ioc_type)
    if isinstance(spec, dict) and spec.get("fields"):
        return spec["fields"][0], spec.get("op", "contains")
    return mapping.get("fallback_field", "message"), "contains"


def _mitre_tags(meta: dict) -> list[str]:
    tags: list[str] = []
    blob = " ".join(str(v) for v in meta.values())
    for t in MITRE_RE.findall(blob):
        tag = f"attack.{t.lower()}"
        if tag not in tags:
            tags.append(tag)
    return tags


def emit_sigma(parsed: dict[str, Any], mapping: dict) -> tuple[dict[str, Any], list[str]]:
    """Return (sigma_rule_dict, report)."""
    meta = parsed.get("meta", {})
    patterns = parsed.get("strings", [])
    ptypes = parsed.get("string_types", ["text"] * len(patterns))
    cond_type = parsed.get("cond_type", "any")
    report: list[str] = []

    detection: dict[str, Any] = {}
    sel_names: list[str] = []

    for idx, pattern in enumerate(patterns):
        ptype = ptypes[idx] if idx < len(ptypes) else "text"
        if ptype == "hex":
            ioc_type = "hash"
            report.append(f"Hex pattern #{idx + 1} treated as a binary/hash indicator (review manually).")
        elif ptype == "regex":
            ioc_type = "generic"
            report.append(f"Regex pattern '{pattern}' mapped with |re modifier.")
        else:
            ioc_type = classify_pattern(pattern)

        field, op = _select_field(mapping, ioc_type)
        sel = f"sel{idx + 1}"
        if ptype == "regex":
            key = f"{field}|re"
        elif op == "contains":
            key = f"{field}|contains"
        else:
            key = field
        detection[sel] = {key: pattern}
        sel_names.append(sel)
        report.append(f"Pattern '{pattern}' -> {ioc_type} -> field '{field}' (op: {op}).")

    if sel_names:
        joiner = " and " if cond_type == "all" else " or "
        detection["condition"] = joiner.join(sel_names)
    else:
        detection["condition"] = "selection"
        report.append("No usable patterns extracted; review the source rule.")

    tags = _mitre_tags(meta) + [f"yara.{t}" for t in parsed.get("tags", [])]

    rule: dict[str, Any] = {
        "title": meta.get("title") or parsed.get("name", "ConvertedRule"),
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": meta.get("description") or f"Converted from YARA rule {parsed.get('name', '')}",
        "author": meta.get("author", "yar2sig"),
        "date": meta.get("date", datetime.date.today().strftime("%Y/%m/%d")),
        "references": [meta[k] for k in ("reference", "ref", "url") if meta.get(k)],
        "tags": tags,
        "logsource": mapping.get("logsource", {"category": "process_creation", "product": "windows"}),
        "detection": detection,
        "falsepositives": ["Unknown - review generated rule before deployment."],
        "level": meta.get("level", "medium"),
    }
    return rule, report
