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

MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
COMPLEX_CONDITION_RE = re.compile(r"\b\d+\s+of\b|\$[A-Za-z0-9_]*\*|for\s+any|for\s+all", re.I)
REVIEW_MODIFIERS = {"wide", "xor", "base64", "base64wide", "fullword"}


def _default_fields(mapping: dict, ioc_type: str) -> list[str]:
    logsource = mapping.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    service = logsource.get("service", "")

    if ioc_type == "user_agent":
        if category == "proxy":
            return ["c-useragent", "UserAgent"]
        return ["CommandLine"]
    if ioc_type == "named_pipe":
        if product == "windows" and service == "sysmon":
            return ["PipeName", "CommandLine"]
        return [mapping.get("fallback_field", "message")]
    return [mapping.get("fallback_field", "message")]


def _select_fields(mapping: dict, ioc_type: str) -> tuple[list[str], str]:
    specs = mapping.get("mappings", {})
    spec = specs.get(ioc_type)
    if isinstance(spec, dict) and spec.get("fields"):
        return list(spec["fields"]), spec.get("op", "contains")
    return _default_fields(mapping, ioc_type), "contains"


def _mitre_tags(meta: dict) -> list[str]:
    tags: list[str] = []
    blob = " ".join(str(v) for v in meta.values())
    for technique in MITRE_RE.findall(blob):
        tag = f"attack.{technique.lower()}"
        if tag not in tags:
            tags.append(tag)
    return tags


def _selection_key(field: str, op: str, ptype: str, modifiers: list[str]) -> str:
    if ptype == "regex":
        return f"{field}|re"
    if op == "contains":
        return f"{field}|contains"
    if op == "startswith":
        return f"{field}|startswith"
    if op == "endswith":
        return f"{field}|endswith"
    return field


def _quality(patterns: list[str], ptypes: list[str], warnings: list[str], condition_raw: str) -> dict[str, Any]:
    score = 100
    if not patterns:
        score -= 70
    score -= min(40, sum(15 for ptype in ptypes if ptype in {"hex", "regex"}))
    score -= min(25, len(warnings) * 5)
    if COMPLEX_CONDITION_RE.search(condition_raw):
        score -= 20
    score = max(0, min(100, score))

    if score >= 80:
        label = "high"
    elif score >= 55:
        label = "medium"
    else:
        label = "low"

    return {
        "score": score,
        "label": label,
        "warnings": warnings,
        "review_required": score < 80 or bool(warnings),
    }


def _add_warning(warnings: list[str], report: list[str], message: str) -> None:
    if message not in warnings:
        warnings.append(message)
    report.append(message)


def emit_sigma(parsed: dict[str, Any], mapping: dict) -> tuple[dict[str, Any], list[str]]:
    """Return (sigma_rule_dict, report)."""
    meta = parsed.get("meta", {})
    patterns = parsed.get("strings", [])
    ptypes = parsed.get("string_types", ["text"] * len(patterns))
    modifiers = parsed.get("string_modifiers", [[] for _ in patterns])
    cond_type = parsed.get("cond_type", "any")
    condition_raw = parsed.get("condition_raw", "")
    report: list[str] = []
    warnings: list[str] = []

    detection: dict[str, Any] = {}
    condition_groups: list[str] = []

    for idx, pattern in enumerate(patterns):
        ptype = ptypes[idx] if idx < len(ptypes) else "text"
        mods = modifiers[idx] if idx < len(modifiers) else []
        if ptype == "hex":
            ioc_type = "hash"
            _add_warning(
                warnings,
                report,
                f"Hex pattern #{idx + 1} needs manual review; Sigma cannot match raw bytes directly.",
            )
        elif ptype == "regex":
            ioc_type = "generic"
            _add_warning(
                warnings,
                report,
                f"Regex pattern '{pattern}' mapped with |re modifier; backend support may vary.",
            )
        else:
            ioc_type = classify_pattern(pattern)

        review_mods = sorted(set(mods).intersection(REVIEW_MODIFIERS))
        if review_mods:
            _add_warning(
                warnings,
                report,
                f"Modifiers {', '.join(review_mods)} on pattern '{pattern}' require analyst validation.",
            )

        fields, op = _select_fields(mapping, ioc_type)
        group_names: list[str] = []
        for field_idx, field in enumerate(fields, start=1):
            sel_name = f"sel{idx + 1}_{field_idx}" if len(fields) > 1 else f"sel{idx + 1}"
            detection[sel_name] = {_selection_key(field, op, ptype, mods): pattern}
            group_names.append(sel_name)
        condition_groups.append(f"({' or '.join(group_names)})" if len(group_names) > 1 else group_names[0])
        report.append(f"Pattern '{pattern}' -> {ioc_type} -> fields {fields} (op: {op}).")

    if condition_groups:
        joiner = " and " if cond_type == "all" else " or "
        detection["condition"] = joiner.join(condition_groups)
    else:
        _add_warning(warnings, report, "No usable patterns extracted; review the source rule.")
        detection["condition"] = "selection"

    if COMPLEX_CONDITION_RE.search(condition_raw):
        _add_warning(warnings, report, f"Complex YARA condition preserved only approximately: {condition_raw}")

    quality = _quality(patterns, ptypes, warnings, condition_raw)
    report.append(f"Conversion confidence: {quality['label']} ({quality['score']}/100).")

    tags = _mitre_tags(meta) + [f"yara.{tag}" for tag in parsed.get("tags", [])]

    rule: dict[str, Any] = {
        "title": meta.get("title") or meta.get("description") or parsed.get("name", "ConvertedRule"),
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": meta.get("description") or f"Converted from YARA rule {parsed.get('name', '')}",
        "author": meta.get("author", "yar2sig"),
        "date": meta.get("date", datetime.date.today().strftime("%Y/%m/%d")),
        "references": [meta[key] for key in ("reference", "ref", "url") if meta.get(key)],
        "tags": tags,
        "logsource": mapping.get("logsource", {"category": "process_creation", "product": "windows"}),
        "detection": detection,
        "falsepositives": ["Unknown - review generated rule before deployment."],
        "level": meta.get("level", "medium"),
        "x_yar2sig": {
            "source_rule": parsed.get("name", "ConvertedRule"),
            "confidence": quality["label"],
            "confidence_score": quality["score"],
            "review_required": quality["review_required"],
            "warnings": quality["warnings"],
        },
    }
    return rule, report
