"""YARA rule parser for yar2sig.

Extracts enough structure from YARA rules to generate useful Sigma rules:
rule name, tags, meta fields, string declarations with modifiers, and a
best-effort condition expression. Supports multiple rules per file.
"""

from __future__ import annotations

import re
from typing import Any

_RULE_RE = re.compile(r"(?ms)^\s*(?:private\s+|global\s+)*rule\s+[^\{]+\{")
_NAME_RE = re.compile(r"(?ms)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)\s*(?::\s*([^\{]+))?\{")
_STRING_DECL_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]+)\s*=\s*(.+?)\s*$")
_HEX_RE = re.compile(r"^\{([0-9a-fA-F\s\?\[\]\-()|]+)\}\s*(.*)$")
_REGEX_RE = re.compile(r"^/(.+)/([a-z]*)\s*(.*)$")
_TEXT_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*(.*)$')


def _strip_comments(text: str) -> str:
    """Strip comments while preserving comment-like text inside strings."""
    out: list[str] = []
    i = 0
    in_quote = False
    escaped = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            i += 1
            continue

        if ch == '"':
            in_quote = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        if ch == "/" and nxt == "/":
            end = text.find("\n", i + 2)
            if end == -1:
                break
            out.append("\n")
            i = end + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, brace_start: int) -> int | None:
    depth = 0
    in_quote = False
    escaped = False
    in_regex = False
    i = brace_start
    while i < len(text):
        ch = text[i]
        prev = text[i - 1] if i else ""
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            i += 1
            continue
        if in_regex:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "/":
                in_regex = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
        elif ch == "/" and prev in "= \t":
            in_regex = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def split_rules(text: str) -> list[str]:
    """Split a multi-rule YARA file into individual rule blocks."""
    text = _strip_comments(text)
    blocks: list[str] = []
    for match in _RULE_RE.finditer(text):
        brace_start = text.index("{", match.end() - 1)
        end = _find_matching_brace(text, brace_start)
        if end is not None:
            blocks.append(text[match.start() : end + 1])
    return blocks or ([text] if text.strip() else [])


def _section(text: str, name: str, stop_names: tuple[str, ...]) -> str:
    if not stop_names:
        match = re.search(rf"\b{name}\s*:\s*(.*?)(?=\}}\s*$)", text, flags=re.S | re.I)
        return match.group(1) if match else ""
    stops = "|".join(re.escape(s) for s in stop_names)
    match = re.search(rf"\b{name}\s*:\s*(.*?)(?=\b(?:{stops})\s*:|\}}\s*$)", text, flags=re.S | re.I)
    return match.group(1) if match else ""


def _decode_text(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = re.sub(r"\\x([0-9a-fA-F]{2})", repl, value)
    replacements = {
        r"\\": "\\",
        r"\"": '"',
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    return value


def _parse_modifiers(text: str) -> list[str]:
    return [m.lower() for m in re.findall(r"\b(?:ascii|wide|nocase|fullword|xor|base64|base64wide|private)\b", text, flags=re.I)]


def _parse_meta(meta_text: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in meta_text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        raw = raw.strip()
        if raw.lower() in {"true", "false"}:
            value: Any = raw.lower() == "true"
        elif re.fullmatch(r"-?\d+", raw):
            value = int(raw)
        else:
            value = raw.strip("\"'")
        meta[key.strip()] = value
    return meta


def _parse_strings(strings_text: str) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for line in strings_text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _STRING_DECL_RE.match(line)
        if not match:
            continue
        ident, raw_value = match.groups()
        kind = "text"
        value = ""
        modifiers: list[str] = []

        text_match = _TEXT_RE.match(raw_value)
        regex_match = _REGEX_RE.match(raw_value)
        hex_match = _HEX_RE.match(raw_value)
        if text_match:
            value = _decode_text(text_match.group(1))
            modifiers = _parse_modifiers(text_match.group(2))
        elif regex_match:
            kind = "regex"
            value = regex_match.group(1)
            modifiers = sorted(set(_parse_modifiers(regex_match.group(2) + " " + regex_match.group(3))))
        elif hex_match:
            kind = "hex"
            value = re.sub(r"\s+", " ", hex_match.group(1).strip())
            modifiers = _parse_modifiers(hex_match.group(2))
        else:
            continue

        declarations.append({"id": ident, "value": value, "type": kind, "modifiers": modifiers})
    return declarations


def parse_yara_rule(text: str) -> dict[str, Any]:
    """Parse the first YARA rule found in *text*."""
    text = _strip_comments(text)
    blocks = split_rules(text)
    if blocks:
        text = blocks[0]

    name_match = _NAME_RE.search(text)
    name = name_match.group(1) if name_match else "ConvertedRule"
    tags = name_match.group(2).split() if (name_match and name_match.group(2)) else []

    meta = _parse_meta(_section(text, "meta", ("strings", "condition")))
    string_entries = _parse_strings(_section(text, "strings", ("condition",)))

    condition_text = _section(text, "condition", ()).strip()
    if not condition_text:
        cond_section = re.search(r"condition\s*:\s*(.*?)(?:\}\s*$|$)", text, flags=re.S | re.I)
        condition_text = cond_section.group(1).strip() if cond_section else ""
    cond_type = "all" if re.search(r"\ball\s+of\b", condition_text, flags=re.I) else "any"

    return {
        "name": name,
        "meta": meta,
        "strings": [s["value"] for s in string_entries],
        "string_types": [s["type"] for s in string_entries],
        "string_ids": [s["id"] for s in string_entries],
        "string_modifiers": [s["modifiers"] for s in string_entries],
        "string_entries": string_entries,
        "cond_type": cond_type,
        "tags": tags,
        "condition_raw": condition_text,
    }
