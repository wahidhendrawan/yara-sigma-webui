"""YARA rule parser for yar2sig.

Lightweight parser that extracts enough structure from YARA rules to
generate meaningful Sigma rules: rule name, meta fields, string patterns
(text, hex, regex), and a simplified condition (all/any). Supports
multiple rules per file.
"""

from __future__ import annotations

import re
from typing import Any


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Strip // line comments but NOT scheme separators like http://
    text = re.sub(r"(?<!:)//.*", "", text)
    return text


def split_rules(text: str) -> list[str]:
    """Split a multi-rule YARA file into individual rule blocks."""
    text = _strip_comments(text)
    blocks: list[str] = []
    for m in re.finditer(r"(?ms)^\s*(?:private\s+|global\s+)*rule\s+[^\{]+\{", text):
        start = m.start()
        # Balance braces from the first '{'
        brace_start = text.index("{", m.end() - 1)
        depth = 0
        i = brace_start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : i + 1])
                    break
            i += 1
    return blocks or ([text] if text.strip() else [])


def parse_yara_rule(text: str) -> dict[str, Any]:
    """Parse the first YARA rule found in *text*.

    Returns dict with: name, meta (dict), strings (list of patterns),
    string_types (parallel list: text/hex/regex), cond_type (all/any),
    tags (list from `rule name : tag1 tag2`).
    """
    text = _strip_comments(text)
    # Scope to the first rule block so condition/strings don't bleed across rules
    blocks = split_rules(text)
    if blocks:
        text = blocks[0]

    name_match = re.search(r"(?ms)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)\s*(?::\s*([^\{]+))?\{", text)
    name = name_match.group(1) if name_match else "ConvertedRule"
    tags = name_match.group(2).split() if (name_match and name_match.group(2)) else []

    meta: dict[str, str] = {}
    meta_section = re.search(r"meta\s*:\s*(.*?)\s*(strings|condition)\s*:", text, flags=re.S | re.I)
    if meta_section:
        for line in meta_section.group(1).splitlines():
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                meta[key.strip()] = val.strip().strip("\"'")

    strings: list[str] = []
    string_types: list[str] = []
    strings_section = re.search(r"strings\s*:\s*(.*?)\s*condition\s*:", text, flags=re.S | re.I)
    if strings_section:
        for line in strings_section.group(1).splitlines():
            line = line.strip()
            if "=" not in line or line.startswith("//"):
                continue
            _, val = line.split("=", 1)
            val = val.strip()
            # Text string: "..."
            m = re.search(r'"((?:[^"\\]|\\.)*)"', val)
            if m:
                strings.append(m.group(1))
                string_types.append("text")
                continue
            # Regex string: /.../
            m = re.match(r"/(.+)/[a-z]*\s*$", val)
            if m:
                strings.append(m.group(1))
                string_types.append("regex")
                continue
            # Hex string: { ... }
            m = re.match(r"\{([0-9a-fA-F\s\?\[\]\-()|]+)\}", val)
            if m:
                strings.append(re.sub(r"\s+", " ", m.group(1).strip()))
                string_types.append("hex")

    condition_text = ""
    cond_section = re.search(r"condition\s*:\s*(.*?)(?:\}\s*$|$)", text, flags=re.S | re.I)
    if cond_section:
        condition_text = cond_section.group(1).strip()

    cond_type = "all" if re.search(r"\ball\s+of\b", condition_text, flags=re.I) else "any"

    return {
        "name": name,
        "meta": meta,
        "strings": strings,
        "string_types": string_types,
        "cond_type": cond_type,
        "tags": tags,
        "condition_raw": condition_text,
    }
