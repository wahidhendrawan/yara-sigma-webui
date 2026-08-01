"""Best-effort Sigma-to-YARA conversion.

Sigma describes log events while YARA scans bytes. Conversion therefore cannot
be generally exact. This module converts safe scalar/list detection values,
preserves basic boolean selection semantics where possible, and reports every
approximation that needs analyst review.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Union

import yaml

MAX_PATTERNS = 500
MAX_PATTERN_LENGTH = 10_000
MAX_RULE_NAME_LENGTH = 128

_YARA_RESERVED = frozenset(
    {
        "all", "and", "any", "ascii", "at", "condition", "contains",
        "endswith", "entrypoint", "false", "filesize", "for", "fullword",
        "global", "import", "in", "include", "matches", "meta", "nocase",
        "none", "not", "of", "or", "private", "rule", "startswith",
        "strings", "them", "true", "wide", "xor",
    }
)
_UNREPRESENTABLE_MODIFIERS = {
    "cidr", "exists", "fieldref", "gt", "gte", "lt", "lte",
}
_SCALAR_TYPES = (str, int, float, bool)


class SigmaConversionError(ValueError):
    """Raised when Sigma input is invalid or cannot be safely processed."""


@dataclass(frozen=True)
class _Pattern:
    identifier: str
    value: str
    kind: str
    modifiers: tuple[str, ...]


def _warn(report: list[str], message: str) -> None:
    warning = f"WARNING: {message}"
    if warning not in report:
        report.append(warning)


def _sanitize_identifier(value: Any, max_length: int = MAX_RULE_NAME_LENGTH) -> str:
    text = re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))
    text = re.sub(r"_+", "_", text).strip("_") or "unnamed"
    if text[0].isdigit():
        text = "_" + text
    text = text[:max_length]
    if text.lower() in _YARA_RESERVED:
        text = (text[: max_length - 5] + "_rule") if max_length > 5 else "_rule"
    return text


def _escape_yara_text(value: str) -> str:
    """Escape text as printable ASCII plus UTF-8 byte escapes."""
    output: list[str] = []
    for byte in value.encode("utf-8"):
        if byte == 0x22:
            output.append(r'\"')
        elif byte == 0x5C:
            output.append(r"\\")
        elif byte == 0x09:
            output.append(r"\t")
        elif byte == 0x0A:
            output.append(r"\n")
        elif byte == 0x0D:
            output.append(r"\r")
        elif 0x20 <= byte <= 0x7E:
            output.append(chr(byte))
        else:
            output.append(f"\\x{byte:02x}")
    return "".join(output)


def _escape_comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\r", " ").replace("\n", " ")


def _wildcard_regex(value: str) -> Optional[str]:
    """Return a YARA regex for a Sigma wildcard string, or None if literal."""
    result: list[str] = []
    wildcard = False
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            result.append(re.escape(value[i + 1]))
            i += 2
            continue
        if char == "*":
            result.append(".*")
            wildcard = True
        elif char == "?":
            result.append(".")
            wildcard = True
        else:
            result.append(re.escape(char))
        i += 1
    return "".join(result) if wildcard else None


def _prepare_regex(value: str, report: list[str], source: str) -> Optional[str]:
    unsupported = (
        r"\(\?[=!<]",       # lookaround/lookbehind
        r"\(\?P",           # named groups
        r"\\[1-9]",         # backreferences
        r"\(\?\(",          # conditionals
        r"\*\+|\+\+|\?\+", # possessive quantifiers
    )
    if any(re.search(pattern, value) for pattern in unsupported):
        _warn(report, f"regex from '{source}' uses syntax unsupported by YARA and was skipped")
        return None
    try:
        re.compile(value)
    except re.error as exc:
        _warn(report, f"invalid regex from '{source}' was skipped ({exc})")
        return None

    output: list[str] = []
    escaped = False
    for char in value:
        if char in "\r\n":
            output.append(f"\\x{ord(char):02x}")
            escaped = False
        elif char == "/" and not escaped:
            output.append(r"\/")
            escaped = False
        elif ord(char) > 0x7E:
            output.extend(f"\\x{byte:02x}" for byte in char.encode("utf-8"))
            escaped = False
        else:
            output.append(char)
            if char == "\\":
                escaped = not escaped
            else:
                escaped = False
    return "".join(output)


class _Builder:
    def __init__(self, max_patterns: int, max_pattern_length: int, report: list[str]) -> None:
        self.max_patterns = max_patterns
        self.max_pattern_length = max_pattern_length
        self.report = report
        self.patterns: list[_Pattern] = []
        self._selection_ids: dict[str, str] = {}
        self._used_ids: set[str] = set()
        self.limit_reached = False

    def selection_id(self, name: str) -> str:
        if name in self._selection_ids:
            return self._selection_ids[name]
        base = _sanitize_identifier(name, 32)
        candidate = base
        suffix = 2
        while candidate.lower() in self._used_ids:
            trailer = f"_{suffix}"
            candidate = base[: 32 - len(trailer)] + trailer
            suffix += 1
        self._selection_ids[name] = candidate
        self._used_ids.add(candidate.lower())
        return candidate

    def add(self, selection: str, field: str, modifiers: set[str], value: Any) -> Optional[str]:
        source = f"{selection}.{field}" if field else selection
        if value is None:
            _warn(self.report, f"null value in '{source}' cannot become a YARA pattern and was skipped")
            return None
        if not isinstance(value, _SCALAR_TYPES):
            _warn(self.report, f"non-scalar value in '{source}' was skipped")
            return None
        if self.limit_reached:
            return None
        if len(self.patterns) >= self.max_patterns:
            self.limit_reached = True
            _warn(self.report, f"pattern limit ({self.max_patterns}) reached; remaining values were skipped")
            return None

        text = str(value)
        if not text:
            _warn(self.report, f"empty value in '{source}' was skipped")
            return None
        byte_length = len(text.encode("utf-8"))
        if byte_length > self.max_pattern_length:
            _warn(
                self.report,
                f"pattern from '{source}' exceeds {self.max_pattern_length} UTF-8 bytes and was skipped",
            )
            return None
        if not isinstance(value, str):
            _warn(self.report, f"non-string scalar from '{source}' was converted to text")

        blocked = modifiers.intersection(_UNREPRESENTABLE_MODIFIERS)
        if blocked:
            _warn(
                self.report,
                f"modifier(s) {', '.join(sorted(blocked))} on '{source}' cannot be represented and the value was skipped",
            )
            return None

        unknown = modifiers.difference(
            {
                "all", "ascii", "base64", "base64offset", "base64wide",
                "cased", "contains", "endswith", "expand", "iendswith",
                "re", "startswith", "utf16", "utf16be", "utf16le", "wide",
                "windash",
            }
        )
        if unknown:
            _warn(
                self.report,
                f"modifier(s) {', '.join(sorted(unknown))} on '{source}' were ignored",
            )
        for approximate in modifiers.intersection(
            {"base64", "base64offset", "base64wide", "expand", "utf16be", "windash"}
        ):
            _warn(self.report, f"modifier '{approximate}' on '{source}' is only approximated")

        kind = "text"
        pattern_value = text
        if "re" in modifiers:
            prepared = _prepare_regex(text, self.report, source)
            if prepared is None:
                return None
            pattern_value = prepared
            kind = "regex"
        else:
            wildcard = _wildcard_regex(text)
            if wildcard is not None:
                prepared = _prepare_regex(wildcard, self.report, source)
                if prepared is None:
                    return None
                pattern_value = prepared
                kind = "regex"
                _warn(self.report, f"Sigma wildcards from '{source}' were converted to a YARA regex")

        yara_modifiers: list[str] = []
        if "cased" not in modifiers:
            yara_modifiers.append("nocase")
        if "utf16" in modifiers or "utf16le" in modifiers or "wide" in modifiers:
            yara_modifiers.append("wide")
        elif "utf16be" in modifiers:
            yara_modifiers.append("wide")
        else:
            yara_modifiers.extend(("ascii", "wide"))

        selection_id = self.selection_id(selection)
        identifier = f"$s_{selection_id}_{len(self.patterns) + 1}"
        self.patterns.append(
            _Pattern(identifier, pattern_value, kind, tuple(yara_modifiers))
        )
        return identifier


def _modifier_parts(field: str) -> tuple[str, set[str]]:
    parts = field.split("|")
    return parts[0], {part.lower() for part in parts[1:] if part}


def _join(expressions: Iterable[str], operator: str) -> Optional[str]:
    values = [value for value in expressions if value]
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return "(" + f" {operator} ".join(values) + ")"


def _mapping_expression(
    selection_name: str,
    mapping: dict[Any, Any],
    builder: _Builder,
) -> Optional[str]:
    field_expressions: list[str] = []
    for raw_field, raw_value in mapping.items():
        if not isinstance(raw_field, str):
            _warn(builder.report, f"non-string field key in selection '{selection_name}' was skipped")
            continue
        field, modifiers = _modifier_parts(raw_field)
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        identifiers: list[str] = []
        for value in values:
            if isinstance(value, (dict, list, tuple, set)):
                _warn(
                    builder.report,
                    f"nested value in '{selection_name}.{field}' was skipped instead of being stringified",
                )
                continue
            identifier = builder.add(selection_name, field, modifiers, value)
            if identifier:
                identifiers.append(identifier)
        operator = "and" if "all" in modifiers else "or"
        expression = _join(identifiers, operator)
        if expression:
            field_expressions.append(expression)
    # Fields in a Sigma selection mapping are ANDed.
    return _join(field_expressions, "and")


def _selection_expression(name: str, value: Any, builder: _Builder) -> Optional[str]:
    if isinstance(value, dict):
        return _mapping_expression(name, value, builder)
    if isinstance(value, list):
        alternatives: list[str] = []
        for item in value:
            if isinstance(item, dict):
                expression = _mapping_expression(name, item, builder)
                if expression:
                    alternatives.append(expression)
            elif isinstance(item, list):
                _warn(builder.report, f"nested list in selection '{name}' was skipped")
            else:
                identifier = builder.add(name, "", set(), item)
                if identifier:
                    alternatives.append(identifier)
        return _join(alternatives, "or")
    identifier = builder.add(name, "", set(), value)
    return identifier


def _selection_matches(pattern: str, names: Iterable[str]) -> list[str]:
    regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    return [name for name in names if regex.match(name)]


def _quantified_condition(
    condition: str,
    expressions: dict[str, str],
    report: list[str],
) -> Optional[str]:
    match = re.fullmatch(r"(?i)(all|any|\d+)\s+of\s+(them|[^\s]+)", condition.strip())
    if not match:
        return None
    quantity, target = match.groups()
    names = list(expressions)
    selected = names if target.lower() == "them" else _selection_matches(target, names)
    if not selected:
        _warn(report, f"condition target '{target}' matched no usable selection")
        return "false"
    values = [expressions[name] for name in selected]
    if quantity.lower() == "all":
        return _join(values, "and")
    if quantity.lower() == "any" or quantity == "1":
        return _join(values, "or")
    requested = int(quantity)
    if requested > len(values):
        _warn(
            report,
            f"'{quantity} of {target}' exceeds the number of usable selections and was converted to false",
        )
        return "false"
    if requested == len(values):
        return _join(values, "and")
    _warn(
        report,
        f"'{quantity} of {target}' cannot be exactly applied to compound selections; using any matching selection",
    )
    return _join(values, "or")


def _boolean_condition(
    condition: str,
    expressions: dict[str, str],
    report: list[str],
) -> Optional[str]:
    token_re = re.compile(r"\s*(\(|\)|(?i:and|or|not)(?=\s|\(|\)|$)|[^\s()]+)")
    tokens = token_re.findall(condition)
    if not tokens or "".join(tokens).replace("(", "").replace(")", "") == "":
        return None
    position = 0

    def parse_primary() -> str:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("unexpected end")
        token = tokens[position]
        if token == "(":
            position += 1
            value = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("missing closing parenthesis")
            position += 1
            return value
        if token.lower() == "not":
            raise ValueError("negation is not safely representable")
        position += 1
        if token not in expressions:
            raise ValueError(f"unknown or unusable selection '{token}'")
        return expressions[token]

    def parse_and() -> str:
        nonlocal position
        values = [parse_primary()]
        while position < len(tokens) and tokens[position].lower() == "and":
            position += 1
            values.append(parse_primary())
        return _join(values, "and") or "false"

    def parse_or() -> str:
        nonlocal position
        values = [parse_and()]
        while position < len(tokens) and tokens[position].lower() == "or":
            position += 1
            values.append(parse_and())
        return _join(values, "or") or "false"

    try:
        result = parse_or()
        if position != len(tokens):
            raise ValueError(f"unexpected token '{tokens[position]}'")
        return result
    except ValueError as exc:
        _warn(report, f"condition '{condition}' was not preserved ({exc})")
        return None


def _condition_expression(
    raw_condition: Any,
    expressions: dict[str, str],
    report: list[str],
) -> str:
    if not expressions:
        return "false"
    conditions = raw_condition if isinstance(raw_condition, list) else [raw_condition]
    converted: list[str] = []
    for raw in conditions:
        if not isinstance(raw, str) or not raw.strip():
            _warn(report, "missing or non-string condition; using any usable selection")
            continue
        expression = _quantified_condition(raw, expressions, report)
        if expression is None:
            expression = _boolean_condition(raw, expressions, report)
        if expression is not None:
            converted.append(expression)
    if converted:
        if len(converted) > 1:
            _warn(report, "multiple Sigma conditions were combined with OR")
        return _join(converted, "or") or "false"
    _warn(report, "condition was approximated as any usable selection")
    return _join(expressions.values(), "or") or "false"


def _metadata(rule: dict[str, Any], report: list[str]) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    fields = (
        ("description", "description", 500),
        ("author", "author", 200),
        ("date", "date", 40),
        ("id", "sigma_id", 100),
        ("status", "sigma_status", 40),
        ("level", "sigma_level", 40),
    )
    allowed = _SCALAR_TYPES + (datetime.date, datetime.datetime)
    for source, target, limit in fields:
        value = rule.get(source)
        if value is None:
            continue
        if not isinstance(value, allowed):
            _warn(report, f"non-scalar metadata field '{source}' was omitted")
            continue
        output.append((target, str(value)[:limit]))
    references = rule.get("references", [])
    if references:
        if not isinstance(references, list):
            _warn(report, "non-list 'references' metadata was omitted")
        else:
            for index, reference in enumerate(references[:5], start=1):
                if isinstance(reference, allowed):
                    output.append((f"reference_{index}", str(reference)[:300]))
                else:
                    _warn(report, "non-scalar reference was omitted")
    output.extend(
        (
            ("converted_by", "yar2sig Sigma-to-YARA reverse converter"),
            ("conversion_note", "Best-effort conversion; review before deployment"),
        )
    )
    return output


def convert_sigma_to_yara(
    sigma_rule: dict[str, Any],
    *,
    max_patterns: int = MAX_PATTERNS,
    max_pattern_length: int = MAX_PATTERN_LENGTH,
    include_comments: bool = True,
) -> tuple[str, list[str]]:
    """Convert one parsed Sigma mapping into ``(YARA source, report)``.

    Only scalar values and lists of scalars are converted. Basic Sigma mapping,
    list, ``and``/``or``, and ``any``/``all`` condition semantics are retained
    when their extracted pattern groups permit it.
    """
    if not isinstance(sigma_rule, dict):
        raise SigmaConversionError("Sigma rule must be a mapping")
    if not isinstance(max_patterns, int) or max_patterns < 1:
        raise SigmaConversionError("max_patterns must be a positive integer")
    if not isinstance(max_pattern_length, int) or max_pattern_length < 1:
        raise SigmaConversionError("max_pattern_length must be a positive integer")

    report: list[str] = []
    _warn(
        report,
        "Sigma event-field semantics cannot be equivalent to YARA byte matching; analyst review is required",
    )
    title = sigma_rule.get("title")
    if not isinstance(title, _SCALAR_TYPES) or not str(title).strip():
        title = sigma_rule.get("id")
    if not isinstance(title, _SCALAR_TYPES) or not str(title).strip():
        title = "UnnamedSigmaRule"
        _warn(report, "rule has no scalar title or id; a fallback identifier was used")
    rule_name = _sanitize_identifier(title)

    detection = sigma_rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaConversionError("Sigma rule 'detection' must be a mapping")

    builder = _Builder(max_patterns, max_pattern_length, report)
    expressions: dict[str, str] = {}
    for raw_name, selection in detection.items():
        if raw_name in {"condition", "timeframe"}:
            continue
        if not isinstance(raw_name, str):
            _warn(report, "non-string detection selection name was skipped")
            continue
        expression = _selection_expression(raw_name, selection, builder)
        if expression:
            expressions[raw_name] = expression
        else:
            _warn(report, f"selection '{raw_name}' produced no usable patterns")

    condition = _condition_expression(detection.get("condition"), expressions, report)
    metadata = _metadata(sigma_rule, report)

    lines: list[str] = []
    if include_comments:
        lines.extend(("/*", " * Sigma-to-YARA conversion report:"))
        lines.extend(f" * {_escape_comment(message)}" for message in report)
        lines.extend((" */", ""))
    lines.extend((f"rule {rule_name}", "{", "    meta:"))
    for key, value in metadata:
        lines.append(f'        {key} = "{_escape_yara_text(value)}"')
    if builder.patterns:
        lines.extend(("", "    strings:"))
        for pattern in builder.patterns:
            modifiers = " ".join(pattern.modifiers)
            if pattern.kind == "regex":
                declaration = f"{pattern.identifier} = /{pattern.value}/ {modifiers}"
            else:
                declaration = (
                    f'{pattern.identifier} = "{_escape_yara_text(pattern.value)}" {modifiers}'
                )
            lines.append("        " + declaration.rstrip())
    lines.extend(("", "    condition:", f"        {condition}", "}"))
    return "\n".join(lines) + "\n", report


def convert_sigma_text(yaml_text: str, **kwargs: Any) -> list[tuple[str, list[str]]]:
    """Convert all Sigma mappings in a YAML stream.

    Documents must each be a mapping. Empty documents are ignored. Invalid
    YAML or non-mapping documents raise :class:`SigmaConversionError`.
    """
    if not isinstance(yaml_text, str):
        raise SigmaConversionError("Sigma YAML input must be text")
    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        raise SigmaConversionError(f"Invalid Sigma YAML: {exc}") from exc
    results: list[tuple[str, list[str]]] = []
    for index, document in enumerate(documents, start=1):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise SigmaConversionError(f"Sigma YAML document {index} must be a mapping")
        results.append(convert_sigma_to_yara(document, **kwargs))
    if not results:
        raise SigmaConversionError("Sigma YAML contains no rule documents")
    return results


def convert_sigma_file(
    path: Union[str, Path],
    **kwargs: Any,
) -> list[tuple[str, list[str]]]:
    """Read and convert all Sigma documents in *path*."""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SigmaConversionError(f"Unable to read Sigma file '{source}': {exc}") from exc
    return convert_sigma_text(text, **kwargs)


__all__ = [
    "MAX_PATTERNS",
    "MAX_PATTERN_LENGTH",
    "SigmaConversionError",
    "convert_sigma_file",
    "convert_sigma_text",
    "convert_sigma_to_yara",
]
