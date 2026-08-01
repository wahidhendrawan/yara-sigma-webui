"""Sigma-to-YARA reverse converter (best-effort).

This module provides a production-quality, best-effort conversion from Sigma
rules to YARA rules. Since YARA and Sigma have fundamentally different
semantics (YARA matches byte patterns in files/memory; Sigma matches log
fields), this converter extracts string patterns from Sigma detection
selections and emits approximate YARA rules with explicit warnings.

Public API:
    convert_sigma_to_yara(sigma_rule, **opts) -> (yara_text, report)
    convert_sigma_file(path, **opts)          -> list[(yara_text, report)]
    convert_sigma_text(yaml_text, **opts)     -> list[(yara_text, report)]
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator, Union

import yaml

__all__ = [
    "convert_sigma_to_yara",
    "convert_sigma_file",
    "convert_sigma_text",
    "SigmaConversionError",
]

# ---------------------------------------------------------------------------
# Constants and limits
# ---------------------------------------------------------------------------

MAX_PATTERNS = 500
MAX_PATTERN_LENGTH = 10_000
MAX_RULE_NAME_LENGTH = 128
RESERVED_YARA_KEYWORDS = frozenset({
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition",
    "contains", "endswith", "entrypoint", "false", "filesize", "for",
    "fullword", "global", "import", "icontains", "iendswith", "iequals",
    "in", "include", "int16", "int16be", "int32", "int32be", "int8", "int8be",
    "istartswith", "matches", "meta", "nocase", "none", "not", "of", "or",
    "private", "rule", "startswith", "strings", "them", "true", "uint16",
    "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide", "xor",
    "defined",
})


class SigmaConversionError(Exception):
    """Raised when Sigma rule cannot be converted."""


# ---------------------------------------------------------------------------
# Identifier and string sanitization
# ---------------------------------------------------------------------------

def _sanitize_yara_identifier(name: str, max_length: int = MAX_RULE_NAME_LENGTH) -> str:
    """Convert a string to a valid YARA identifier.
    
    YARA identifiers must:
    - Start with a letter or underscore
    - Contain only letters, digits, underscores
    - Not be a reserved keyword
    """
    if not name:
        return "_unnamed"
    
    # Replace invalid characters with underscore
    s = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
    
    # Collapse multiple underscores
    s = re.sub(r'_+', '_', s)
    
    # Ensure starts with letter or underscore
    if s and s[0].isdigit():
        s = '_' + s
    
    # Truncate if too long
    if len(s) > max_length:
        s = s[:max_length]
    
    # Handle reserved keywords
    if s.lower() in RESERVED_YARA_KEYWORDS:
        s = s + '_rule'
    
    return s if s else '_unnamed'


def _escape_yara_string(text: str) -> str:
    """Escape a string for use in a YARA text pattern."""
    result = []
    for ch in text:
        if ch == '\\':
            result.append('\\\\')
        elif ch == '"':
            result.append('\\"')
        elif ch == '\n':
            result.append('\\n')
        elif ch == '\r':
            result.append('\\r')
        elif ch == '\t':
            result.append('\\t')
        elif ord(ch) < 32 or ord(ch) > 126:
            # Non-printable: use hex escape
            result.append(f'\\x{ord(ch):02x}')
        else:
            result.append(ch)
    return ''.join(result)


def _sigma_regex_to_yara_regex(pattern: str) -> tuple[str, list[str]]:
    """Convert Sigma regex pattern to YARA regex.
    
    Returns (converted_pattern, warnings).
    Sigma uses RE2-style regex; YARA uses a limited subset.
    """
    warnings = []
    
    # YARA regex is delimited by /.../ so we need to escape internal /
    converted = pattern.replace('/', '\\/')
    
    # Sigma wildcards in regex context
    if '*' in pattern and '.*' not in pattern:
        warnings.append(f"Wildcard '*' in pattern may need review: {pattern[:50]}")
    
    # Lookahead/lookbehind not supported in YARA
    if re.search(r'\(\?[=!<]', pattern):
        warnings.append(f"Lookahead/lookbehind not supported in YARA regex: {pattern[:50]}")
    
    return converted, warnings


def _sigma_wildcard_to_yara(value: str) -> tuple[str, str, list[str]]:
    """Convert Sigma wildcard pattern to YARA pattern.
    
    Returns (pattern, pattern_type, warnings).
    pattern_type is 'text' or 'regex'.
    
    Sigma wildcards:
    - * matches any characters
    - ? matches single character
    """
    warnings = []
    
    has_wildcard = '*' in value or '?' in value
    
    if not has_wildcard:
        return value, 'text', warnings
    
    # Convert to regex
    regex_parts = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == '*':
            regex_parts.append('.*')
        elif ch == '?':
            regex_parts.append('.')
        elif ch in r'\.[]{}()+^$|':
            regex_parts.append('\\' + ch)
        else:
            regex_parts.append(ch)
        i += 1
    
    warnings.append(f"Wildcard pattern converted to regex: {value[:50]}")
    return ''.join(regex_parts), 'regex', warnings


# ---------------------------------------------------------------------------
# Detection extraction
# ---------------------------------------------------------------------------

def _extract_values_from_selection(
    selection: Any,
    field_path: str = "",
) -> Iterator[tuple[str, str, Any]]:
    """Recursively extract string values from a Sigma selection.
    
    Yields (field_name, modifier, value) tuples.
    """
    if selection is None:
        return
    
    if isinstance(selection, str):
        yield (field_path, "", selection)
        return
    
    if isinstance(selection, (int, float, bool)):
        yield (field_path, "", str(selection))
        return
    
    if isinstance(selection, list):
        for item in selection:
            yield from _extract_values_from_selection(item, field_path)
        return
    
    if isinstance(selection, dict):
        for key, value in selection.items():
            # Parse field|modifier syntax
            if '|' in key:
                parts = key.split('|')
                field = parts[0]
                modifier = '|'.join(parts[1:])
            else:
                field = key
                modifier = ""
            
            child_path = f"{field_path}.{field}" if field_path else field
            
            if isinstance(value, list):
                for item in value:
                    yield (child_path, modifier, item)
            elif isinstance(value, dict):
                # Nested structure - recurse
                yield from _extract_values_from_selection(value, child_path)
            else:
                yield (child_path, modifier, value)
        return


def _parse_sigma_condition(condition: str) -> tuple[str, list[str]]:
    """Parse Sigma condition to determine YARA condition type.
    
    Returns (yara_condition_type, warnings).
    yara_condition_type is 'all', 'any', or a specific expression.
    """
    warnings = []
    condition_lower = condition.lower().strip()
    
    # Simple cases
    if not condition:
        return 'any', ["No condition specified, defaulting to 'any of them'"]
    
    # Check for "all of" patterns
    if re.search(r'\ball\s+of\s+(them|\w+\*?)\b', condition_lower):
        return 'all', []
    
    # Check for "any of" or "1 of" patterns
    if re.search(r'\b(any|1)\s+of\s+(them|\w+\*?)\b', condition_lower):
        return 'any', []
    
    # Check for N of patterns
    n_of_match = re.search(r'\b(\d+)\s+of\s+(them|\w+\*?)\b', condition_lower)
    if n_of_match:
        n = int(n_of_match.group(1))
        warnings.append(f"'{n} of' condition approximated; YARA will use '{n} of them'")
        return f'{n}_of', warnings
    
    # "selection" or single identifier typically means all
    if re.fullmatch(r'\w+', condition_lower):
        return 'all', []
    
    # Complex boolean logic
    if ' and ' in condition_lower and ' or ' not in condition_lower:
        return 'all', []
    
    if ' or ' in condition_lower and ' and ' not in condition_lower:
        return 'any', []
    
    # Mixed logic - can't represent exactly
    if ' and ' in condition_lower and ' or ' in condition_lower:
        warnings.append(
            f"Complex condition '{condition}' cannot be exactly represented; "
            "using 'any of them' as safe approximation"
        )
        return 'any', warnings
    
    # "not" conditions
    if condition_lower.startswith('not ') or ' not ' in condition_lower:
        warnings.append(
            f"Negation in condition '{condition}' not supported; "
            "emitting positive match only"
        )
        return 'any', warnings
    
    # Filter expressions
    if '|' in condition:
        warnings.append(
            f"Filter expression in condition '{condition}' not supported; "
            "using 'any of them'"
        )
        return 'any', warnings
    
    return 'any', [f"Condition '{condition}' not fully parsed; defaulting to 'any of them'"]


# ---------------------------------------------------------------------------
# Main conversion
# ---------------------------------------------------------------------------

def convert_sigma_to_yara(
    sigma_rule: dict[str, Any],
    *,
    max_patterns: int = MAX_PATTERNS,
    max_pattern_length: int = MAX_PATTERN_LENGTH,
    include_comments: bool = True,
) -> tuple[str, list[str]]:
    """Convert a parsed Sigma rule dictionary to a YARA rule string.
    
    Args:
        sigma_rule: Parsed Sigma rule as a dictionary.
        max_patterns: Maximum number of string patterns to emit.
        max_pattern_length: Maximum length of a single pattern.
        include_comments: Include warning comments in the YARA rule.
    
    Returns:
        Tuple of (yara_rule_text, report_messages).
    
    Raises:
        SigmaConversionError: If the rule cannot be converted.
    """
    if not isinstance(sigma_rule, dict):
        raise SigmaConversionError("Sigma rule must be a dictionary")
    
    report: list[str] = []
    
    # --- Rule name ---
    title = sigma_rule.get('title', '')
    rule_id = sigma_rule.get('id', '')
    if not title and not rule_id:
        title = 'UnnamedSigmaRule'
        report.append("WARNING: No title or id in Sigma rule")
    
    rule_name = _sanitize_yara_identifier(title or f"sigma_{rule_id[:8]}")
    
    # --- Metadata ---
    meta_items: list[tuple[str, str]] = []
    
    if sigma_rule.get('description'):
        desc = str(sigma_rule['description'])[:500]
        meta_items.append(('description', desc))
    
    if sigma_rule.get('author'):
        meta_items.append(('author', str(sigma_rule['author'])[:100]))
    
    if sigma_rule.get('date'):
        meta_items.append(('date', str(sigma_rule['date'])))
    
    if sigma_rule.get('id'):
        meta_items.append(('sigma_id', str(sigma_rule['id'])))
    
    if sigma_rule.get('status'):
        meta_items.append(('sigma_status', str(sigma_rule['status'])))
    
    if sigma_rule.get('level'):
        meta_items.append(('sigma_level', str(sigma_rule['level'])))
    
    refs = sigma_rule.get('references', [])
    if isinstance(refs, list):
        for i, ref in enumerate(refs[:5]):  # Limit references
            meta_items.append((f'reference{i}', str(ref)[:200]))
    
    # Add conversion notice
    meta_items.append(('converted_by', 'yar2sig (Sigma to YARA reverse converter)'))
    meta_items.append(('conversion_note', 'Best-effort conversion - review before use'))
    
    # --- Extract patterns from detection ---
    detection = sigma_rule.get('detection', {})
    if not isinstance(detection, dict):
        raise SigmaConversionError("Detection block must be a dictionary")
    
    condition_text = detection.get('condition', '')
    if isinstance(condition_text, list):
        condition_text = ' or '.join(str(c) for c in condition_text)
        report.append("WARNING: Multiple conditions joined with 'or'")
    
    # Get condition semantics
    cond_type, cond_warnings = _parse_sigma_condition(str(condition_text))
    report.extend(cond_warnings)
    
    # Extract all selections (skip 'condition' and 'timeframe')
    strings_data: list[dict[str, Any]] = []
    selection_names = [k for k in detection.keys() if k not in ('condition', 'timeframe')]
    
    if not selection_names:
        report.append("WARNING: No detection selections found")
    
    for sel_name in selection_names:
        selection = detection[sel_name]
        
        for field_name, modifier, value in _extract_values_from_selection(selection):
            if value is None:
                continue
            
            value_str = str(value)
            
            # Skip empty values
            if not value_str.strip():
                continue
            
            # Enforce length limit
            if len(value_str) > max_pattern_length:
                report.append(
                    f"WARNING: Pattern from '{sel_name}.{field_name}' truncated "
                    f"(was {len(value_str)} chars)"
                )
                value_str = value_str[:max_pattern_length]
            
            # Determine pattern type based on modifier
            pattern_type = 'text'
            modifiers_list: list[str] = []
            pattern_warnings: list[str] = []
            
            if 're' in modifier.split('|'):
                # Regex pattern
                converted, regex_warnings = _sigma_regex_to_yara_regex(value_str)
                pattern_warnings.extend(regex_warnings)
                value_str = converted
                pattern_type = 'regex'
            elif any(m in modifier.split('|') for m in ('contains', 'startswith', 'endswith')):
                # Check for wildcards
                value_str, pattern_type, wc_warnings = _sigma_wildcard_to_yara(value_str)
                pattern_warnings.extend(wc_warnings)
            else:
                # Plain text - still check for wildcards
                value_str, pattern_type, wc_warnings = _sigma_wildcard_to_yara(value_str)
                pattern_warnings.extend(wc_warnings)
            
            # Case insensitivity
            if 'i' in modifier or modifier.startswith('i') or 'nocase' in modifier:
                modifiers_list.append('nocase')
            
            # Encoding hints
            if 'wide' in modifier:
                modifiers_list.append('wide')
            if 'base64' in modifier:
                modifiers_list.append('base64')
                report.append(f"WARNING: base64 modifier on '{field_name}' may need review")
            
            # Default to wide ascii for broader matching
            if 'wide' not in modifiers_list and pattern_type == 'text':
                modifiers_list.extend(['wide', 'ascii'])
            
            report.extend(pattern_warnings)
            
            strings_data.append({
                'selection': sel_name,
                'field': field_name,
                'value': value_str,
                'type': pattern_type,
                'modifiers': modifiers_list,
            })
            
            # Check pattern limit
            if len(strings_data) >= max_patterns:
                report.append(f"WARNING: Pattern limit ({max_patterns}) reached, truncating")
                break
        
        if len(strings_data) >= max_patterns:
            break
    
    # --- Build YARA strings section ---
    yara_strings: list[str] = []
    string_counter: dict[str, int] = {}
    
    for data in strings_data:
        # Generate unique identifier
        base_id = _sanitize_yara_identifier(data['selection'], max_length=20)
        count = string_counter.get(base_id, 0)
        string_counter[base_id] = count + 1
        string_id = f"${base_id}_{count}"
        
        value = data['value']
        mods = ' '.join(data['modifiers'])
        
        if data['type'] == 'regex':
            # Regex pattern
            pattern_str = f"{string_id} = /{value}/"
            if mods:
                pattern_str += f" {mods}"
        else:
            # Text pattern
            escaped = _escape_yara_string(value)
            pattern_str = f"{string_id} = \"{escaped}\""
            if mods:
                pattern_str += f" {mods}"
        
        yara_strings.append(pattern_str)
    
    # --- Build condition ---
    if not yara_strings:
        report.append("WARNING: No string patterns extracted - rule will not compile")
        yara_strings.append('// No patterns extracted from Sigma detection')
        yara_condition = 'false // No patterns - manual review required'
    elif cond_type == 'all':
        yara_condition = 'all of them'
    elif cond_type == 'any':
        yara_condition = 'any of them'
    elif cond_type.endswith('_of'):
        n = cond_type.split('_')[0]
        yara_condition = f'{n} of them'
    else:
        yara_condition = 'any of them'
    
    # --- Assemble YARA rule ---
    lines: list[str] = []
    
    # Header comment
    if include_comments and report:
        lines.append('/*')
        lines.append(' * Sigma-to-YARA Conversion Report:')
        for msg in report:
            lines.append(f' *   {msg}')
        lines.append(' */')
        lines.append('')
    
    # Rule declaration
    lines.append(f'rule {rule_name}')
    lines.append('{')
    
    # Meta section
    lines.append('    meta:')
    for key, value in meta_items:
        escaped_value = _escape_yara_string(str(value))
        lines.append(f'        {key} = "{escaped_value}"')
    
    # Strings section
    lines.append('')
    lines.append('    strings:')
    for s in yara_strings:
        lines.append(f'        {s}')
    
    # Condition section
    lines.append('')
    lines.append('    condition:')
    lines.append(f'        {yara_condition}')
    
    lines.append('}')
    
    yara_text = '\n'.join(lines)
    return yara_text, report


def convert_sigma_text(
    yaml_text: str,
    **kwargs: Any,
) -> list[tuple[str, list[str]]]:
    """Convert YAML text containing one or more Sigma rules to YARA.
    
    Supports multiple YAML documents separated by '---'.
    
    Returns:
        List of (yara_rule_text, report) tuples.
    """
    results: list[tuple[str, list[str]]] = []
    
    # Parse all YAML documents
    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as e:
        raise SigmaConversionError(f"Invalid YAML: {e}") from e
    
    for i, doc in enumerate(documents):
        if doc is None:
            continue
        
        if not isinstance(doc, dict):
            results.append(('', [f"WARNING: Document {i+1} is not a dictionary, skipped"]))
            continue
        
        try:
            yara_text, report = convert_sigma_to_yara(doc, **kwargs)
            results.append((yara_text, report))
        except SigmaConversionError as e:
            results.append(('', [f"ERROR: Document {i+1}: {e}"]))
    
    return results


def convert_sigma_file(
    path: Union[str, Path],
    **kwargs: Any,
) -> list[tuple[str, list[str]]]:
    """Convert a Sigma YAML file to YARA rules.
    
    Returns:
        List of (yara_rule_text, report) tuples.
    """
    path = Path(path)
    if not path.exists():
        raise SigmaConversionError(f"File not found: {path}")
    
    try:
        text = path.read_text(encoding='utf-8')
    except IOError as e:
        raise SigmaConversionError(f"Cannot read file: {e}") from e
    
    return convert_sigma_text(text, **kwargs)
