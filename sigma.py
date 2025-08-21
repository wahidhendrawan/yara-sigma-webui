"""Sigma emitter for yar2sig.

This module contains functions that take a parsed YARA rule and a
mapping specification and produce a Sigma rule.  A small
heuristics-based engine classifies each plain text string extracted
from the YARA rule into an indicator type (URL, domain, IP, hash,
path/filename or generic) and then looks up the appropriate Sigma
field and operator from the mapping specification.  Where no mapping
applies, a fallback field is used.

The emitter also returns a conversion report detailing the mapping
decisions.  This report can be surfaced to users of the CLI or web
UI so they understand which parts of the original YARA rule were
applied and where manual follow-up may be required.
"""

from __future__ import annotations

from typing import Dict, Any, Tuple, List
import uuid
import datetime
import re   # tambahan

from ..extractors import classify_pattern

FILE_EXTS = {
    ".pdb", ".exe", ".dll", ".sys", ".ocx", ".scr",
    ".dat", ".bin", ".tmp", ".cmd", ".bat", ".ps1",
    ".vbs", ".js", ".jar", ".com"
}


def looks_like_filename(s: str) -> bool:
    """
    Return True jika string tampak seperti nama file/path.
    Digunakan untuk override classifier yang salah anggap domain.
    """
    if not s:
        return False
    t = s.strip().strip('"').strip("'")
    lo = t.lower()
    # Jangan anggap URL sebagai file
    if lo.startswith(("http://", "https://")):
        return False
    # Mengandung slash/backslash → path
    if "/" in t or "\\" in t:
        return True
    # Berakhir dengan ekstensi file umum
    for ext in FILE_EXTS:
        if lo.endswith(ext):
            return True
    # Pola nama.ext (mis. evict1.pdb)
    if re.match(r"^[A-Za-z0-9_\-\.]+\.[A-Za-z0-9]{2,4}$", t):
        return True
    return False


def _select_field(mapping: dict, indicator_type: str) -> Tuple[str, str]:
    """Select the field and operator for a given indicator type.

    Args:
        mapping: Mapping specification loaded from YAML.
        indicator_type: One of the IOC types returned by
            :func:`classify_pattern`.

    Returns:
        A tuple ``(field, op)`` specifying the Sigma field and operation.
        If the indicator type is not present in the mapping the
        ``fallback_field`` and a default ``contains`` operator are used.
    """
    m = mapping.get('mappings', {})
    if indicator_type in m:
        spec = m[indicator_type]
        # For hash mappings some specs may further separate by algorithm
        if isinstance(spec, dict) and 'fields' not in spec:
            # Choose first algorithm spec by default
            # Flatten nested mapping to use all algorithm fields
            fields: List[str] = []
            for algo, sub in spec.items():
                if isinstance(sub, dict) and 'fields' in sub:
                    fields.extend(sub['fields'])
            op = next(iter(spec.values())).get('op', 'contains')  # type: ignore
            return (fields[0], op) if fields else (mapping.get('fallback_field', 'message'), 'contains')
        # Normal case
        fields = spec.get('fields', []) if isinstance(spec, dict) else []
        op = spec.get('op', 'contains') if isinstance(spec, dict) else 'contains'
        if fields:
            return (fields[0], op)
    # Fallback
    fallback_field = mapping.get('fallback_field', 'message')
    return (fallback_field, 'contains')


def emit_sigma(parsed: Dict[str, Any], mapping: dict) -> Tuple[Dict[str, Any], List[str]]:
    """Generate a Sigma rule and conversion report from a parsed YARA rule.

    Args:
        parsed: The output of :func:`yar2sig.parsers.parse_yara_rule`.
        mapping: Mapping specification loaded via
            :func:`yar2sig.mappings.load_mapping`.

    Returns:
        A tuple ``(sigma_rule, report)`` where ``sigma_rule`` is a
        dictionary representing a valid Sigma rule (ready to be
        serialised to YAML) and ``report`` is a list of human
        readable strings describing the conversion decisions.
    """
    meta = parsed.get('meta', {})
    patterns: List[str] = parsed.get('strings', [])
    cond_type: str = parsed.get('cond_type', 'any')
    report: List[str] = []

    detection: Dict[str, Any] = {}
    selection_names: List[str] = []

    # Build selections for each pattern
    for idx, pattern in enumerate(patterns):
        indicator_type = classify_pattern(pattern)
        # Override jika terlihat seperti file tapi dikira domain/url/generic
        if looks_like_filename(pattern) and indicator_type in ("domain", "url", "generic"):
            indicator_type = "path_or_filename"

        field, op = _select_field(mapping, indicator_type)
        sel_name = f'sel{idx + 1}'
        if op == 'contains':
            key = f'{field}|contains'
        else:
            key = field
        detection[sel_name] = {key: pattern}
        selection_names.append(sel_name)
        # Record in report
        report.append(
            f"Pattern '{pattern}' classified as {indicator_type} mapped to field '{field}' using operator '{op}'"
        )

    # Build condition string
    if selection_names:
        if cond_type == 'all':
            cond = ' and '.join(selection_names)
        else:
            cond = ' or '.join(selection_names)
        detection['condition'] = cond
    else:
        detection['condition'] = 'false'
        report.append('No patterns were extracted; condition set to false')

    # Compose Sigma rule fields
    sigma_rule: Dict[str, Any] = {
        'title': parsed.get('name', 'ConvertedRule'),
        'id': str(uuid.uuid4()),
        'status': 'experimental',
        'description': meta.get('description', f'Converted from YARA rule {parsed.get("name", "")}') or '',
        'author': meta.get('author', 'unknown'),
        'date': meta.get('date', datetime.date.today().strftime('%Y/%m/%d')),
        'references': [],
        'tags': [],
        'logsource': mapping.get('logsource', {'category': 'process_creation', 'product': 'unknown'}),
        'detection': detection,
        'falsepositives': ['unknown'],
        'level': 'medium',
        # Custom extension fields capturing the conversion provenance and loss
        'x-yara-source': {
            'rule': parsed.get('name', 'ConvertedRule'),
        },
        'x-conversion-notes': report,
        'x-conf-loss': 'medium' if patterns else 'high',
    }
    return sigma_rule, report
