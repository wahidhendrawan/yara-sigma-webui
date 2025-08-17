"""Simple YARA parser used by yar2sig.

This module provides a lightweight parser for YARA rules.  The aim of
this parser is not to fully understand the YARA language but rather
to extract enough information to generate meaningful Sigma rules.  In
particular it extracts the rule name, meta fields, a list of plain
text string patterns from the ``strings`` section and a simplified
condition (either ``"all"`` or ``"any"``).  Complex features such
as hex strings, regular expressions, private strings, comments,
imports and include statements are deliberately ignored.

If you need full YARA support you can substitute this parser with
``plyara`` or another full‑featured parser.  The rest of the
yar2sig library consumes only the returned dictionary so replacing
this function will not affect other modules.
"""

from __future__ import annotations

import re
import datetime
from typing import Dict, List, Any

def parse_yara_rule(text: str) -> Dict[str, Any]:
    """Parse a YARA rule and return a structured representation.

    The parser handles only a single rule at a time.  If multiple
    rules are present in the same file the first one is returned.  The
    following properties are extracted:

    * ``name`` – the identifier following the ``rule`` keyword.  If
      missing the name ``ConvertedRule`` is used.
    * ``meta`` – a mapping of key/value pairs from the ``meta``
      section.  Values are stripped of surrounding quotes.
    * ``strings`` – a list of plain text patterns extracted from
      quoted strings in the ``strings`` section.  Hexadecimal and
      regular expression patterns are ignored.
    * ``cond_type`` – either ``"all"`` if the condition contains
      ``all of`` or ``"any"`` otherwise.  When nothing can be
      determined the default is ``"any"``.

    Args:
        text: Raw YARA rule text.

    Returns:
        A dictionary containing the parsed components.
    """
    # Remove C‑style and C++ style comments.
    def remove_comments(s: str) -> str:
        # Remove block comments
        s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
        # Remove line comments
        s = re.sub(r'//.*', '', s)
        return s

    text_no_comments = remove_comments(text)

    # Extract the rule name
    name_match = re.search(r'(?m)^\s*rule\s+([^{\s]+)', text_no_comments)
    name = name_match.group(1) if name_match else 'ConvertedRule'

    # Extract meta section
    meta: Dict[str, str] = {}
    meta_section = re.search(
        r'meta\s*:\s*(.*?)\s*(strings|condition)\s*:',
        text_no_comments,
        flags=re.S | re.I,
    )
    if meta_section:
        meta_body = meta_section.group(1)
        for line in meta_body.splitlines():
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                # Trim whitespace and surrounding quotes
                val = val.strip().strip('"\'')
                meta[key] = val

    # Extract strings section
    strings: List[str] = []
    strings_section = re.search(
        r'strings\s*:\s*(.*?)\s*condition\s*:',
        text_no_comments,
        flags=re.S | re.I,
    )
    if strings_section:
        str_body = strings_section.group(1)
        for line in str_body.splitlines():
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            if '=' in line:
                _key, val = line.split('=', 1)
                val = val.strip()
                # Consider only quoted plain‑text strings
                str_match = re.search(r'"([^"\\]*(?:\\.[^"\\]*)*)"', val)
                if str_match:
                    pattern = str_match.group(1)
                    strings.append(pattern)

    # Extract condition text
    condition_text = ''
    condition_section = re.search(
        r'condition\s*:\s*(.*?)(?:rule\s+\w+|$)',
        text_no_comments,
        flags=re.S | re.I,
    )
    if condition_section:
        condition_text = condition_section.group(1).strip()

    # Determine whether all patterns must match or any pattern may match
    cond_type = 'any'
    if re.search(r'\ball\s+of\b', condition_text, flags=re.I):
        cond_type = 'all'
    elif re.search(r'\bany\s+of\b', condition_text, flags=re.I):
        cond_type = 'any'

    return {
        'name': name,
        'meta': meta,
        'strings': strings,
        'cond_type': cond_type,
    }