"""Indicator extraction and classification utilities.

This module contains lightweight functions for classifying a plain text
pattern as a particular type of indicator of compromise (IOC).  The
resulting type is used by the mapping engine to determine which
fields in a Sigma rule should be populated when converting from
YARA.  Because YARA strings are often ambiguous the heuristics are
necessarily approximate.  Users are encouraged to review the
generated Sigma rules and adjust the patterns or mapping
configuration as needed.
"""

from __future__ import annotations

import re

HASH_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')
IP_V4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
IP_V6_RE = re.compile(r'^[0-9a-fA-F:]{3,39}$')
DOMAIN_RE = re.compile(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
COMMON_FILE_EXTENSIONS = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'scr', 'jar', 'zip', 'rar'
    # Note: we deliberately exclude 'com' here to avoid misclassifying
    # domain names ending in .com as file names.  True 16‑bit COM
    # executables are rare and can still be detected by the presence
    # of path separators.
}


def classify_pattern(pattern: str) -> str:
    """Classify a single plain text pattern into an IOC type.

    The classification is based on very simple heuristics:

    * If the pattern contains ``://`` it is treated as a URL.
    * If the pattern resembles an IPv4 or IPv6 address it is treated as
      ``ip``.
    * If the pattern is a hex string of length 32–64 characters it is
      treated as a ``hash``.
    * If the pattern contains ``@`` it is treated as an email address
      and mapped as a domain.
    * If the pattern contains path separators (``/`` or ``\\``) or ends
      with a file extension it is considered a file path or name.
    * If the pattern contains a dot and no whitespace it is classified
      as a domain name.
    * Otherwise it is considered a generic string.

    Args:
        pattern: The plain text string extracted from a YARA rule.

    Returns:
        A string representing the IOC type.  One of ``"url"``,
        ``"ip"``, ``"hash"``, ``"domain"``, ``"path_or_filename"`` or
        ``"generic_string"``.
    """
    s = pattern.strip()
    # URL detection
    if '://' in s:
        return 'url'
    # IP address
    if IP_V4_RE.match(s) or IP_V6_RE.match(s):
        return 'ip'
    # Hash detection
    if HASH_RE.match(s):
        return 'hash'
    # Email addresses map to domain
    if '@' in s and DOMAIN_RE.match(s.split('@')[-1]):
        return 'domain'
    # File path or name
    if '/' in s or '\\' in s:
        return 'path_or_filename'
    ext_match = re.search(r'\.([A-Za-z0-9]{2,5})$', s)
    if ext_match:
        ext = ext_match.group(1).lower()
        if ext in COMMON_FILE_EXTENSIONS:
            return 'path_or_filename'
    # Domain detection (ensure no whitespace and at least one dot)
    if DOMAIN_RE.match(s) and ' ' not in s:
        return 'domain'
    # Fallback
    return 'generic_string'