"""IOC classification heuristics for yar2sig.

Classifies a plain-text pattern extracted from a YARA rule into an
indicator type used by the mapping engine to pick Sigma fields.
"""

from __future__ import annotations

import re

HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
REG_RE = re.compile(r"^(?:HKLM|HKCU|HKCR|HKU|HKEY_)", re.I)
URL_RE = re.compile(r"^[a-z]+://", re.I)

FILE_EXTS = {
    "exe", "dll", "sys", "ocx", "scr", "bat", "cmd", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "jar", "pdb", "tmp", "dat",
    "bin", "lnk", "hta", "wsf", "msi", "dmp", "so", "elf", "sh", "py",
}

MUTEX_HINTS = ("global\\", "local\\", "mutex", "\\sessions\\")


def classify_pattern(pattern: str) -> str:
    """Return one of: url, ip, hash, email, domain, registry, mutex,
    path_or_filename, generic."""
    s = pattern.strip()
    if not s:
        return "generic"

    if URL_RE.match(s):
        return "url"
    if REG_RE.match(s) or "\\software\\" in s.lower() or "\\system\\currentcontrolset" in s.lower():
        return "registry"
    if IPV4_RE.match(s) or IPV6_RE.match(s):
        return "ip"
    if HASH_RE.match(s):
        return "hash"
    if EMAIL_RE.match(s):
        return "email"

    low = s.lower()
    if any(h in low for h in MUTEX_HINTS):
        return "mutex"

    # Path / filename
    if "/" in s or "\\" in s:
        return "path_or_filename"
    ext = re.search(r"\.([A-Za-z0-9]{1,5})$", s)
    if ext and ext.group(1).lower() in FILE_EXTS:
        return "path_or_filename"

    if DOMAIN_RE.match(s) and " " not in s:
        return "domain"

    return "generic"
