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
NAMED_PIPE_RE = re.compile(r"^\\\\(?:\.\\)?pipe\\", re.I)

FILE_EXTS = {
    "bat", "bin", "cmd", "dat", "dll", "dmp", "elf", "exe", "hta", "jar",
    "js", "jse", "lnk", "msi", "ocx", "pdb", "ps1", "psm1", "py", "scr",
    "sh", "so", "sys", "tmp", "vbe", "vbs", "wsf",
}

MUTEX_HINTS = ("global\\", "local\\", "mutex", "\\sessions\\")
USER_AGENT_HINTS = (
    "mozilla/",
    "chrome/",
    "firefox/",
    "safari/",
    "trident/",
    "edge/",
    "edg/",
    "opera/",
    "curl/",
    "wget/",
)


def classify_pattern(pattern: str) -> str:
    """Return a normalized IOC type for mapping selection."""
    value = pattern.strip()
    if not value:
        return "generic"

    low = value.lower()
    if URL_RE.match(value):
        return "url"
    if REG_RE.match(value) or "\\software\\" in low or "\\system\\currentcontrolset" in low:
        return "registry"
    if NAMED_PIPE_RE.match(value):
        return "named_pipe"
    if IPV4_RE.match(value) or IPV6_RE.match(value):
        return "ip"
    if HASH_RE.match(value):
        return "hash"
    if EMAIL_RE.match(value):
        return "email"
    if any(hint in low for hint in MUTEX_HINTS):
        return "mutex"
    if any(hint in low for hint in USER_AGENT_HINTS):
        return "user_agent"

    if "/" in value or "\\" in value:
        return "path_or_filename"

    ext = re.search(r"\.([A-Za-z0-9]{1,5})$", value)
    if ext and ext.group(1).lower() in FILE_EXTS:
        return "path_or_filename"

    if DOMAIN_RE.match(value) and " " not in value:
        return "domain"

    return "generic"
