"""Multi-backend query generation for yar2sig.

Attempts to use sigma-cli for native conversion; falls back to simple
wildcard search expressions per backend when sigma-cli is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

BACKENDS: dict[str, tuple[str, str, str | None]] = {
    "elasticsearch": ("Elastic (Lucene/KQL)", "message", "lucene"),
    "splunk": ("Splunk SPL", "_raw", "splunk"),
    "kusto": ("Microsoft Sentinel / Defender (KQL)", "ProcessCommandLine", "kusto"),
    "qradar": ("IBM QRadar AQL", "payload", "qradar"),
    "carbonblack": ("VMware Carbon Black", "process_cmdline", None),
    "sentinelone": ("SentinelOne Deep Visibility", "SrcProcCmdLine", None),
    "crowdstrike": ("CrowdStrike Falcon", "CommandLine", None),
}

LUCENE_SPECIAL_RE = re.compile(r"([+\-&|!(){}\[\]^\"~*?:\\/])")


def _sigma_cli_available() -> bool:
    return shutil.which("sigma") is not None


def _clean_patterns(patterns: list[str]) -> list[str]:
    return [str(pattern) for pattern in patterns if str(pattern).strip()]


def _escape_quoted(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_lucene(value: str) -> str:
    return LUCENE_SPECIAL_RE.sub(r"\\\1", value)


def _escape_kusto(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_qradar_like(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("'", "''")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _fallback_query(backend_id: str, patterns: list[str]) -> str:
    field = BACKENDS[backend_id][1]
    values = _clean_patterns(patterns)
    if not values:
        return f"{field}:*"

    if backend_id == "splunk":
        return " OR ".join(f'{field}="*{_escape_quoted(value)}*"' for value in values)

    if backend_id == "kusto":
        conds = " or ".join(f'{field} contains "{_escape_kusto(value)}"' for value in values)
        return f"DeviceProcessEvents | where {conds}"

    if backend_id == "qradar":
        conds = " OR ".join(
            f"\"{field}\" ILIKE '%{_escape_qradar_like(value)}%' ESCAPE '\\\\'" for value in values
        )
        return f"SELECT * FROM events WHERE {conds}"

    if backend_id in {"carbonblack", "sentinelone", "crowdstrike", "elasticsearch"}:
        return " OR ".join(f"{field}:*{_escape_lucene(value)}*" for value in values)

    return " OR ".join(f"{field}:*{_escape_lucene(value)}*" for value in values)


def generate_query(backend_id: str, sigma_rule: dict[str, Any], patterns: list[str]) -> str:
    """Generate a native query for *backend_id*.

    Tries sigma-cli first when a native target exists, then falls back to a
    best-effort escaped wildcard query.
    """
    if backend_id not in BACKENDS:
        return f"# Unknown backend: {backend_id}"

    target = BACKENDS[backend_id][2]
    tmp: str | None = None
    if target and _sigma_cli_available():
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
                yaml.safe_dump(sigma_rule, fh, sort_keys=False, allow_unicode=True)
                tmp = fh.name
            out = subprocess.run(
                ["sigma", "convert", "-t", target, tmp],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:
            pass
        finally:
            if tmp:
                Path(tmp).unlink(missing_ok=True)

    return _fallback_query(backend_id, patterns)
