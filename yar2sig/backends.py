"""Multi-backend query generation for yar2sig.

Attempts to use sigma-cli for native conversion; falls back to simple
wildcard search expressions per backend when sigma-cli is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

# backend_id -> (display name, default field, sigma-cli target)
BACKENDS: dict[str, tuple[str, str, str | None]] = {
    "elasticsearch": ("Elastic (Lucene/KQL)", "message", "lucene"),
    "splunk": ("Splunk SPL", "_raw", "splunk"),
    "kusto": ("Microsoft Sentinel / Defender (KQL)", "ProcessCommandLine", "kusto"),
    "qradar": ("IBM QRadar AQL", "payload", "qradar"),
    "carbonblack": ("VMware Carbon Black", "process_cmdline", None),
    "sentinelone": ("SentinelOne Deep Visibility", "SrcProcCmdLine", None),
    "crowdstrike": ("CrowdStrike Falcon", "CommandLine", None),
}


def _sigma_cli_available() -> bool:
    return shutil.which("sigma") is not None


def _fallback_query(backend_id: str, patterns: list[str]) -> str:
    field = BACKENDS[backend_id][1]
    if not patterns:
        return f"{field}:*"
    if backend_id == "splunk":
        return " OR ".join(f'{field}="*{p}*"' for p in patterns)
    if backend_id == "kusto":
        conds = " or ".join(f'{field} contains "{p}"' for p in patterns)
        return f"DeviceProcessEvents | where {conds}"
    if backend_id == "qradar":
        conds = " OR ".join(f"\"{field}\" ILIKE '%{p}%'" for p in patterns)
        return f"SELECT * FROM events WHERE {conds}"
    if backend_id in ("carbonblack", "sentinelone", "crowdstrike"):
        return " OR ".join(f"{field}:*{p}*" for p in patterns)
    # elasticsearch / default
    return " OR ".join(f"{field}:*{p}*" for p in patterns)


def generate_query(backend_id: str, sigma_rule: dict[str, Any], patterns: list[str]) -> str:
    """Generate a native query for *backend_id*.

    Tries sigma-cli first (when a target exists & it's installed),
    otherwise returns a wildcard fallback query.
    """
    if backend_id not in BACKENDS:
        return f"# Unknown backend: {backend_id}"

    target = BACKENDS[backend_id][2]
    if target and _sigma_cli_available():
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
                yaml.safe_dump(sigma_rule, fh, sort_keys=False, allow_unicode=True)
                tmp = fh.name
            out = subprocess.run(
                ["sigma", "convert", "-t", target, tmp],
                capture_output=True, text=True, timeout=30,
            )
            Path(tmp).unlink(missing_ok=True)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:
            pass
    return _fallback_query(backend_id, patterns)
