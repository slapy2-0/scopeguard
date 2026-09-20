from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path

from scopeguard import __version__
from scopeguard.core.scope import Scope


def _load_json(path: Path | None) -> dict | None:
    if path is None:
        return None
    data = json.loads(path.read_text())
    return data


def build_report(
    scope: Scope,
    wifi_path: Path | None = None,
    net_path: Path | None = None,
) -> dict:
    """Assemble a report document from saved scan JSON files."""
    wifi = _load_json(wifi_path)
    net = _load_json(net_path)

    wifi_aps = (wifi or {}).get("access_points", [])
    net_hosts = (net or {}).get("hosts", [])

    wifi_findings_count = sum(len(ap.get("findings") or []) for ap in wifi_aps)
    net_open_ports_count = sum(len(h.get("open_ports") or []) for h in net_hosts)

    return {
        "meta": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "scopeguard_version": __version__,
            "host_os": platform.platform(),
            "python": platform.python_version(),
        },
        "scope": {
            "owner": scope.owner,
            "authorized_by": scope.authorized_by,
            "valid_until": scope.valid_until.isoformat(),
            "notes": scope.notes,
            "targets": [t.model_dump(exclude_none=True) for t in scope.targets],
        },
        "summary": {
            "wifi_aps": len(wifi_aps),
            "wifi_findings": wifi_findings_count,
            "net_hosts": len(net_hosts),
            "net_open_ports": net_open_ports_count,
        },
        "wifi": {
            "scanned_at": (wifi or {}).get("scanned_at"),
            "interface": (wifi or {}).get("interface"),
            "backend": (wifi or {}).get("backend"),
            "access_points": wifi_aps,
        },
        "net": {
            "scanned_at": (net or {}).get("scanned_at"),
            "cidr": (net or {}).get("cidr"),
            "ports_spec": (net or {}).get("ports_spec"),
            "hosts": net_hosts,
        },
    }
