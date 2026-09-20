from __future__ import annotations

import sys

from scopeguard.core.errors import BackendUnavailableError
from scopeguard.core.scope import Scope


def get_backend():
    """Return the platform-appropriate WiFi backend module."""
    if sys.platform == "win32":
        from scopeguard.modules.backends import netsh as backend
        return backend
    if sys.platform.startswith("linux"):
        from scopeguard.modules.backends import iw as backend
        return backend
    raise BackendUnavailableError(
        f"No WiFi backend for platform {sys.platform!r}. "
        "Linux (iw) and Windows (netsh) are supported."
    )


def scan(iface: str | None = None) -> list[dict]:
    backend = get_backend()
    return backend.scan(iface)  # type: ignore[arg-type]


def classify(ap: dict) -> list[str]:
    findings: list[str] = []

    if ap.get("privacy") is False:
        findings.append("OPEN network - no encryption")
    elif ap.get("privacy") is True and ap.get("wpa") and not ap.get("rsn"):
        findings.append("WPA1/TKIP legacy - upgrade to WPA2/WPA3")
    elif ap.get("privacy") is True and not ap.get("rsn") and not ap.get("wpa"):
        findings.append("Encryption present but no WPA/RSN - likely WEP")

    if ap.get("wps"):
        findings.append("WPS enabled - brute-forceable PIN")

    if ap.get("signal_pct") is not None and ap["signal_pct"] < 20:
        findings.append("Very weak signal - possible rogue/edge AP")

    return findings


def scan_in_scope(iface: str | None, scope: Scope) -> list[dict]:
    aps = scan(iface)
    in_scope: list[dict] = []
    for ap in aps:
        try:
            scope.assert_wifi(ap.get("ssid"), ap.get("bssid"))
        except Exception:
            continue
        ap["findings"] = classify(ap)
        in_scope.append(ap)
    return in_scope
