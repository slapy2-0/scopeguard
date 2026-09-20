from __future__ import annotations

import re
import shutil
import subprocess
import sys

from scopeguard.core.errors import BackendUnavailableError


def is_available() -> bool:
    return sys.platform == "win32" and shutil.which("netsh") is not None


def scan(iface: str | None = None) -> list[dict]:
    """`iface` is ignored on Windows; netsh scans all interfaces.

    Requires WLAN AutoConfig service running. No admin needed.
    """
    if not is_available():
        raise BackendUnavailableError("`netsh` not available (Windows only)")

    proc = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise BackendUnavailableError(
            f"`netsh wlan show networks` failed: {proc.stderr.strip() or 'unknown error'}"
        )
    return parse(proc.stdout)


# SSID header line: "SSID 1 : MyNetwork"
_SSID_HDR = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
# BSSID line: "BSSID 1 : aa:bb:cc:dd:ee:ff"
_BSSID = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})")
_SIGNAL = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
_CHANNEL = re.compile(r"^\s*Channel\s*:\s*(\d+)")
_AUTH = re.compile(r"^\s*Authentication\s*:\s*(.+)$")
_CIPHER = re.compile(r"^\s*Encryption\s*:\s*(.+)$")


def parse(text: str) -> list[dict]:
    aps: list[dict] = []
    cur_ssid: str | None = None
    cur_auth: str | None = None
    cur_cipher: str | None = None
    pending: dict | None = None

    def flush():
        nonlocal pending
        if pending is not None:
            aps.append(pending)
            pending = None

    for raw in text.splitlines():
        line = raw.rstrip()

        if m := _SSID_HDR.match(line):
            flush()
            cur_ssid = m.group(1).strip() or None
            cur_auth = None
            cur_cipher = None
            continue

        if m := _AUTH.match(line):
            cur_auth = m.group(1).strip()
            if pending is not None:
                pending["auth_raw"] = cur_auth
            continue

        if m := _CIPHER.match(line):
            cur_cipher = m.group(1).strip()
            if pending is not None:
                pending["cipher_raw"] = cur_cipher
            continue

        if m := _BSSID.match(line):
            flush()
            pending = {
                "bssid": m.group(1).lower(),
                "ssid": cur_ssid,
                "channel": None,
                "signal_dbm": None,  # netsh gives %, not dBm
                "signal_pct": None,
                "privacy": None,
                "wpa": False,
                "rsn": False,
                "wps": False,
                "auth_raw": cur_auth,
                "cipher_raw": cur_cipher,
            }
            continue

        if pending is None:
            continue

        if m := _SIGNAL.match(line):
            pending["signal_pct"] = int(m.group(1))
        elif m := _CHANNEL.match(line):
            pending["channel"] = int(m.group(1))

    flush()
    _derive_flags(aps)
    return aps


def _derive_flags(aps: list[dict]) -> None:
    for ap in aps:
        auth = (ap.get("auth_raw") or "").lower()
        cipher = (ap.get("cipher_raw") or "").lower()

        if "open" in auth:
            ap["privacy"] = False
        else:
            ap["privacy"] = True

        if "wpa3" in auth or "wpa2" in auth or "rsn" in cipher:
            ap["rsn"] = True
        if "wpa" in auth and "wpa2" not in auth and "wpa3" not in auth:
            ap["wpa"] = True

        # Windows doesn't report WPS reliably; leave as False.
        ap["wps"] = False
