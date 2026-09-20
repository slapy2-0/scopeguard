from __future__ import annotations

import re
import shutil
import subprocess

from scopeguard.core.errors import BackendUnavailableError


def is_available() -> bool:
    return shutil.which("iw") is not None


def scan(iface: str) -> list[dict]:
    if not is_available():
        raise BackendUnavailableError("`iw` not found. Install with: sudo apt install iw")

    proc = subprocess.run(
        ["iw", "dev", iface, "scan"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise BackendUnavailableError(
            f"`iw scan` failed: {proc.stderr.strip() or 'unknown error'}"
        )
    return parse(proc.stdout)


_BSS_RE = re.compile(r"^BSS ([0-9a-f:]{17})")
_SSID_RE = re.compile(r"^\s*SSID: (.+)$")
_CHAN_RE = re.compile(r"^\s*DS Parameter set: channel (\d+)")
_SIGNAL_RE = re.compile(r"^\s*signal: (-?\d+)")
_PRIVACY_RE = re.compile(r"^\s*Privacy: yes")
_WPA_RE = re.compile(r"^\s*WPA:")
_RSN_RE = re.compile(r"^\s*RSN:")
_WPS_RE = re.compile(r"^\s*WPS:")


def parse(text: str) -> list[dict]:
    aps: list[dict] = []
    cur: dict | None = None

    for line in text.splitlines():
        m = _BSS_RE.match(line)
        if m:
            if cur:
                aps.append(cur)
            cur = {
                "bssid": m.group(1),
                "ssid": None,
                "channel": None,
                "signal_dbm": None,
                "privacy": False,
                "wpa": False,
                "rsn": False,
                "wps": False,
            }
            continue
        if cur is None:
            continue
        if m := _SSID_RE.match(line):
            cur["ssid"] = m.group(1)
        elif m := _CHAN_RE.match(line):
            cur["channel"] = int(m.group(1))
        elif m := _SIGNAL_RE.match(line):
            cur["signal_dbm"] = int(m.group(1))
        elif _PRIVACY_RE.match(line):
            cur["privacy"] = True
        elif _WPA_RE.match(line):
            cur["wpa"] = True
        elif _RSN_RE.match(line):
            cur["rsn"] = True
        elif _WPS_RE.match(line):
            cur["wps"] = True

    if cur:
        aps.append(cur)
    return aps
