# ScopeGuard

> Authorization-first WiFi and network security auditor.

ScopeGuard refuses to scan anything you have not explicitly listed in `scope.yaml`.
**No scope, no scan.** No exceptions.

<p align="center">
  <img alt="status: alpha" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="python: 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="license: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="platform: linux | windows" src="https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey">
</p>

---

## Why

Most recon tools will happily scan any target you point them at. That's a foot-gun.
ScopeGuard inverts the model: you declare what you're allowed to test, sign off on it
with an expiry date, and every module checks that file before touching a packet.

It's for **auditing your own network**, **lab environments**, and **authorized
engagements** — nothing else.

## Features

- **WiFi audit** — passive AP scan, flags open networks, WEP/TKIP, WPS, weak signals
- **Network scan** — parallel TCP port scan with service detection and banner grab
- **Scope enforcement** — every command requires a valid `scope.yaml` with expiry
- **Shareable reports** — self-contained HTML + machine-readable JSON
- **Local web dashboard** — FastAPI + single-page UI, no auth needed because it binds to localhost
- **Cross-platform** — `iw` on Linux, `netsh` on Windows, pure sockets for net scan

## Non-goals

Forever, by design:

- No WiFi password cracking
- No handshake capture
- No deauthentication / packet injection
- No scanning outside `scope.yaml`

If you want any of those, this is not your tool.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/<you>/scopeguard.git
cd scopeguard
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# source .venv/Scripts/activate    # Windows / MINGW64
pip install -e ".[dev]"
```

## Usage

```bash
scopeguard scope init
# edit scope.yaml — add your SSID and target ranges, set an expiry date

scopeguard wifi scan
scopeguard net scan
scopeguard report
```

## License

MIT
