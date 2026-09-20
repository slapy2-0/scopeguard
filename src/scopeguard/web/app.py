from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scopeguard import __version__
from scopeguard.core.errors import ScopeGuardError
from scopeguard.core.scope import DEFAULT_SCOPE_FILE, load_scope
from scopeguard.modules import network, wifi
from scopeguard.report import builder, renderer

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="ScopeGuard", version=__version__, docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_scan_lock = asyncio.Lock()


# --- models -----------------------------------------------------------------

class WifiScanRequest(BaseModel):
    iface: str | None = None
    include_out_of_scope: bool = False


class NetScanRequest(BaseModel):
    cidr: str
    ports: str = "common"
    timeout: float = 1.0
    host_workers: int = 32
    port_workers: int = 64


class ReportRequest(BaseModel):
    wifi: dict | None = None
    net: dict | None = None
    format: str = "html"


# --- helpers ----------------------------------------------------------------

def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _load_scope_or_400():
    try:
        scope = load_scope(DEFAULT_SCOPE_FILE)
        scope.assert_valid()
    except ScopeGuardError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return scope


def _hosts_to_dicts(hosts) -> list[dict]:
    return [
        {
            "ip": h.ip,
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in h.open_ports
            ],
        }
        for h in hosts
    ]


# --- routes -----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text())


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/scope")
async def get_scope() -> dict:
    scope = _load_scope_or_400()
    return {
        "owner": scope.owner,
        "authorized_by": scope.authorized_by,
        "valid_until": scope.valid_until.isoformat(),
        "notes": scope.notes,
        "targets": [t.model_dump(exclude_none=True) for t in scope.targets],
    }


@app.post("/api/wifi/scan")
async def api_wifi_scan(req: WifiScanRequest) -> dict:
    if _scan_lock.locked():
        raise HTTPException(status_code=429, detail="A scan is already in progress")
    async with _scan_lock:
        scope = _load_scope_or_400()
        try:
            if req.include_out_of_scope:
                aps = await asyncio.to_thread(wifi.scan, req.iface)
            else:
                aps = await asyncio.to_thread(wifi.scan_in_scope, req.iface, scope)
        except ScopeGuardError as e:
            raise HTTPException(status_code=400, detail=str(e))

        backend_name = wifi.get_backend().__name__.rsplit(".", 1)[-1]
        return {
            "scanned_at": _now(),
            "interface": req.iface,
            "backend": backend_name,
            "access_points": aps,
        }


@app.post("/api/net/scan")
async def api_net_scan(req: NetScanRequest) -> dict:
    if _scan_lock.locked():
        raise HTTPException(status_code=429, detail="A scan is already in progress")
    async with _scan_lock:
        scope = _load_scope_or_400()

        try:
            port_list = network.parse_ports(req.ports)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Bad ports: {e}")

        try:
            results, skipped = await asyncio.to_thread(
                network.scan_cidr,
                req.cidr, port_list, scope,
                req.timeout, req.host_workers, req.port_workers,
            )
        except ScopeGuardError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        return {
            "scanned_at": _now(),
            "cidr": req.cidr,
            "ports_spec": req.ports,
            "hosts": _hosts_to_dicts(results),
            "skipped_out_of_scope": len(skipped),
        }


@app.post("/api/report")
async def api_report(req: ReportRequest):
    scope = _load_scope_or_400()

    if req.wifi is None and req.net is None:
        raise HTTPException(
            status_code=400,
            detail="Nothing to report. Run a scan first.",
        )

    # Persist to temp files so builder can reuse the existing file-based API.
    import json as _json
    import tempfile
    from pathlib import Path as P

    with tempfile.TemporaryDirectory() as td:
        wifi_path = None
        net_path = None
        if req.wifi is not None:
            wifi_path = P(td) / "wifi.json"
            wifi_path.write_text(_json.dumps(req.wifi))
        if req.net is not None:
            net_path = P(td) / "net.json"
            net_path.write_text(_json.dumps(req.net))

        doc = builder.build_report(scope, wifi_path=wifi_path, net_path=net_path)

    try:
        content = renderer.render(doc, req.format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if req.format.lower() == "html":
        return HTMLResponse(content)
    return JSONResponse(doc)
