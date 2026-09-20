from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.table import Table

from scopeguard import __version__
from scopeguard.core.console import console, err_console
from scopeguard.core.errors import ScopeGuardError
from scopeguard.core.scope import (
    DEFAULT_SCOPE_FILE,
    load_scope,
    write_example_scope,
)
from scopeguard.modules import network, wifi
from scopeguard.report import builder, renderer

app = typer.Typer(
    name="scopeguard",
    help="Authorization-first WiFi and network security auditor.",
    no_args_is_help=True,
)
scope_app = typer.Typer(help="Manage the authorization scope file.")
wifi_app = typer.Typer(help="WiFi reconnaissance and auditing.")
net_app = typer.Typer(help="Network host and port discovery.")
app.add_typer(scope_app, name="scope")
app.add_typer(wifi_app, name="wifi")
app.add_typer(net_app, name="net")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"scopeguard [bold cyan]{__version__}[/]")


@app.command()
def doctor() -> None:
    """Diagnose environment: OS, backend availability, scope file."""
    tbl = Table(title="scopeguard doctor", show_lines=True)
    tbl.add_column("Check")
    tbl.add_column("Status")
    tbl.add_column("Detail")

    tbl.add_row("Python", "[green]ok[/]", sys.version.split()[0])
    tbl.add_row("Platform", "[cyan]info[/]", sys.platform)

    try:
        backend = wifi.get_backend()
        name = backend.__name__.rsplit(".", 1)[-1]
        avail = backend.is_available()
        status = "[green]ok[/]" if avail else "[yellow]missing[/]"
        detail = f"backend={name}"
        if not avail:
            if sys.platform == "win32":
                detail += " (netsh not found or WLAN service off)"
            elif sys.platform.startswith("linux"):
                detail += " (install: sudo apt install iw)"
        tbl.add_row("WiFi backend", status, detail)
    except Exception as e:  # noqa: BLE001
        tbl.add_row("WiFi backend", "[red]fail[/]", str(e))

    tbl.add_row("Network scanner", "[green]ok[/]", "pure sockets (all platforms)")
    tbl.add_row("Report engine", "[green]ok[/]", "html + json")

    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        tbl.add_row("Web dashboard", "[green]ok[/]", "fastapi + uvicorn")
    except ImportError:
        tbl.add_row("Web dashboard", "[yellow]missing[/]", "pip install -e \".[web,dev]\"")

    try:
        scope = load_scope(DEFAULT_SCOPE_FILE)
        scope.assert_valid()
        tbl.add_row(
            "scope.yaml",
            "[green]ok[/]",
            f"{len(scope.targets)} targets, expires {scope.valid_until}",
        )
    except ScopeGuardError as e:
        tbl.add_row("scope.yaml", "[yellow]missing/invalid[/]", str(e))

    console.print(tbl)


@scope_app.command("init")
def scope_init(
    path: Path = typer.Option(DEFAULT_SCOPE_FILE, "--path", "-p"),
) -> None:
    """Create a starter scope.yaml. Edit it before scanning."""
    try:
        write_example_scope(path)
        console.print(f"[green]Created[/] {path}. Edit targets before scanning.")
    except FileExistsError as e:
        err_console.print(str(e))
        raise typer.Exit(1)


@scope_app.command("check")
def scope_check(
    path: Path = typer.Option(DEFAULT_SCOPE_FILE, "--path", "-p"),
) -> None:
    """Validate the current scope.yaml."""
    try:
        scope = load_scope(path)
        scope.assert_valid()
    except ScopeGuardError as e:
        err_console.print(str(e))
        raise typer.Exit(1)

    tbl = Table(title="Scope", show_lines=True)
    tbl.add_column("Field")
    tbl.add_column("Value")
    tbl.add_row("owner", scope.owner)
    tbl.add_row("authorized_by", scope.authorized_by)
    tbl.add_row("valid_until", scope.valid_until.isoformat())
    tbl.add_row("targets", str(len(scope.targets)))
    console.print(tbl)


def _fmt_signal(ap: dict) -> str:
    if ap.get("signal_dbm") is not None:
        return f'{ap["signal_dbm"]} dBm'
    if ap.get("signal_pct") is not None:
        return f'{ap["signal_pct"]}%'
    return "-"


def _save_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2))
    console.print(f"[green]Saved[/] {path}")


@wifi_app.command("scan")
def wifi_scan(
    iface: str | None = typer.Option(
        None, "--iface", "-i",
        help="Wireless interface (Linux only). Ignored on Windows.",
    ),
    scope_path: Path = typer.Option(DEFAULT_SCOPE_FILE, "--scope"),
    show_out_of_scope: bool = typer.Option(
        False, "--all", help="Include out-of-scope APs (not audited)",
    ),
    save: Path | None = typer.Option(None, "--save", help="Write scan JSON here"),
) -> None:
    """Scan nearby WiFi APs. Only in-scope APs are audited."""
    try:
        scope = load_scope(scope_path)
        scope.assert_valid()
        aps = wifi.scan(iface) if show_out_of_scope else wifi.scan_in_scope(iface, scope)
    except ScopeGuardError as e:
        err_console.print(str(e))
        raise typer.Exit(1)

    if save is not None:
        backend_name = wifi.get_backend().__name__.rsplit(".", 1)[-1]
        _save_json(save, {
            "scanned_at": _utc_now(),
            "interface": iface,
            "backend": backend_name,
            "access_points": aps,
        })

    if not aps:
        console.print("[yellow]No access points found.[/]")
        return

    title = f"WiFi scan{' on ' + iface if iface else ''}"
    tbl = Table(title=title, show_lines=False)
    for col in ("SSID", "BSSID", "CH", "Signal", "Enc", "Findings"):
        tbl.add_column(col)

    for ap in aps:
        if ap.get("privacy") is False:
            enc = "Open"
        elif ap.get("rsn"):
            enc = "WPA2/3"
        elif ap.get("wpa"):
            enc = "WPA/Legacy"
        else:
            enc = "Unknown"

        findings = ", ".join(ap.get("findings", [])) or "-"
        tbl.add_row(
            ap.get("ssid") or "<hidden>",
            ap.get("bssid") or "-",
            str(ap.get("channel") or "-"),
            _fmt_signal(ap),
            enc,
            findings,
        )

    console.print(tbl)


@net_app.command("scan")
def net_scan(
    cidr: str = typer.Argument(..., help="CIDR to scan, e.g. 192.168.1.0/24"),
    ports: str = typer.Option(
        "common", "--ports", "-p",
        help="'quick' | 'common' | 'extended' | '22,80,443' | '1-1024'",
    ),
    scope_path: Path = typer.Option(DEFAULT_SCOPE_FILE, "--scope"),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-port timeout (s)"),
    host_workers: int = typer.Option(32, "--host-workers", help="Parallel hosts"),
    port_workers: int = typer.Option(64, "--port-workers", help="Parallel ports per host"),
    save: Path | None = typer.Option(None, "--save", help="Write scan JSON here"),
) -> None:
    """Scan a CIDR for live hosts and open TCP ports. Scope-locked."""
    try:
        port_list = network.parse_ports(ports)
    except ValueError as e:
        err_console.print(f"[red]Bad --ports:[/] {e}")
        raise typer.Exit(2)

    try:
        scope = load_scope(scope_path)
        results, skipped = network.scan_cidr(
            cidr, port_list, scope,
            timeout=timeout,
            host_workers=host_workers,
            port_workers=port_workers,
        )
    except ScopeGuardError as e:
        err_console.print(str(e))
        raise typer.Exit(1)
    except ValueError as e:
        err_console.print(f"[red]{e}[/]")
        raise typer.Exit(2)

    if save is not None:
        _save_json(save, {
            "scanned_at": _utc_now(),
            "cidr": cidr,
            "ports_spec": ports,
            "hosts": [
                {
                    "ip": h.ip,
                    "open_ports": [
                        {"port": p.port, "service": p.service, "banner": p.banner}
                        for p in h.open_ports
                    ],
                }
                for h in results
            ],
        })

    if skipped:
        console.print(f"[dim]{len(skipped)} host(s) skipped (out of scope)[/]")

    if not results:
        console.print("[yellow]No live hosts with open ports found.[/]")
        return

    tbl = Table(title=f"net scan {cidr}", show_lines=True)
    for col in ("Host", "Port", "Service", "Banner"):
        tbl.add_column(col)

    for host in results:
        for i, p in enumerate(host.open_ports):
            tbl.add_row(
                host.ip if i == 0 else "",
                str(p.port),
                p.service or "-",
                (p.banner[:60] + "...") if len(p.banner) > 60 else (p.banner or "-"),
            )

    console.print(tbl)


@app.command()
def report(
    wifi_path: Path | None = typer.Option(None, "--wifi", help="WiFi scan JSON"),
    net_path: Path | None = typer.Option(None, "--net", help="Network scan JSON"),
    fmt: str = typer.Option("html", "--format", "-f", help="html | json"),
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Output file. Defaults to report.<format>",
    ),
    scope_path: Path = typer.Option(DEFAULT_SCOPE_FILE, "--scope"),
) -> None:
    """Build a shareable report from saved scan JSON files."""
    try:
        scope = load_scope(scope_path)
        scope.assert_valid()
    except ScopeGuardError as e:
        err_console.print(str(e))
        raise typer.Exit(1)

    if wifi_path is None and net_path is None:
        err_console.print(
            "[red]Nothing to report.[/] Pass --wifi and/or --net. "
            "Tip: add `--save wifi.json` to scan commands."
        )
        raise typer.Exit(2)

    doc = builder.build_report(scope, wifi_path=wifi_path, net_path=net_path)

    try:
        content = renderer.render(doc, fmt)
    except ValueError as e:
        err_console.print(f"[red]{e}[/]")
        raise typer.Exit(2)

    out = output or Path(f"report.{fmt.lower()}")
    out.write_text(content)

    console.print(f"[green]Wrote[/] {out}")
    console.print(
        f"  APs: [bold]{doc['summary']['wifi_aps']}[/] "
        f"(findings: [bold]{doc['summary']['wifi_findings']}[/])"
    )
    console.print(
        f"  Hosts: [bold]{doc['summary']['net_hosts']}[/] "
        f"(open ports: [bold]{doc['summary']['net_open_ports']}[/])"
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (defaults to localhost)"),
    port: int = typer.Option(8000, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change (dev only)"),
) -> None:
    """Launch the local web dashboard."""
    try:
        import uvicorn
    except ImportError:
        err_console.print(
            "[red]uvicorn not installed.[/] Reinstall: pip install -e \".[dev]\""
        )
        raise typer.Exit(1)

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[yellow]WARNING:[/] binding to [bold]{host}[/] exposes the dashboard "
            "on your network."
        )
        console.print(
            "ScopeGuard has no authentication. Only do this on a trusted LAN."
        )

    console.print(f"ScopeGuard dashboard: [bold cyan]http://{host}:{port}[/]")
    console.print("Press Ctrl+C to stop.")

    uvicorn.run(
        "scopeguard.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    app()
