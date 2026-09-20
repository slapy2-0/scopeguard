from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass, field

from scopeguard.core.errors import ScopeViolationError
from scopeguard.core.scope import Scope

# --- port presets -----------------------------------------------------------

_QUICK = [22, 80, 443, 445, 3389, 8080]

_COMMON = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080,
]

_EXTENDED = _COMMON + [
    1, 7, 9, 13, 37, 42, 69, 79, 88, 102, 113, 119, 161, 389, 427, 464,
    465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646,
    873, 990, 1025, 1080, 1433, 1434, 1521, 1701, 1720, 1755, 1812, 1900,
    2000, 2049, 2082, 2083, 2100, 2222, 3000, 3128, 3260, 3690, 4000, 4443,
    4567, 5000, 5060, 5222, 5269, 5357, 5432, 5555, 5632, 5985, 6000, 6379,
    6667, 7001, 7171, 8000, 8008, 8081, 8443, 8888, 9000, 9090, 9200, 9999,
    10000, 11211, 27017, 27018, 28017,
]

PRESETS: dict[str, list[int]] = {
    "quick": _QUICK,
    "common": _COMMON,
    "extended": _EXTENDED,
}

MAX_HOSTS = 4096  # cap at /20
MAX_PORTS = 4096


# --- parsing ----------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """'quick' | 'common' | 'extended' | '22,80,443' | '1-1024' | mixed."""
    s = spec.strip().lower()
    if s in PRESETS:
        return sorted(set(PRESETS[s]))

    ports: set[int] = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            lo, hi = int(a), int(b)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"invalid port range: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(chunk)
            if p < 1 or p > 65535:
                raise ValueError(f"invalid port: {p}")
            ports.add(p)

    if not ports:
        raise ValueError("no ports specified")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"too many ports ({len(ports)} > {MAX_PORTS})")
    return sorted(ports)


# --- results ----------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


@dataclass
class HostResult:
    ip: str
    open_ports: list[PortResult] = field(default_factory=list)


# --- core scan --------------------------------------------------------------

def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _probe(ip: str, port: int, timeout: float) -> PortResult | None:
    """Try to TCP-connect. Return PortResult on success, None otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = ""
            try:
                s.settimeout(min(timeout, 1.0))
                data = s.recv(256)
                banner = data.decode("utf-8", errors="replace").strip()
            except (TimeoutError, OSError):
                pass
            return PortResult(port=port, service=_service_name(port), banner=banner)
    except OSError:
        return None


def scan_host(ip: str, ports: list[int], timeout: float, workers: int = 64) -> HostResult:
    result = HostResult(ip=ip)
    if not ports:
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        futures = [ex.submit(_probe, ip, p, timeout) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r is not None:
                result.open_ports.append(r)
    result.open_ports.sort(key=lambda r: r.port)
    return result


def scan_cidr(
    cidr: str,
    ports: list[int],
    scope: Scope,
    timeout: float = 1.0,
    host_workers: int = 32,
    port_workers: int = 64,
) -> tuple[list[HostResult], list[str]]:
    """Returns (results_with_open_ports, skipped_ips_out_of_scope)."""
    scope.assert_valid()
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > MAX_HOSTS:
        raise ValueError(
            f"CIDR too large: {len(hosts)} hosts > {MAX_HOSTS}. Use a smaller range."
        )

    allowed: list[str] = []
    skipped: list[str] = []
    for ip in hosts:
        if any(t.matches_host(str(ip)) for t in scope.targets):
            allowed.append(str(ip))
        else:
            skipped.append(str(ip))

    if not allowed:
        raise ScopeViolationError(f"No hosts in {cidr} are listed in scope.yaml")

    results: list[HostResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as ex:
        futures = {ex.submit(scan_host, ip, ports, timeout, port_workers): ip for ip in allowed}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r.open_ports:
                results.append(r)
    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
    return results, skipped
