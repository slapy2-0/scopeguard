from __future__ import annotations

import ipaddress
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from scopeguard.core.errors import (
    ScopeExpiredError,
    ScopeMissingError,
    ScopeViolationError,
)

DEFAULT_SCOPE_FILE = Path("scope.yaml")


class ScopeTarget(BaseModel):
    ssid: str | None = None
    bssid: str | None = None
    host: str | None = None
    cidr: str | None = None

    def matches_wifi(self, ssid: str | None, bssid: str | None) -> bool:
        if self.ssid and ssid and self.ssid.lower() == ssid.lower():
            return True
        if self.bssid and bssid and self.bssid.lower() == bssid.lower():
            return True
        return False
            
    def matches_host(self, host: str) -> bool:
                    if self.host is not None and self.host.lower() == host.lower():
                        return True
                    if self.cidr:
                        try:
                            net = ipaddress.ip_network(self.cidr, strict=False)
                            ip = ipaddress.ip_address(host)
                            return ip in net
                        except ValueError:
                            return False
                        return False

class Scope(BaseModel):
    owner: str
    authorized_by: str
    valid_until: date
    targets: list[ScopeTarget] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("valid_until")
    @classmethod
    def _not_too_far(cls, v: date) -> date:
        if (v - date.today()).days > 365:
            raise ValueError("valid_until cannot be more than 1 year out")
        return v

    def is_expired(self) -> bool:
        return date.today() > self.valid_until

    def assert_valid(self) -> None:
        if self.is_expired():
            raise ScopeExpiredError(
                f"Scope expired on {self.valid_until}. Re-authorize before scanning."
            )

    def assert_wifi(self, ssid: str | None, bssid: str | None) -> None:
        self.assert_valid()
        if not any(t.matches_wifi(ssid, bssid) for t in self.targets):
            raise ScopeViolationError(
                f"WiFi target ssid={ssid!r} bssid={bssid!r} is not in scope."
            )

    def assert_host(self, host: str) -> None:
        self.assert_valid()
        if not any(t.matches_host(host) for t in self.targets):
            raise ScopeViolationError(f"Host {host!r} is not in scope.")


def load_scope(path: Path = DEFAULT_SCOPE_FILE) -> Scope:
    if not path.exists():
        raise ScopeMissingError(
            f"No scope file at {path}. Run `scopeguard scope init` first."
        )
    data = yaml.safe_load(path.read_text()) or {}
    return Scope(**data)


def write_example_scope(path: Path = DEFAULT_SCOPE_FILE) -> None:
    if path.exists():
        raise FileExistsError(f"{path} already exists")
    path.write_text(
        "# ScopeGuard authorization file.\n"
        "# You MUST only list targets you own or have written permission to test.\n"
        'owner: "Your Name or Org"\n'
        'authorized_by: "Yourself / Client Name"\n'
        'valid_until: "2026-12-31"\n'
        'notes: "Internal lab + home network audit"\n'
        "targets:\n"
        '  - ssid: "HomeLab"\n'
        '  - bssid: "aa:bb:cc:dd:ee:ff"\n'
        '  - host: "192.168.1.10"\n'
        '  - cidr: "192.168.1.0/24"\n'
    )
