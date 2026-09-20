from datetime import date, timedelta

import pytest

from scopeguard.core.errors import ScopeExpiredError, ScopeViolationError
from scopeguard.core.scope import Scope, ScopeTarget


def _scope(**kw):
    base = dict(
        owner="me",
        authorized_by="me",
        valid_until=date.today() + timedelta(days=30),
        targets=[ScopeTarget(ssid="HomeLab", bssid="aa:bb:cc:dd:ee:ff", host="192.168.1.10")],
    )
    base.update(kw)
    return Scope(**base)


def test_in_scope_ssid_passes():
    _scope().assert_wifi("HomeLab", None)


def test_out_of_scope_ssid_raises():
    with pytest.raises(ScopeViolationError):
        _scope().assert_wifi("NeighborWiFi", None)


def test_expired_scope_raises():
    s = _scope(valid_until=date.today() - timedelta(days=1))
    with pytest.raises(ScopeExpiredError):
        s.assert_valid()


def test_host_in_scope():
    _scope().assert_host("192.168.1.10")


def test_host_out_of_scope():
    with pytest.raises(ScopeViolationError):
        _scope().assert_host("10.0.0.1")
