"""
tests/test_arp_restore.py - Tests for the ARP-spoof auto-restore responder.

Verifies it re-pins the configured gateway MAC (only) on a gateway ARP-anomaly,
across both backends, with the usual gating and an end-to-end approval path.
The conftest config has gateway_ip 192.168.1.1 / gateway_mac aa:bb:cc:00:00:01.
"""

from __future__ import annotations

import pytest

from sentinelpi.responders.arp_restore import ARPRestoreResponder
from sentinelpi.responders.manager import ResponderManager
from sentinelpi.models import Alert, AlertCategory, Severity


class _RecordingRunner:
    def __init__(self, code=0, output=""):
        self.calls = []
        self._code, self._output = code, output

    def __call__(self, argv):
        self.calls.append(argv)
        return self._code, self._output


def _arp_alert(is_gateway=True, severity=Severity.CRITICAL,
               category=AlertCategory.ARP_ANOMALY, host="192.168.1.1"):
    return Alert(
        severity=severity, category=category, affected_host=host,
        title="gateway MAC changed", description="d",
        extra={"is_gateway": is_gateway, "old_mac": "aa:bb:cc:00:00:01", "new_mac": "de:ad:be:ef:00:01"},
    )


# -------------------------------------------------------------------- backends
def test_arp_backend_command(config):
    config.response.arp_restore_enabled = True
    r = ARPRestoreResponder(config, runner=_RecordingRunner())
    action = r.plan(_arp_alert())
    assert action.target == "192.168.1.1"
    assert action.commands == [["arp", "-s", "192.168.1.1", "aa:bb:cc:00:00:01"]]


def test_ip_backend_command(config):
    config.response.arp_restore_enabled = True
    config.response.arp_restore_backend = "ip"
    runner = _RecordingRunner()
    r = ARPRestoreResponder(config, runner=runner)
    r.execute(r.plan(_arp_alert()))
    assert runner.calls == [
        ["ip", "neigh", "replace", "192.168.1.1", "lladdr", "aa:bb:cc:00:00:01", "dev", "eth0"],
    ]


# ---------------------------------------------------------------------- gating
def test_disabled_not_handled(config):
    config.response.arp_restore_enabled = False
    assert ARPRestoreResponder(config).can_handle(_arp_alert()) is False


def test_non_gateway_arp_not_handled(config):
    config.response.arp_restore_enabled = True
    assert ARPRestoreResponder(config).can_handle(_arp_alert(is_gateway=False)) is False


def test_non_arp_category_not_handled(config):
    config.response.arp_restore_enabled = True
    r = ARPRestoreResponder(config)
    assert r.can_handle(_arp_alert(category=AlertCategory.PORT_SCAN)) is False


def test_requires_configured_gateway_mac(config):
    config.response.arp_restore_enabled = True
    config.network.gateway_mac = ""   # no ground truth to restore to
    r = ARPRestoreResponder(config)
    assert r.can_handle(_arp_alert()) is False
    assert r.plan(_arp_alert()) is None


def test_below_min_severity_not_handled(config):
    config.response.arp_restore_enabled = True
    config.response.arp_restore_min_severity = "high"
    r = ARPRestoreResponder(config)
    assert r.can_handle(_arp_alert(severity=Severity.MEDIUM)) is False


# ------------------------------------------------------------------- execution
def test_command_failure_recorded(config):
    config.response.arp_restore_enabled = True
    runner = _RecordingRunner(code=1, output="not permitted")
    r = ARPRestoreResponder(config, runner=runner)
    action = r.plan(_arp_alert())
    r.execute(action)
    assert action.success is False and "not permitted" in action.error


def test_through_manager_with_approval(config):
    from sentinelpi.responders.base import PENDING, EXECUTED
    config.response.enabled = True
    config.response.dry_run = False
    config.response.require_approval = True
    config.response.arp_restore_enabled = True
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(ARPRestoreResponder(config, runner=runner))

    action = mgr.handle(_arp_alert())[0]
    assert action.status == PENDING and runner.calls == []
    mgr.approve(action.action_id)
    assert action.status == EXECUTED and runner.calls
