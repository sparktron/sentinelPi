"""Live, durable, and auditable device-trust policy tests."""

from __future__ import annotations

import pytest

from sentinelpi.capture.proc_reader import ARPEntry, ProcConnection
from sentinelpi.config.manager import TrustedDevice
from sentinelpi.detectors.connection_detector import ConnectionDetector
from sentinelpi.inventory.device_tracker import DeviceTracker
from sentinelpi.utils import clock


def _discover(tracker: DeviceTracker, ip: str = "192.168.1.50") -> None:
    tracker.process_entries([
        ARPEntry(
            ip=ip,
            mac="aa:bb:cc:dd:ee:50",
            interface="eth0",
            flags="0x2",
        )
    ])


def test_trust_policy_is_live_durable_and_auditable(config, db, device_tracker):
    _discover(device_tracker)

    trusted = device_tracker.set_device_trust(
        "192.168.1.50", True, "dashboard:127.0.0.1"
    )

    assert trusted is not None and trusted.is_trusted is True
    assert device_tracker.is_trusted_device("192.168.1.50") is True
    assert db.get_device_by_ip("192.168.1.50").is_trusted is True
    history = device_tracker.get_device_trust_history("192.168.1.50")
    assert history[0]["timestamp"]
    assert {key: value for key, value in history[0].items() if key != "timestamp"} == {
        "ip": "192.168.1.50",
        "mac": "aa:bb:cc:dd:ee:50",
        "trusted": True,
        "actor": "dashboard:127.0.0.1",
    }

    restarted = DeviceTracker(config, db)
    assert restarted.is_trusted_device("192.168.1.50") is True

    untrusted = restarted.set_device_trust(
        "192.168.1.50", False, "dashboard:127.0.0.1"
    )
    assert untrusted is not None and untrusted.is_trusted is False
    assert restarted.is_trusted_device("192.168.1.50") is False
    assert [event["trusted"] for event in restarted.get_device_trust_history("192.168.1.50")] == [
        False,
        True,
    ]


def test_configured_trust_cannot_be_removed_at_runtime(config, db):
    config.trusted_devices = [TrustedDevice(mac="aa:bb:cc:dd:ee:50")]
    tracker = DeviceTracker(config, db)
    _discover(tracker)

    with pytest.raises(ValueError, match="configuration"):
        tracker.set_device_trust("192.168.1.50", False, "dashboard:127.0.0.1")


def test_connection_detector_consults_live_trust_policy(
    config, db, baseline, device_tracker
):
    _discover(device_tracker)
    detector = ConnectionDetector(config, db, baseline, device_tracker)
    connection = ProcConnection(
        local_ip="192.168.1.50",
        local_port=50000,
        remote_ip="198.51.100.20",
        remote_port=4444,
        state="ESTABLISHED",
        protocol="tcp",
        inode=1,
    )

    device_tracker.set_device_trust("192.168.1.50", True, "test")
    assert detector._new_destination_alert(connection, clock.now()) is None

    device_tracker.set_device_trust("192.168.1.50", False, "test")
    assert detector._new_destination_alert(connection, clock.now()) is not None


def test_dashboard_trust_and_untrust_update_auditable_policy(
    config, db, baseline, alert_manager, device_tracker
):
    pytest.importorskip("flask")
    from sentinelpi.ui.dashboard import create_app

    _discover(device_tracker)
    config.dashboard.access_token = "test-token"
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    client = app.test_client()
    headers = {"Authorization": "Bearer test-token"}

    trusted = client.post("/api/devices/192.168.1.50/trust", headers=headers)
    assert trusted.status_code == 200
    assert trusted.get_json()["trusted"] is True

    detail = client.get("/api/devices/192.168.1.50/detail", headers=headers)
    assert detail.status_code == 200
    assert detail.get_json()["trust_history"][0]["actor"] == "dashboard:127.0.0.1"

    untrusted = client.post("/api/devices/192.168.1.50/untrust", headers=headers)
    assert untrusted.status_code == 200
    assert untrusted.get_json()["trusted"] is False
