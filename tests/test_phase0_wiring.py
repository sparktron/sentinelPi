"""Regression coverage for the 2026-07-12 Phase 0 runtime wiring fixes."""

from __future__ import annotations

import threading

from sentinelpi.detectors.port_scan_detector import PortScanDetector
from sentinelpi.inventory.device_tracker import DeviceTracker
from sentinelpi.main import SentinelPi, build_detector_thread
from sentinelpi.models import Alert, AlertCategory, Severity


def _build_app(tmp_path) -> SentinelPi:
    config_path = tmp_path / "sentinelpi.yaml"
    config_path.write_text(
        "\n".join([
            "monitoring:",
            "  packet_capture_enabled: false",
            "  auth_log_enabled: false",
            "storage:",
            f"  db_path: {tmp_path / 'app.db'}",
            "logging:",
            f"  log_dir: {tmp_path / 'logs'}",
            f"  json_alerts_file: {tmp_path / 'alerts.json'}",
        ]),
        encoding="utf-8",
    )
    return SentinelPi(config_path=str(config_path))


def test_port_scan_detector_is_registered_for_events_and_polling(tmp_path):
    app = _build_app(tmp_path)
    try:
        assert any(
            isinstance(detector, PortScanDetector)
            for detector in app._build_event_detectors()
        )
        assert any(
            isinstance(component, PortScanDetector)
            for component, _interval, _name in app._build_pollers()
        )
    finally:
        app._shutdown()


def test_device_tracker_uses_alert_dispatch_polling_path(tmp_path):
    app = _build_app(tmp_path)
    try:
        assert any(
            isinstance(component, DeviceTracker)
            for component, _interval, _name in app._build_pollers()
        )
    finally:
        app._shutdown()


def test_device_tracker_poll_alerts_reach_alert_manager(
    db, device_tracker, alert_manager, monkeypatch
):
    alert = Alert(
        severity=Severity.LOW,
        category=AlertCategory.NEW_DEVICE,
        affected_host="192.168.1.50",
        title="New test device",
    )
    stop_event = threading.Event()

    def poll_once():
        stop_event.set()
        return [alert]

    monkeypatch.setattr(device_tracker, "poll", poll_once)
    thread = build_detector_thread(
        device_tracker,
        alert_manager,
        stop_event,
        poll_interval=0,
        name="DeviceTracker",
    )

    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    persisted = db.get_alert(alert.alert_id)
    assert persisted is not None
    assert persisted.category == AlertCategory.NEW_DEVICE
    assert persisted.affected_host == "192.168.1.50"
