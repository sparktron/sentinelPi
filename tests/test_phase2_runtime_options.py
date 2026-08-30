"""Runtime coverage for Phase 2 public configuration switches."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpi.capture.packet_capture import build_bpf_filter
from sentinelpi.capture.proc_reader import ARPEntry, InterfaceStats
from sentinelpi.detectors.dns_detector import DNSDetector
from sentinelpi.detectors.file_integrity_detector import FileIntegrityDetector
from sentinelpi.detectors.traffic_detector import TrafficSpikeDetector
from sentinelpi.inventory.active_discovery import ActiveDiscovery
from sentinelpi.main import SentinelPi
from sentinelpi.models import AlertCategory
from sentinelpi.reporting import ReportScheduler


def _build_app(tmp_path, monitoring: list[str] | None = None, reporting: list[str] | None = None):
    lines = [
        "monitoring:",
        "  packet_capture_enabled: false",
        "  auth_log_enabled: false",
        *(monitoring or []),
        "reporting:",
        *(reporting or ["  daily_report_enabled: false", "  weekly_report_enabled: false"]),
        "storage:",
        f"  db_path: {tmp_path / 'app.db'}",
        "logging:",
        f"  log_dir: {tmp_path / 'logs'}",
        f"  json_alerts_file: {tmp_path / 'alerts.json'}",
    ]
    config_path = tmp_path / "sentinelpi.yaml"
    config_path.write_text("\n".join(lines), encoding="utf-8")
    return SentinelPi(config_path=str(config_path))


def test_dns_disable_removes_capture_and_detector_wiring(tmp_path):
    app = _build_app(tmp_path, ["  dns_monitoring_enabled: false"])
    try:
        assert "udp port 53" not in build_bpf_filter(dns_monitoring_enabled=False)
        assert not any(isinstance(detector, DNSDetector) for detector in app._build_event_detectors())
    finally:
        app._shutdown()


def test_active_discovery_routes_observations_through_device_tracker(
    config, device_tracker
):
    entry = ARPEntry("192.168.1.77", "02:00:00:00:00:77", "eth0", "0x2")
    discovery = ActiveDiscovery(config, device_tracker, discover=lambda _config: [entry])

    alerts = discovery.poll()

    assert len(alerts) == 1
    assert alerts[0].category == AlertCategory.NEW_DEVICE
    assert device_tracker.get_device("192.168.1.77") is not None


def test_active_discovery_uses_configured_interval(tmp_path):
    app = _build_app(
        tmp_path,
        ["  active_discovery_enabled: true", "  active_discovery_interval_seconds: 123"],
    )
    try:
        assert any(
            isinstance(component, ActiveDiscovery) and interval == 123
            for component, interval, _name in app._build_pollers()
        )
    finally:
        app._shutdown()


def test_runtime_pollers_cover_integrity_traffic_and_reports(tmp_path):
    monitored = tmp_path / "important.conf"
    monitored.write_text("original", encoding="utf-8")
    app = _build_app(
        tmp_path,
        [
            "  file_integrity_enabled: true",
            "  file_integrity_paths:",
            f"    - {monitored}",
        ],
        ["  daily_report_enabled: true", "  weekly_report_enabled: false"],
    )
    try:
        components = [component for component, _interval, _name in app._build_pollers()]
        assert any(isinstance(component, FileIntegrityDetector) for component in components)
        assert any(isinstance(component, TrafficSpikeDetector) for component in components)
        assert any(isinstance(component, ReportScheduler) for component in components)
    finally:
        app._shutdown()


def test_file_integrity_detects_content_change(
    config, db, baseline, device_tracker, tmp_path
):
    monitored = tmp_path / "important.conf"
    monitored.write_text("original", encoding="utf-8")
    config.monitoring.file_integrity_paths = [str(monitored)]
    detector = FileIntegrityDetector(config, db, baseline, device_tracker)

    assert detector.poll() == []
    monitored.write_text("changed", encoding="utf-8")
    alerts = detector.poll()

    assert len(alerts) == 1
    assert alerts[0].category == AlertCategory.PROCESS_ANOMALY
    assert "content changed" in alerts[0].title


def test_traffic_detector_emits_spike_after_baseline(
    config, db, baseline, device_tracker, monkeypatch
):
    for _ in range(5):
        baseline.record_traffic("eth0", 100.0)
    detector = TrafficSpikeDetector(config, db, baseline, device_tracker)
    samples = iter([
        {"eth0": InterfaceStats("eth0", rx_bytes=1_000)},
        {"eth0": InterfaceStats("eth0", rx_bytes=11_000)},
    ])
    times = iter([0.0, 60.0])
    monkeypatch.setattr("sentinelpi.detectors.traffic_detector.read_interface_stats", lambda: next(samples))
    monkeypatch.setattr("sentinelpi.detectors.traffic_detector.time.monotonic", lambda: next(times))

    assert detector.poll() == []
    alerts = detector.poll()

    assert len(alerts) == 1
    assert alerts[0].category == AlertCategory.TRAFFIC_SPIKE


def test_scheduled_reports_emit_once_across_scheduler_restart(
    config, db, device_tracker, baseline, monkeypatch
):
    config.reporting.daily_report_enabled = True
    config.reporting.daily_report_hour = 7
    config.reporting.weekly_report_enabled = True
    config.reporting.weekly_report_day = 1
    now = datetime(2026, 7, 13, 8, 0, 0, tzinfo=timezone.utc)  # Monday
    monkeypatch.setattr("sentinelpi.reporting._local_now", lambda: now)
    monkeypatch.setattr("sentinelpi.reporting.clock.now", lambda: now)

    scheduler = ReportScheduler(config, db, device_tracker, baseline)
    alerts = scheduler.poll()

    assert [alert.title for alert in alerts] == [
        "Daily SentinelPi security report",
        "Weekly SentinelPi security report",
    ]
    assert scheduler.poll() == []
    assert ReportScheduler(config, db, device_tracker, baseline).poll() == []
