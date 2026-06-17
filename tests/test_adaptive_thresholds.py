"""
tests/test_adaptive_thresholds.py - Per-host adaptive threshold backoff.

Covers the AdaptiveThresholds helper (multiplier growth, decay, disabled
passthrough, isolation across hosts/signals) and its integration into the
port-scan detector so a chronically noisy host's bar rises while a quiet host
stays fully sensitive.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinelpi.detectors.adaptive import AdaptiveThresholds


def _at(**kw) -> AdaptiveThresholds:
    base = dict(enabled=True, trips_before_backoff=3, window_seconds=3600, step=0.5, max_multiplier=4.0)
    base.update(kw)
    return AdaptiveThresholds(**base)


def test_quiet_host_keeps_base_threshold():
    at = _at()
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    assert at.effective("port_scan", "10.0.0.1", 20, now) == 20


def test_multiplier_grows_after_repeated_trips():
    at = _at(trips_before_backoff=3, step=0.5)
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    # First two trips: still under the backoff floor → no scaling.
    at.record_trip("port_scan", "h", now)
    at.record_trip("port_scan", "h", now)
    assert at.multiplier("port_scan", "h", now) == 1.0
    # Third trip reaches the floor → backoff begins (1 + 0.5*1).
    at.record_trip("port_scan", "h", now)
    assert at.multiplier("port_scan", "h", now) == 1.5
    at.record_trip("port_scan", "h", now)
    assert at.multiplier("port_scan", "h", now) == 2.0


def test_multiplier_is_capped():
    at = _at(trips_before_backoff=1, step=1.0, max_multiplier=3.0)
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    for _ in range(20):
        at.record_trip("s", "h", now)
    assert at.multiplier("s", "h", now) == 3.0


def test_trips_decay_out_of_window():
    at = _at(trips_before_backoff=3, window_seconds=600)
    t0 = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    for _ in range(4):
        at.record_trip("s", "h", t0)
    assert at.multiplier("s", "h", t0) > 1.0
    # Well past the window: old trips expire, multiplier returns to 1.0.
    later = t0 + timedelta(seconds=601)
    assert at.multiplier("s", "h", later) == 1.0


def test_disabled_is_passthrough():
    at = _at(enabled=False, trips_before_backoff=1)
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    for _ in range(10):
        at.record_trip("s", "h", now)
    assert at.multiplier("s", "h", now) == 1.0
    assert at.effective("s", "h", 20, now) == 20


def test_signals_and_hosts_are_isolated():
    at = _at(trips_before_backoff=1, step=1.0)
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    at.record_trip("port_scan", "h1", now)
    at.record_trip("port_scan", "h1", now)
    assert at.multiplier("port_scan", "h1", now) > 1.0
    # Different host, different signal: untouched.
    assert at.multiplier("port_scan", "h2", now) == 1.0
    assert at.multiplier("dns_dga", "h1", now) == 1.0


def test_empty_keys_are_evicted_after_decay():
    at = _at(trips_before_backoff=1, window_seconds=60)
    t0 = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)
    at.record_trip("s", "h", t0)
    assert at._trips  # tracked
    # Access well past the window prunes and drops the now-empty key.
    at.multiplier("s", "h", t0 + timedelta(seconds=61))
    assert ("s", "h") not in at._trips


# --- integration: noisy host backs off, quiet host stays sensitive -----------

def _scan(detector, src_ip, dst_ip, ports, now):
    from sentinelpi.capture.packet_capture import CapturedConnection
    alerts = []
    for p in ports:
        alerts += detector.process_event(CapturedConnection(
            timestamp=now, src_ip=src_ip, src_port=40000,
            dst_ip=dst_ip, dst_port=p, protocol="tcp", flags="S",
        ))
    return alerts


def test_port_scan_threshold_adapts_for_noisy_host(config, db, baseline, device_tracker):
    from sentinelpi.detectors.port_scan_detector import PortScanDetector

    config.thresholds.port_scan_ports_per_minute = 10
    config.monitoring.adaptive_thresholds_enabled = True
    config.monitoring.adaptive_threshold_trips_before_backoff = 2
    config.monitoring.adaptive_threshold_step = 1.0
    config.monitoring.adaptive_threshold_window_seconds = 86400
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    detector = PortScanDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)

    noisy = "192.168.1.50"
    now = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)

    # Drive several scans from the noisy host to a fresh target each time (the
    # cooldown is per src→dst pair), accumulating trips so its bar rises.
    trips = 0
    for i in range(4):
        # Each scan is 15 ports — above the base 10. Use a new target + time
        # outside the 300s per-pair cooldown.
        t = now + timedelta(seconds=i * 400)
        alerts = _scan(detector, noisy, f"192.168.2.{10 + i}", range(1000, 1015), t)
        trips += len([a for a in alerts if a.category.value == "port_scan"])
    # It tripped at least the first couple of times before the bar climbed.
    assert trips >= 2

    # Its multiplier has grown, so 15 ports is now below its effective bar.
    mult = detector._adaptive.multiplier("port_scan", noisy, now + timedelta(seconds=2000))
    assert mult > 1.0

    # A quiet host doing the same 15-port scan still trips at the base threshold.
    quiet_alerts = _scan(detector, "192.168.1.77", "192.168.2.200",
                         range(1000, 1015), now + timedelta(seconds=5000))
    assert any(a.category.value == "port_scan" for a in quiet_alerts)
