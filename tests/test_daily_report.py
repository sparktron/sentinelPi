"""
tests/test_daily_report.py - Daily report health summary.

The daily report answers "what did the sensor see?"; the health block added
here answers "was the sensor itself healthy?" by condensing the operational
watchdog snapshot.
"""

from __future__ import annotations

import queue
import threading

from sentinelpi.ui.dashboard import _generate_daily_report, _health_summary
from sentinelpi.utils.watchdog import OperationalWatchdog


def _watchdog(config, capture_queue=None, threads=None):
    return OperationalWatchdog(config, capture_queue or queue.Queue(maxsize=10), threads or [])


def test_health_summary_none_watchdog():
    summary = _health_summary(None)
    assert summary["healthy"] is None
    assert summary["monitoring_enabled"] is False
    assert summary["degraded"] == []


def test_health_summary_healthy(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    summary = _health_summary(_watchdog(config))

    assert summary["healthy"] is True
    assert summary["monitoring_enabled"] is True
    assert summary["degraded"] == []
    assert summary["dead_threads"] == []


def test_health_summary_flags_dead_thread_and_low_disk(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    config.monitoring.self_monitoring_disk_free_min_mb = 10**12  # force low-disk
    dead = threading.Thread(target=lambda: None, name="DeadWorker")
    summary = _health_summary(_watchdog(config, threads=[dead]))

    assert summary["healthy"] is False
    assert "DeadWorker" in summary["dead_threads"]
    joined = " ".join(summary["degraded"])
    assert "dead worker threads" in joined
    assert "low disk" in joined


def test_daily_report_includes_health(config, db, device_tracker, baseline, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    report = _generate_daily_report(db, device_tracker, baseline, _watchdog(config))

    assert "health" in report
    assert report["health"]["healthy"] is True


def test_daily_report_health_degrades_without_watchdog(config, db, device_tracker, baseline):
    report = _generate_daily_report(db, device_tracker, baseline)
    assert report["health"]["healthy"] is None
    assert report["health"]["monitoring_enabled"] is False
