from __future__ import annotations

import queue
import threading

from sentinelpi.models import AlertCategory, Severity
from sentinelpi.ui.dashboard import create_app
from sentinelpi.utils.watchdog import OperationalWatchdog


def _watchdog(config, capture_queue=None, threads=None):
    return OperationalWatchdog(config, capture_queue or queue.Queue(maxsize=10), threads or [])


def test_watchdog_alerts_on_dead_managed_thread(config):
    thread = threading.Thread(target=lambda: None, name="DeadWorker")
    watchdog = _watchdog(config, threads=[thread])

    alerts = watchdog.check()

    assert len(alerts) == 1
    assert alerts[0].category == AlertCategory.SYSTEM
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].dedup_key == "watchdog:thread:DeadWorker"


def test_watchdog_alerts_on_high_capture_queue(config):
    q = queue.Queue(maxsize=10)
    for item in range(8):
        q.put_nowait(item)
    config.monitoring.self_monitoring_queue_warn_ratio = 0.75
    watchdog = _watchdog(config, capture_queue=q)

    alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:capture_queue_high"]
    assert alerts[0].extra["watchdog"]["usage_ratio"] == 0.8


def test_watchdog_alerts_on_low_disk_threshold(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    config.monitoring.self_monitoring_disk_free_min_mb = 10**12
    watchdog = _watchdog(config)

    alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:disk_low"]
    assert alerts[0].severity == Severity.HIGH


def test_watchdog_status_reports_healthy_snapshot(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    watchdog = _watchdog(config)

    status = watchdog.get_status()

    assert status["enabled"] is True
    assert status["healthy"] is True
    assert status["capture_queue"]["size"] == 0
    assert status["dead_threads"] == []
    assert status["disk"]["path"] == str(tmp_path)


def test_dashboard_status_includes_watchdog(
    config, db, device_tracker, baseline, alert_manager, tmp_path
):
    config.dashboard.access_token = "tok"
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    watchdog = _watchdog(config)
    app = create_app(config, db, device_tracker, baseline, alert_manager, watchdog=watchdog)

    resp = app.test_client().get("/api/status", headers={"Authorization": "Bearer tok"})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["watchdog"]["enabled"] is True
    assert "capture_queue" in data["watchdog"]
