"""
utils/watchdog.py - SentinelPi self-monitoring checks.

The watchdog turns SentinelPi's own degradation into normal SYSTEM alerts so an
operator can tell when the monitor itself needs attention.
"""

from __future__ import annotations

import logging
import queue
import shutil
import threading
from pathlib import Path
from typing import List, Sequence

from ..config.manager import Config
from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)


class OperationalWatchdog:
    """Checks core runtime health and emits SYSTEM alerts for degradation."""

    def __init__(
        self,
        config: Config,
        capture_queue: "queue.Queue",
        threads: Sequence[threading.Thread],
    ) -> None:
        self.config = config
        self.capture_queue = capture_queue
        self.threads = threads
        self._last_status = self.snapshot()

    def check(self) -> List[Alert]:
        """Run health checks and return any SYSTEM alerts."""
        status = self.snapshot()
        self._last_status = status

        alerts: List[Alert] = []
        alerts.extend(self._thread_alerts(status))
        queue_alert = self._queue_alert(status)
        if queue_alert:
            alerts.append(queue_alert)
        disk_alert = self._disk_alert(status)
        if disk_alert:
            alerts.append(disk_alert)
        return alerts

    def get_status(self) -> dict:
        """Return the latest health snapshot for APIs/dashboard."""
        return dict(self._last_status)

    def snapshot(self) -> dict:
        dead_threads = sorted(t.name for t in self.threads if not t.is_alive())
        queue_size = self.capture_queue.qsize()
        queue_max = self.capture_queue.maxsize or 0
        queue_ratio = (queue_size / queue_max) if queue_max else 0.0
        disk = self._disk_status()

        return {
            "enabled": self.config.monitoring.self_monitoring_enabled,
            "healthy": not dead_threads
            and queue_ratio < self.config.monitoring.self_monitoring_queue_warn_ratio
            and disk["free_mb"] >= self.config.monitoring.self_monitoring_disk_free_min_mb,
            "dead_threads": dead_threads,
            "capture_queue": {
                "size": queue_size,
                "max_size": queue_max,
                "usage_ratio": round(queue_ratio, 4),
                "warn_ratio": self.config.monitoring.self_monitoring_queue_warn_ratio,
            },
            "disk": disk,
        }

    def _disk_status(self) -> dict:
        path = Path(self.config.storage.db_path).expanduser()
        target = path.parent if path.suffix else path
        try:
            target.mkdir(parents=True, exist_ok=True)
            usage = shutil.disk_usage(target)
        except OSError as exc:
            logger.debug("Watchdog disk check failed for %s: %s", target, exc)
            return {
                "path": str(target),
                "free_mb": 0,
                "total_mb": 0,
                "used_percent": 100.0,
                "error": str(exc),
            }

        total_mb = usage.total / (1024 * 1024)
        free_mb = usage.free / (1024 * 1024)
        used_percent = ((usage.total - usage.free) / usage.total * 100.0) if usage.total else 100.0
        return {
            "path": str(target),
            "free_mb": round(free_mb, 1),
            "total_mb": round(total_mb, 1),
            "used_percent": round(used_percent, 1),
            "min_free_mb": self.config.monitoring.self_monitoring_disk_free_min_mb,
        }

    def _thread_alerts(self, status: dict) -> List[Alert]:
        alerts = []
        for name in status["dead_threads"]:
            alerts.append(Alert(
                severity=Severity.HIGH,
                category=AlertCategory.SYSTEM,
                affected_host="localhost",
                title=f"SentinelPi worker thread stopped: {name}",
                description=(
                    f"The managed worker thread '{name}' is no longer alive. SentinelPi may be "
                    "missing capture, detector, forwarding, or dashboard work until restarted."
                ),
                recommended_action="Check logs for the thread failure and restart the service if needed.",
                confidence=1.0,
                dedup_key=f"watchdog:thread:{name}",
                extra={"watchdog": {"kind": "dead_thread", "thread": name}},
            ))
        return alerts

    def _queue_alert(self, status: dict) -> Alert | None:
        q = status["capture_queue"]
        if not q["max_size"] or q["usage_ratio"] < q["warn_ratio"]:
            return None
        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title=f"SentinelPi capture queue high water mark: {q['size']}/{q['max_size']}",
            description=(
                f"The capture queue is {q['usage_ratio']:.0%} full. If it reaches capacity, "
                "packet or flow events will be dropped before detectors can process them."
            ),
            recommended_action=(
                "Reduce capture volume, disable noisy sources, or investigate slow detector/notifier work."
            ),
            confidence=0.9,
            dedup_key="watchdog:capture_queue_high",
            extra={"watchdog": {"kind": "capture_queue", **q}},
        )

    def _disk_alert(self, status: dict) -> Alert | None:
        disk = status["disk"]
        if disk["free_mb"] >= disk["min_free_mb"] and "error" not in disk:
            return None
        if "error" in disk:
            title = "SentinelPi disk health check failed"
            description = f"Could not inspect storage path {disk['path']}: {disk['error']}."
        else:
            title = f"SentinelPi low disk space: {disk['free_mb']} MB free"
            description = (
                f"Storage path {disk['path']} has {disk['free_mb']} MB free "
                f"({disk['used_percent']}% used), below the configured minimum of "
                f"{disk['min_free_mb']} MB."
            )
        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title=title,
            description=description,
            recommended_action="Free disk space or move SentinelPi storage to a larger volume.",
            confidence=1.0,
            dedup_key="watchdog:disk_low",
            extra={"watchdog": {"kind": "disk", **disk}},
        )
