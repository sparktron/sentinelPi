"""Scheduled daily and weekly security-summary alerts."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Set

from .config.manager import Config
from .models import Alert, AlertCategory, Severity
from .utils import clock


def _local_now() -> datetime:
    """Return local wall time for operator-configured report schedules."""
    return datetime.now().astimezone()


class ReportScheduler:
    """Emit each configured report once after its local scheduled time."""

    def __init__(self, config: Config, db, device_tracker, baseline) -> None:
        self.config = config
        self.db = db
        self.device_tracker = device_tracker
        self.baseline = baseline
        self._delivered: Set[str] = set()

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def poll(self) -> List[Alert]:
        now = _local_now()
        if now.hour < self.config.reporting.daily_report_hour:
            return []

        alerts: List[Alert] = []
        daily_key = f"daily:{now.date().isoformat()}"
        if self.config.reporting.daily_report_enabled and not self._was_delivered("daily", daily_key):
            alerts.append(self._build_report("Daily", 24, daily_key))
            self._mark_delivered("daily", daily_key)

        # Config uses Sunday=0, Monday=1, matching isoweekday() modulo seven.
        weekly_key = f"weekly:{now.date().isoformat()}"
        if (
            self.config.reporting.weekly_report_enabled
            and now.isoweekday() % 7 == self.config.reporting.weekly_report_day
            and not self._was_delivered("weekly", weekly_key)
        ):
            alerts.append(self._build_report("Weekly", 24 * 7, weekly_key))
            self._mark_delivered("weekly", weekly_key)
        return alerts

    def _was_delivered(self, frequency: str, key: str) -> bool:
        if key in self._delivered:
            return True
        return self.db.get_app_state(f"report_last_{frequency}") == key

    def _mark_delivered(self, frequency: str, key: str) -> None:
        self.db.set_app_state(f"report_last_{frequency}", key)
        self._delivered.add(key)

    def _build_report(self, label: str, hours: int, key: str) -> Alert:
        since = clock.now() - timedelta(hours=hours)
        recent = self.db.get_recent_alerts(limit=10_000, since=since)
        severities: dict[str, int] = {}
        for alert in recent:
            severities[alert.severity.value] = severities.get(alert.severity.value, 0) + 1
        return Alert(
            severity=Severity.INFO,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title=f"{label} SentinelPi security report",
            description=(
                f"{len(recent)} alerts and {self.device_tracker.get_device_count()} known devices "
                f"in the last {hours} hours."
            ),
            recommended_action="Review elevated alerts and newly observed devices.",
            confidence=1.0,
            confidence_rationale="Generated from SentinelPi's local audit database.",
            dedup_key=f"scheduled_report:{key}",
            extra={
                "period_hours": hours,
                "total_alerts": len(recent),
                "alerts_by_severity": severities,
                "total_known_devices": self.device_tracker.get_device_count(),
                "baseline_summary": self.baseline.get_summary(),
            },
        )
