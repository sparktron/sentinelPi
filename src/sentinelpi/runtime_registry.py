"""Shared runtime component manifest and live capability state."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .utils import clock


@dataclass(frozen=True)
class ComponentDefinition:
    """Static configuration and routing metadata for one runtime component."""

    key: str
    label: str
    kind: str
    configured: bool
    routes: Tuple[str, ...] = ()
    poll_interval: Optional[int] = None


def component_manifest(config) -> List[ComponentDefinition]:
    """Return the ordered capability matrix for an effective configuration."""
    m = config.monitoring
    n = config.notifications
    r = config.response
    f = config.flow
    reports_enabled = (
        config.reporting.daily_report_enabled or config.reporting.weekly_report_enabled
    )
    event_router_enabled = (
        m.packet_capture_enabled
        or f.conntrack_enabled
        or f.netflow_enabled
        or f.filterlog_enabled
    )
    return [
        ComponentDefinition("input:packet_capture", "PacketCapture", "input", m.packet_capture_enabled),
        ComponentDefinition("input:conntrack", "ConntrackFlowSource", "input", f.conntrack_enabled),
        ComponentDefinition("input:netflow", "NetFlowCollector", "input", f.netflow_enabled),
        ComponentDefinition("input:filterlog", "FilterlogSource", "input", f.filterlog_enabled),
        ComponentDefinition("input:honeypot", "HoneypotService", "input", m.honeypot_enabled),
        ComponentDefinition(
            "inventory:device_tracker", "DeviceTracker", "inventory", True,
            routes=("poll",), poll_interval=30,
        ),
        ComponentDefinition(
            "detector:arp", "ARPDetector", "detector", True,
            routes=("event", "poll"), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:beacon", "BeaconDetector", "detector", True,
            routes=("event", "poll"), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:connection", "ConnectionDetector", "detector", True,
            routes=("event", "poll"), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:port_scan", "PortScanDetector", "detector", True,
            routes=("event", "poll"), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:dns", "DNSDetector", "detector", m.dns_monitoring_enabled,
            routes=("event",),
        ),
        ComponentDefinition(
            "detector:lateral_movement", "LateralMovementDetector", "detector", True,
            routes=("event", "poll"), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:auth_log", "AuthLogDetector", "detector", m.auth_log_enabled,
            routes=("poll",), poll_interval=30,
        ),
        ComponentDefinition(
            "detector:traffic_spike", "TrafficSpikeDetector", "detector", True,
            routes=("poll",), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:doh", "DoHDetector", "detector", m.doh_detection_enabled,
            routes=("event",),
        ),
        ComponentDefinition(
            "detector:geo_country", "GeoCountryDetector", "detector", m.geo_enabled,
            routes=("event",),
        ),
        ComponentDefinition(
            "detector:asn", "ASNReputationDetector", "detector", m.asn_reputation_enabled,
            routes=("event",),
        ),
        ComponentDefinition(
            "detector:active_hours", "ActiveHoursDetector", "detector",
            m.active_hours_detection_enabled, routes=("event",),
        ),
        ComponentDefinition(
            "detector:host_profile", "HostProfileDetector", "detector",
            m.host_profile_detection_enabled, routes=("event",),
        ),
        ComponentDefinition(
            "detector:threat_intel", "ThreatIntelDetector", "detector",
            config.threat_intel.enabled, routes=("event",),
        ),
        ComponentDefinition(
            "detector:file_integrity", "FileIntegrityDetector", "detector",
            m.file_integrity_enabled, routes=("poll",), poll_interval=60,
        ),
        ComponentDefinition(
            "detector:incident_correlator", "IncidentCorrelator", "detector",
            config.correlation.enabled,
        ),
        ComponentDefinition(
            "input:active_discovery", "ActiveDiscovery", "input", m.active_discovery_enabled,
            routes=("poll",), poll_interval=m.active_discovery_interval_seconds,
        ),
        ComponentDefinition(
            "service:reports", "ReportScheduler", "service", reports_enabled,
            routes=("poll",), poll_interval=60,
        ),
        ComponentDefinition("notifier:console", "ConsoleNotifier", "notifier", True),
        ComponentDefinition("notifier:file", "FileNotifier", "notifier", True),
        ComponentDefinition("notifier:email", "EmailNotifier", "notifier", n.email_enabled),
        ComponentDefinition(
            "notifier:webhook", "WebhookNotifier", "notifier",
            n.webhook_enabled and bool(n.webhook_url),
        ),
        ComponentDefinition(
            "notifier:ntfy", "NtfyNotifier", "notifier",
            n.ntfy_enabled and bool(n.ntfy_topic),
        ),
        ComponentDefinition("notifier:sms", "TwilioSMSNotifier", "notifier", n.sms_enabled),
        ComponentDefinition(
            "notifier:siem", "SyslogNotifier", "notifier",
            n.siem_enabled and bool(n.siem_host),
        ),
        ComponentDefinition(
            "notifier:otlp", "OTLPNotifier", "notifier",
            n.otlp_enabled and bool(n.otlp_endpoint),
        ),
        ComponentDefinition(
            "notifier:forward", "ForwardNotifier", "notifier",
            config.cluster.role == "sensor" and bool(config.cluster.collector_url),
        ),
        ComponentDefinition(
            "responder:firewall", "FirewallResponder", "responder",
            r.enabled and r.firewall_block_enabled,
        ),
        ComponentDefinition(
            "responder:dns_sinkhole", "DNSSinkholeResponder", "responder",
            r.enabled and r.dns_sinkhole_enabled,
        ),
        ComponentDefinition(
            "responder:arp_restore", "ARPRestoreResponder", "responder",
            r.enabled and r.arp_restore_enabled,
        ),
        ComponentDefinition(
            "responder:killswitch", "KillSwitchResponder", "responder",
            r.enabled and r.killswitch_enabled,
        ),
        ComponentDefinition("service:dashboard", "DashboardServer", "service", config.dashboard.enabled),
        ComponentDefinition("service:event_router", "EventRouter", "service", event_router_enabled),
        ComponentDefinition(
            "service:watchdog", "OperationalWatchdog", "service", m.self_monitoring_enabled
        ),
        ComponentDefinition(
            "service:threat_intel_refresh", "ThreatIntelRefresh", "service",
            config.threat_intel.enabled,
        ),
        ComponentDefinition(
            "service:collector_ingest", "CollectorIngest", "service",
            bool(config.cluster.collector_key),
        ),
    ]


class RuntimeComponentRegistry:
    """Bind live component state and activity to the shared static manifest."""

    def __init__(self, config) -> None:
        self._lock = threading.RLock()
        self._definitions = {item.key: item for item in component_manifest(config)}
        self._instances: Dict[str, Any] = {}
        self._state: Dict[str, str] = {
            key: "configured" if item.configured else "disabled"
            for key, item in self._definitions.items()
        }
        self._detail: Dict[str, str] = {}
        self._activity_count: Dict[str, int] = {}
        self._last_activity: Dict[str, str] = {}

    def attach(self, key: str, instance: Any) -> None:
        if instance is None:
            return
        with self._lock:
            self._require(key)
            self._instances[key] = instance
            if self._definitions[key].configured:
                self._state[key] = "ready"

    def mark_started(self, key: str, detail: str = "") -> None:
        with self._lock:
            self._require(key)
            if self._definitions[key].configured:
                self._state[key] = "started"
                self._detail[key] = detail

    def mark_degraded(self, key: str, detail: str) -> None:
        with self._lock:
            self._require(key)
            if self._definitions[key].configured:
                self._state[key] = "degraded"
                self._detail[key] = detail

    def mark_stopped(self, key: str) -> None:
        with self._lock:
            self._require(key)
            if self._definitions[key].configured:
                self._state[key] = "stopped"

    def mark_all_stopped(self) -> None:
        """Mark every configured component that reached runtime as stopped."""
        with self._lock:
            for key, item in self._definitions.items():
                if item.configured and (
                    key in self._instances or self._state[key] in {"ready", "started", "degraded"}
                ):
                    self._state[key] = "stopped"

    def record_activity(self, key: str, count: int = 1) -> None:
        with self._lock:
            self._require(key)
            self._activity_count[key] = self._activity_count.get(key, 0) + max(0, count)
            self._last_activity[key] = clock.now().isoformat()

    def record_instance_activity(self, instance: Any, count: int = 1) -> None:
        with self._lock:
            for key, candidate in self._instances.items():
                if candidate is instance:
                    self.record_activity(key, count)
                    return

    def routed_instances(self, route: str) -> List[Any]:
        with self._lock:
            return [
                self._instances[key]
                for key, item in self._definitions.items()
                if item.configured and route in item.routes and key in self._instances
            ]

    def pollers(self) -> List[Tuple[Any, int, str, str]]:
        with self._lock:
            return [
                (self._instances[key], item.poll_interval or 60, item.label, key)
                for key, item in self._definitions.items()
                if item.configured
                and "poll" in item.routes
                and item.poll_interval is not None
                and key in self._instances
            ]

    def key_for_instance(self, instance: Any) -> Optional[str]:
        with self._lock:
            for key, candidate in self._instances.items():
                if candidate is instance:
                    return key
        return None

    def snapshot(self) -> List[dict]:
        with self._lock:
            snapshot = []
            for key, item in self._definitions.items():
                instance = self._instances.get(key)
                instance_activity = getattr(instance, "emitted", 0)
                activity_count = max(
                    self._activity_count.get(key, 0),
                    instance_activity if isinstance(instance_activity, int) else 0,
                )
                snapshot.append({
                    "key": key,
                    "label": item.label,
                    "kind": item.kind,
                    "configured": item.configured,
                    "state": self._state[key],
                    "routes": list(item.routes),
                    "poll_interval": item.poll_interval,
                    "activity_count": activity_count,
                    "last_activity": self._last_activity.get(key),
                    "detail": self._detail.get(key, ""),
                })
            return snapshot

    def _require(self, key: str) -> None:
        if key not in self._definitions:
            raise KeyError(f"unknown runtime component: {key}")
