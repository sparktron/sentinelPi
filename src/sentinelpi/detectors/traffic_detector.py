"""Per-interface traffic-volume anomaly polling."""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

from .base import BaseDetector
from ..capture.proc_reader import InterfaceStats, read_interface_stats
from ..models import Alert, AlertCategory, Evidence, Severity, explain


class TrafficSpikeDetector(BaseDetector):
    """Convert kernel byte counters to bytes/minute and compare with the baseline."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._previous: Dict[str, Tuple[float, int]] = {}

    def _poll(self) -> List[Alert]:
        now = time.monotonic()
        stats = read_interface_stats()
        alerts: List[Alert] = []
        for interface in self.config.network.interfaces:
            sample = stats.get(interface)
            if sample is None:
                continue
            total_bytes = sample.rx_bytes + sample.tx_bytes
            previous = self._previous.get(interface)
            self._previous[interface] = (now, total_bytes)
            if previous is None:
                continue
            previous_time, previous_bytes = previous
            elapsed = now - previous_time
            if elapsed <= 0 or total_bytes < previous_bytes:
                continue
            bytes_per_minute = (total_bytes - previous_bytes) * 60.0 / elapsed
            is_spike, z_score = self.baseline.check_traffic_spike(interface, bytes_per_minute)
            self.baseline.record_traffic(interface, bytes_per_minute)
            if not is_spike:
                continue
            alerts.append(self._build_alert(interface, bytes_per_minute, z_score, sample))
        return alerts

    def _build_alert(
        self,
        interface: str,
        bytes_per_minute: float,
        z_score: float,
        sample: InterfaceStats,
    ) -> Alert:
        factor = self.config.thresholds.traffic_spike_factor
        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.TRAFFIC_SPIKE,
            affected_host=interface,
            title=f"Traffic spike detected on {interface}",
            description=(
                f"Interface {interface} transferred {bytes_per_minute:,.0f} bytes/minute, "
                f"exceeding its learned traffic baseline."
            ),
            recommended_action="Review active connections and large transfers on this interface.",
            confidence=min(0.6 + max(z_score, 0.0) * 0.05, 0.95),
            confidence_rationale=f"Observed rate exceeded the learned baseline (z={z_score:.2f}).",
            dedup_key=f"traffic_spike:{interface}",
            extra={
                "rx_bytes": sample.rx_bytes,
                "tx_bytes": sample.tx_bytes,
                **explain(
                    Evidence(
                        metric="bytes_per_minute",
                        observed=round(bytes_per_minute, 2),
                        threshold=f"{factor}x learned mean or z-score anomaly",
                        comparison=">",
                        baseline="per-interface traffic volume",
                    ),
                    confidence_basis="Rate compared with the learned interface baseline.",
                ),
            },
        )
