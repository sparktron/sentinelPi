"""
detectors/host_profile_detector.py - Per-host behavioural profiling.

The sibling of :class:`ActiveHoursDetector`: instead of *when* a host is active,
this learns *what a host normally does* and flags the first off-profile action.
Four dimensions, all keyed to the host's own history (not a global baseline):

- ``dst_port``: the destination ports a local host normally connects to. A
  daytime laptop that has only ever used 80/443/53 suddenly opening 445 (SMB)
  or 22 (SSH) outbound is a strong lateral-movement / compromise tell.
- ``peer``: the *internal* hosts a local host normally talks to. The first time
  a workstation connects to an internal server it has never contacted is the
  slow, deliberate cousin of the burst that :class:`LateralMovementDetector`
  catches.
- ``protocol``: the L4 protocols (tcp/udp/icmp) a host normally uses. A host
  that has only spoken TCP/UDP suddenly using ICMP can indicate tunneling.
- ``byte_range``: the per-flow transfer-size buckets a host normally produces.
  A sudden much larger transfer from a host that only sent small flows is a
  possible exfiltration tell. Only learned when a flow source supplies byte
  counts (NetFlow); SYN-only capture and conntrack leave size 0, so the
  dimension simply stays dormant there.

External peers are deliberately not profiled — their cardinality is unbounded
(CDNs, ad networks) and carries little host-specific signal; destination *ports*
already capture the interesting external behaviour at low cardinality.

Like active-hours, each dimension stays quiet until the host has an established
profile (``host_profile_min_known_*`` distinct values) and during the global
learning phase, so a forming profile doesn't alert on every first-of-its-kind
value. State is persisted per host so the profile survives restarts.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Evidence, Severity, explain

logger = logging.getLogger(__name__)

_DIM_PORT = "dst_port"
_DIM_PEER = "peer"
_DIM_PROTO = "protocol"
_DIM_BYTES = "byte_range"

# Ordered byte-size buckets (upper bound in bytes, label). A per-flow size is
# mapped to the first bucket it fits in; the top bucket is open-ended. Used as
# discrete profile values so a new, larger-than-usual transfer size stands out.
_BYTE_BUCKETS: list[tuple[float, str]] = [
    (1_000, "0-1K"),
    (10_000, "1K-10K"),
    (100_000, "10K-100K"),
    (1_000_000, "100K-1M"),
    (10_000_000, "1M-10M"),
    (float("inf"), "10M+"),
]


def _byte_bucket(size: int) -> str:
    """Map a byte count to its discrete size-bucket label."""
    for upper, label in _BYTE_BUCKETS:
        if size < upper:
            return label
    return _BYTE_BUCKETS[-1][1]


class HostProfileDetector(BaseDetector):
    """Flags a local host acting outside its own learned port / peer / protocol / size profile."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._min_known_ports = self.config.monitoring.host_profile_min_known_ports
        self._min_known_peers = self.config.monitoring.host_profile_min_known_peers
        self._min_known_protocols = self.config.monitoring.host_profile_min_known_protocols
        self._min_known_byte_ranges = self.config.monitoring.host_profile_min_known_byte_ranges
        # (ip, dimension) -> set of values seen; seeded lazily from the DB.
        self._seen: Dict[Tuple[str, str], Set[str]] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []
        src = event.src_ip
        if not src or not self._is_local_ip(src):
            return []

        alerts: List[Alert] = []
        # Destination port (against any destination — low cardinality).
        if event.dst_port:
            alerts += self._observe(
                src, _DIM_PORT, str(event.dst_port), self._min_known_ports
            )
        # Internal peer only (bounded by LAN size, high lateral-movement signal).
        if event.dst_ip and self._is_local_ip(event.dst_ip) and event.dst_ip != src:
            alerts += self._observe(
                src, _DIM_PEER, event.dst_ip, self._min_known_peers
            )
        # Protocol mix (tcp/udp/icmp) — very low cardinality; a new protocol is
        # a strong tell (e.g. ICMP tunneling from a host that only spoke TCP/UDP).
        if event.protocol:
            alerts += self._observe(
                src, _DIM_PROTO, event.protocol, self._min_known_protocols
            )
        # Per-flow byte-size bucket — only when a flow source supplies a size
        # (NetFlow); SYN-only capture and conntrack leave size 0.
        if event.size and event.size > 0:
            alerts += self._observe(
                src, _DIM_BYTES, _byte_bucket(event.size), self._min_known_byte_ranges
            )
        return alerts

    def _observe(self, src: str, dimension: str, value: str, min_known: int) -> List[Alert]:
        """Record one (host, dimension, value); alert if it's off an established profile."""
        cache_key = (src, dimension)
        seen = self._seen.get(cache_key)
        if seen is None:
            seen = self.db.get_host_profile_values(src, dimension)
            self._seen[cache_key] = seen

        if value in seen:
            return []  # already part of this host's profile

        established = len(seen) >= min_known
        seen.add(value)
        self.db.record_host_profile_value(src, dimension, value)

        # Quiet while the profile is still forming or during global learning.
        if not established or self.baseline.is_learning:
            return []

        return self._build_alert(src, dimension, value, len(seen) - 1)

    def _build_alert(self, src: str, dimension: str, value: str, known: int) -> List[Alert]:
        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname
        who = f"{src}{' (' + hostname + ')' if hostname else ''}"

        if dimension == _DIM_PORT:
            title = f"Off-profile destination port for {who}: {value}"
            description = (
                f"{src} opened a connection to destination port {value} — a port it has "
                f"never used before (its profile spans {known} other ports). A host suddenly "
                "using an unfamiliar service port (e.g. SMB/445, SSH/22, RDP/3389) can indicate "
                "lateral movement or a compromised process."
            )
            action = (
                f"Confirm what on {src} is connecting on port {value} and whether that service "
                "is expected for this device."
            )
            rationale = f"First connection from {src} to destination port {value}."
        elif dimension == _DIM_PROTO:
            title = f"Off-profile protocol for {who}: {value}"
            description = (
                f"{src} used the {value.upper()} protocol for the first time (its profile spans "
                f"{known} other protocol(s)). A host that has only ever spoken TCP/UDP suddenly "
                "using ICMP can indicate tunneling or an unexpected new service."
            )
            action = (
                f"Confirm what on {src} is using {value.upper()} and whether that is expected "
                "for this device."
            )
            rationale = f"First {value.upper()} traffic observed from {src}."
        elif dimension == _DIM_BYTES:
            title = f"Off-profile transfer size for {who}: {value}"
            description = (
                f"{src} produced a flow in the {value} byte range — a transfer size it has not "
                f"shown before (its profile spans {known} other size range(s)). A sudden much "
                "larger transfer from a host that only ever sent small flows can indicate "
                "data exfiltration."
            )
            action = (
                f"Confirm what on {src} produced a {value} transfer and whether that volume is "
                "expected (a backup/sync is benign; unexplained bulk egress is not)."
            )
            rationale = f"First {value} byte-range flow observed from {src}."
        else:  # _DIM_PEER
            peer_name = ""
            peer_device = self.device_tracker.get_device(value)
            if peer_device:
                peer_name = peer_device.hostname
            peer_who = f"{value}{' (' + peer_name + ')' if peer_name else ''}"
            title = f"Off-profile internal peer for {who}: {peer_who}"
            description = (
                f"{src} connected to internal host {peer_who} for the first time (its profile "
                f"spans {known} other internal peers). A device reaching a LAN peer it has never "
                "talked to is a classic slow lateral-movement signal."
            )
            action = (
                f"Confirm whether {src} is expected to talk to {value} (a new service or share "
                "is benign; unexplained internal traffic is not)."
            )
            rationale = f"First internal connection from {src} to peer {value}."

        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=src,
            related_host=value if dimension == _DIM_PEER else "",
            title=title,
            description=description,
            recommended_action=action,
            confidence=0.5,
            confidence_rationale=rationale,
            dedup_key=f"hostprofile:{dimension}:{src}:{value}",
            extra={
                "dimension": dimension,
                "value": value,
                "known": known,
                "explanation": explain(
                    Evidence(
                        metric=f"host_{dimension}",
                        observed=value,
                        comparison="not-in-profile",
                        baseline=f"{known} {dimension} value(s) learned for this host",
                    ),
                    confidence_basis="fixed 0.5 for a first off-profile value on an established dimension",
                ),
            },
        )]
