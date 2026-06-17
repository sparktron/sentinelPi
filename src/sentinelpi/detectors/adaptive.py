"""
detectors/adaptive.py - Per-host adaptive thresholds.

Fixed global thresholds force a trade-off: set them tight and a chronically
chatty host floods the operator with false positives; set them loose and a
quiet host's genuine anomaly slips under the bar. Adaptive thresholds break that
trade-off per host instead of globally.

For each ``(signal, host)`` we track recent *trips* (times the host actually
raised that signal's alert). A host that keeps tripping the same signal is
treated as chronically noisy: its effective threshold is scaled up by a capped
multiplier, so it must clear a higher bar to alert again. Trips age out of a
sliding window, so the multiplier decays back to ``1.0`` once the host goes
quiet. The multiplier is never below ``1.0``, so a quiet host always sees the
full global sensitivity — adaptation only ever *raises* a noisy host's bar, it
never blinds a calm one.

This lets a noisy network settle on its own without the operator lowering global
sensitivity (and thereby dulling every other host).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Tuple

_Key = Tuple[str, str]  # (signal, host)

# Cap the number of tracked (signal, host) keys so a churny network can't grow
# this unbounded. Empty deques are dropped on access; this is the hard ceiling.
_MAX_KEYS = 8192


class AdaptiveThresholds:
    """Per-host multiplicative backoff for rate-based detector thresholds."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        trips_before_backoff: int = 5,
        window_seconds: int = 3600,
        step: float = 0.5,
        max_multiplier: float = 4.0,
    ) -> None:
        self.enabled = enabled
        self.trips_before_backoff = trips_before_backoff
        self.window = timedelta(seconds=window_seconds)
        self.step = step
        self.max_multiplier = max_multiplier
        self._trips: Dict[_Key, Deque[datetime]] = defaultdict(deque)

    @classmethod
    def from_config(cls, config) -> "AdaptiveThresholds":
        m = config.monitoring
        return cls(
            enabled=m.adaptive_thresholds_enabled,
            trips_before_backoff=m.adaptive_threshold_trips_before_backoff,
            window_seconds=m.adaptive_threshold_window_seconds,
            step=m.adaptive_threshold_step,
            max_multiplier=m.adaptive_threshold_max_multiplier,
        )

    def _recent_trips(self, key: _Key, now: datetime) -> int:
        """Prune trips outside the window and return how many remain."""
        dq = self._trips.get(key)
        if dq is None:
            return 0
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            # Drop the now-empty key so idle hosts don't accumulate.
            del self._trips[key]
            return 0
        return len(dq)

    def multiplier(self, signal: str, host: str, now: datetime) -> float:
        """
        Current threshold multiplier for ``(signal, host)`` (>= 1.0).

        Stays 1.0 until the host has tripped ``trips_before_backoff`` times in
        the window, then grows by ``step`` per extra trip up to ``max_multiplier``.
        """
        if not self.enabled:
            return 1.0
        count = self._recent_trips((signal, host), now)
        if count < self.trips_before_backoff:
            return 1.0
        excess = count - self.trips_before_backoff + 1
        return min(self.max_multiplier, 1.0 + self.step * excess)

    def effective(self, signal: str, host: str, base: float, now: datetime) -> float:
        """Return ``base`` scaled by the current per-host multiplier."""
        return base * self.multiplier(signal, host, now)

    def record_trip(self, signal: str, host: str, now: datetime) -> None:
        """Record that ``host`` raised ``signal``'s alert (drives future backoff)."""
        if not self.enabled:
            return
        # Opportunistic global cap: if we're at the ceiling, evict the oldest-keyed
        # idle entries by pruning. (Most keys self-empty via the sliding window.)
        if len(self._trips) >= _MAX_KEYS:
            for k in list(self._trips.keys()):
                self._recent_trips(k, now)
                if len(self._trips) < _MAX_KEYS:
                    break
        self._trips[(signal, host)].append(now)
