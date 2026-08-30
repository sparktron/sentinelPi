"""Durable health tracking for safety-critical persistence paths."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict

from . import clock

logger = logging.getLogger(__name__)


class DurablePersistenceHealth:
    """Track a persistence path's degraded/recovered state in ``app_state``."""

    def __init__(self, db: Any, key: str) -> None:
        self._db = db
        self._key = key
        self._lock = threading.Lock()
        self._state = self._healthy_state()
        if db is None:
            return
        try:
            raw = db.get_app_state(key)
            if raw:
                stored = json.loads(raw)
                if isinstance(stored, dict):
                    self._state.update(stored)
        except Exception as exc:
            self._state = self._failed_state(exc, 1)
            logger.critical("Failed to load durable persistence health %s: %s", key, exc)

    @staticmethod
    def _healthy_state() -> Dict[str, object]:
        return {
            "degraded": False,
            "consecutive_failures": 0,
            "failed_at": None,
            "last_error": "",
            "recovered_at": None,
        }

    @staticmethod
    def _failed_state(exc: Exception, failures: int) -> Dict[str, object]:
        return {
            "degraded": True,
            "consecutive_failures": failures,
            "failed_at": clock.now().isoformat(),
            "last_error": str(exc)[:500],
            "recovered_at": None,
        }

    @property
    def status(self) -> Dict[str, object]:
        with self._lock:
            return dict(self._state)

    def mark_failed(self, exc: Exception) -> None:
        """Record a failure in memory, logs, and durable state when possible."""
        with self._lock:
            previous_failures = self._state.get("consecutive_failures", 0)
            failures = previous_failures + 1 if isinstance(previous_failures, int) else 1
            self._state = self._failed_state(exc, failures)
            state = dict(self._state)
        logger.critical("Persistence path %s is degraded: %s", self._key, exc)
        self._store(state)

    def mark_succeeded(self) -> None:
        """Record recovery while retaining the last failure for audit context."""
        with self._lock:
            if not self._state.get("degraded"):
                return
            recovered = dict(self._state)
            recovered["degraded"] = False
            recovered["consecutive_failures"] = 0
            recovered["recovered_at"] = clock.now().isoformat()
        if self._store(recovered):
            with self._lock:
                self._state = recovered

    def _store(self, state: Dict[str, object]) -> bool:
        if self._db is None:
            return True
        try:
            self._db.set_app_state(self._key, json.dumps(state, sort_keys=True))
            return True
        except Exception as exc:
            logger.critical("Failed to store durable persistence health %s: %s", self._key, exc)
            return False
