"""
responders/manager.py - Orchestrates responders with safety gating + approval.

The ResponderManager is the *only* component that decides whether an action
actually runs. Responders just describe what they could do; the manager applies
the layered safety model:

    plan only        ⇐  master off (response.enabled false): nothing planned
    plan + record    ⇐  dry_run: decide and log, never execute
    await approval   ⇐  armed + require_approval (and category not auto-trusted)
    execute          ⇐  armed + (not require_approval OR category auto-trusted)

So even an *armed* responder holds risky actions as PENDING for one-click human
approval, unless the operator has explicitly added the alert's category to
``auto_execute_categories``. Dry-run remains the honest default: you can watch
decisions for days before arming, then arm with a human in the loop before
finally trusting specific categories to fire on their own.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime
from typing import Callable, Deque, Dict, List, Optional, Tuple

from .base import BaseResponder, ResponderAction, PLANNED, PENDING, EXECUTED, FAILED, REJECTED
from ..models import Alert

logger = logging.getLogger(__name__)


class ResponderManager:
    """Runs applicable responders for an alert, under explicit safety gating."""

    def __init__(self, config, db=None) -> None:
        self.config = config
        self._db = db
        self._responders: List[BaseResponder] = []
        self._lock = threading.Lock()
        # Recent actions (any status) for the dashboard / audit.
        self._recent: Deque[ResponderAction] = deque(maxlen=200)
        # action_id → (action, responder) for actions awaiting approval.
        self._pending: Dict[str, Tuple[ResponderAction, BaseResponder]] = {}
        # Pending rows are rehydrated before responders are registered; bind
        # them by responder name as add_responder() is called.
        self._unbound_pending: Dict[str, ResponderAction] = {}
        # Optional callback fired when an action is queued for approval, so an
        # actionable notifier (e.g. ntfy) can push Approve/Reject buttons.
        self._pending_notifier: Optional[Callable[[ResponderAction], None]] = None
        self._load_actions()

    def add_responder(self, responder: BaseResponder) -> None:
        with self._lock:
            self._responders.append(responder)
            for action_id, action in list(self._unbound_pending.items()):
                if action.responder == responder.name:
                    self._pending[action_id] = (action, responder)
                    del self._unbound_pending[action_id]
        logger.debug("Registered responder: %s", responder.name)

    def _load_actions(self) -> None:
        """Rehydrate recent history and pending approvals from the database."""
        if self._db is None:
            return
        try:
            rows = self._db.get_response_actions(limit=self._recent.maxlen or 200)
        except Exception as exc:
            logger.error("Failed to load responder action history: %s", exc)
            return
        for row in rows:
            try:
                action = self._action_from_row(row)
            except (TypeError, ValueError) as exc:
                logger.warning("Skipping invalid persisted responder action: %s", exc)
                continue
            self._recent.append(action)
            if action.status == PENDING:
                self._unbound_pending[action.action_id] = action

    @staticmethod
    def _action_from_row(row: dict) -> ResponderAction:
        import json

        return ResponderAction(
            responder=str(row["responder"]),
            target=str(row["target"]),
            description=str(row["description"]),
            commands=json.loads(row["commands"] or "[]"),
            action_id=str(row["action_id"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            status=str(row["status"]),
            dry_run=bool(row["dry_run"]),
            executed=bool(row["executed"]),
            success=bool(row["success"]),
            error=str(row["error"] or ""),
            alert_id=str(row["alert_id"] or ""),
        )

    def _persist(self, action: ResponderAction) -> None:
        if self._db is None:
            return
        try:
            self._db.save_response_action(action)
        except Exception as exc:
            logger.error("Failed to persist responder action %s: %s", action.action_id, exc)

    def set_pending_notifier(self, callback: Callable[[ResponderAction], None]) -> None:
        """Register a callback invoked with each action newly queued for approval."""
        self._pending_notifier = callback

    def handle(self, alert: Alert) -> List[ResponderAction]:
        """
        Plan, and depending on gating dry-run / queue-for-approval / execute,
        responses for ``alert``. Returns the actions. A no-op returning [] when
        the master switch is off — nothing is even planned, fully inert.
        """
        rc = self.config.response
        if not rc.enabled:
            return []

        dry_run = rc.dry_run
        actions: List[ResponderAction] = []

        for responder in list(self._responders):
            try:
                if not responder.can_handle(alert):
                    continue
                action = responder.plan(alert)
                if action is None:
                    continue
                action.dry_run = dry_run
                action.alert_id = alert.alert_id

                if dry_run:
                    action.status = PLANNED
                    logger.warning("[DRY-RUN] %s would act on %s: %s",
                                   responder.name, action.target, action.description)
                elif self._needs_approval(alert):
                    action.status = PENDING
                    with self._lock:
                        self._pending[action.action_id] = (action, responder)
                    logger.warning("[PENDING APPROVAL] %s on %s (%s): %s",
                                   responder.name, action.target, action.action_id, action.description)
                    if self._pending_notifier is not None:
                        try:
                            self._pending_notifier(action)
                        except Exception as exc:
                            logger.error("Pending-action notifier failed for %s: %s",
                                         action.action_id, exc)
                else:
                    self._run(action, responder)

                actions.append(action)
                self._persist(action)
            except Exception as exc:
                logger.error("Responder %s failed on alert %s: %s", responder.name, alert.alert_id, exc)

        if actions:
            with self._lock:
                self._recent.extend(actions)
        return actions

    def _needs_approval(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.require_approval:
            return False
        # Categories the operator has explicitly trusted bypass approval.
        return alert.category.value not in rc.auto_execute_categories

    def _run(self, action: ResponderAction, responder: BaseResponder) -> None:
        responder.execute(action)
        action.status = EXECUTED if action.success else FAILED
        self._persist(action)

    # ------------------------------------------------------------- approvals
    def approve(self, action_id: str) -> Optional[ResponderAction]:
        """Execute a pending action. Returns it (updated), or None if unknown."""
        with self._lock:
            entry = self._pending.pop(action_id, None)
        if entry is None:
            return None
        action, responder = entry
        logger.warning("Approved action %s — executing %s on %s.",
                       action_id, responder.name, action.target)
        self._run(action, responder)
        return action

    def reject(self, action_id: str) -> Optional[ResponderAction]:
        """Discard a pending action without executing it."""
        with self._lock:
            entry = self._pending.pop(action_id, None)
        if entry is None:
            return None
        action, _ = entry
        action.status = REJECTED
        self._persist(action)
        logger.info("Rejected action %s (%s on %s).", action_id, action.responder, action.target)
        return action

    def pending_actions(self) -> List[ResponderAction]:
        with self._lock:
            return [a for a, _ in self._pending.values()]

    def recent_actions(self, limit: int = 50) -> List[ResponderAction]:
        with self._lock:
            items = list(self._recent)
        return items[-limit:]
