"""Durable response-action ledger and restart rehydration tests."""

from __future__ import annotations

from sentinelpi.models import Alert, AlertCategory, Severity
from sentinelpi.responders.base import EXECUTED, PENDING, REJECTED
from sentinelpi.responders.firewall import FirewallResponder
from sentinelpi.responders.manager import ResponderManager


class _RecordingRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return 0, ""


def _arm(config) -> None:
    config.response.enabled = True
    config.response.dry_run = False
    config.response.firewall_block_enabled = True
    config.response.require_approval = True


def _alert() -> Alert:
    return Alert(
        severity=Severity.HIGH,
        category=AlertCategory.THREAT_INTEL,
        affected_host="192.168.1.50",
        related_host="45.9.148.99",
        title="known bad",
    )


def test_pending_action_rehydrates_and_can_be_approved(config, db):
    _arm(config)
    first_runner = _RecordingRunner()
    first = ResponderManager(config, db)
    first.add_responder(FirewallResponder(config, runner=first_runner))

    action = first.handle(_alert())[0]
    assert action.status == PENDING
    assert first_runner.calls == []

    restarted_runner = _RecordingRunner()
    restarted = ResponderManager(config, db)
    restarted.add_responder(FirewallResponder(config, runner=restarted_runner))

    assert [item.action_id for item in restarted.pending_actions()] == [action.action_id]
    approved = restarted.approve(action.action_id)
    assert approved is not None
    assert approved.status == EXECUTED
    assert restarted_runner.calls

    after_execution = ResponderManager(config, db)
    persisted = {item.action_id: item for item in after_execution.recent_actions()}
    assert persisted[action.action_id].status == EXECUTED
    assert persisted[action.action_id].success is True


def test_rejection_is_persisted(config, db):
    _arm(config)
    manager = ResponderManager(config, db)
    manager.add_responder(FirewallResponder(config, runner=_RecordingRunner()))
    action = manager.handle(_alert())[0]

    rejected = manager.reject(action.action_id)
    assert rejected is not None
    assert rejected.status == REJECTED

    restarted = ResponderManager(config, db)
    persisted = {item.action_id: item for item in restarted.recent_actions()}
    assert persisted[action.action_id].status == REJECTED
    assert restarted.pending_actions() == []
