"""Durable response-action ledger and restart rehydration tests."""

from __future__ import annotations

from sentinelpi.models import Alert, AlertCategory, Severity
import pytest

from sentinelpi.responders.base import EXECUTED, EXPIRED, FAILED, PENDING, PLANNED, REJECTED
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


@pytest.mark.parametrize("failed_write", [1, 2])
def test_response_does_not_execute_without_durable_audit_plan(
    config, db, monkeypatch, failed_write
):
    """Both the plan and pre-execution intent are fail-closed persistence gates."""
    _arm(config)
    config.response.require_approval = False
    runner = _RecordingRunner()
    manager = ResponderManager(config, db)
    manager.add_responder(FirewallResponder(config, runner=runner))
    save_response_action = db.save_response_action
    writes = 0

    def fail_selected_write(action):
        nonlocal writes
        writes += 1
        if writes == failed_write:
            raise RuntimeError("database unavailable")
        save_response_action(action)

    monkeypatch.setattr(db, "save_response_action", fail_selected_write)

    action = manager.handle(_alert())[0]

    assert action.status == FAILED
    assert "persist" in action.error
    assert runner.calls == []
    assert manager.persistence_health["degraded"] is True

    persisted = next(
        (
            row
            for row in db.get_response_actions()
            if row["action_id"] == action.action_id
        ),
        None,
    )
    if failed_write == 1:
        assert persisted is None
    else:
        assert persisted is not None
        assert persisted["status"] == PLANNED

    restarted = ResponderManager(config, db)
    assert restarted.persistence_health["degraded"] is True


def test_timed_firewall_action_expires_after_restart(config, db):
    from datetime import datetime, timedelta, timezone
    from sentinelpi.utils import clock

    _arm(config)
    config.response.require_approval = False
    config.response.block_duration_seconds = 60
    started = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)

    first_runner = _RecordingRunner()
    with clock.use_clock(clock.FixedClock(started)):
        first = ResponderManager(config, db)
        first.add_responder(FirewallResponder(config, runner=first_runner))
        action = first.handle(_alert())[0]

    assert action.status == EXECUTED
    assert action.expires_at == started + timedelta(seconds=60)

    restart_runner = _RecordingRunner()
    with clock.use_clock(clock.FixedClock(started + timedelta(seconds=61))):
        restarted = ResponderManager(config, db)
        restarted.add_responder(FirewallResponder(config, runner=restart_runner))

    persisted = {item.action_id: item for item in restarted.recent_actions()}
    assert persisted[action.action_id].status == EXPIRED
    assert any(argv[1] == "-D" for argv in restart_runner.calls)


def test_nftables_expiry_uses_persisted_rule_markers(config, db):
    from datetime import datetime, timedelta, timezone
    from sentinelpi.utils import clock

    class _NftRunner(_RecordingRunner):
        def __call__(self, argv):
            self.calls.append(argv)
            if argv[:4] == ["nft", "-a", "list", "chain"]:
                chain = argv[-1]
                return 0, f'ip daddr 45.9.148.99 drop comment "sentinelpi:{action.action_id}:{chain}" # handle 42'
            return 0, ""

    _arm(config)
    config.response.require_approval = False
    config.response.firewall_backend = "nftables"
    config.response.block_duration_seconds = 30
    started = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)

    initial_runner = _RecordingRunner()
    with clock.use_clock(clock.FixedClock(started)):
        first = ResponderManager(config, db)
        first.add_responder(FirewallResponder(config, runner=initial_runner))
        action = first.handle(_alert())[0]

    nft_runner = _NftRunner()
    with clock.use_clock(clock.FixedClock(started + timedelta(seconds=31))):
        restarted = ResponderManager(config, db)
        restarted.add_responder(FirewallResponder(config, runner=nft_runner))

    assert any(argv[:3] == ["nft", "delete", "rule"] for argv in nft_runner.calls)
    persisted = {item.action_id: item for item in restarted.recent_actions()}
    assert persisted[action.action_id].status == EXPIRED
