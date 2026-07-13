"""
tests/test_baseline_persistence.py - Regression tests for CODE_REVIEW H4.

H4: update_hourly_baseline used a biased EWMA recurrence (mislabeled "Welford")
    and a non-atomic read-modify-write. It is now a pure atomic upsert that
    snapshots the correct in-memory RunningStats. These tests pin:
      - the persisted avg/stddev match the true population statistics, and
      - the upsert overwrites (idempotent) rather than accumulating.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

from sentinelpi.baseline.engine import BaselineEngine, RunningStats
from sentinelpi.utils import clock


def _truth(values):
    mean = statistics.fmean(values)
    # Population variance (M2 / n), matching RunningStats.variance.
    pvar = statistics.pvariance(values)
    return mean, pvar ** 0.5


def test_running_stats_matches_population_statistics():
    values = [3, 7, 7, 19, 2, 11, 5, 5, 8, 13]
    rs = RunningStats()
    for v in values:
        rs.update(float(v))

    mean, stddev = _truth(values)
    assert abs(rs.mean - mean) < 1e-9
    assert abs(rs.stddev - stddev) < 1e-9


def test_snapshot_roundtrips_through_db(db):
    values = [10, 12, 9, 11, 30, 8, 10, 9, 11, 10]
    rs = RunningStats()
    for v in values:
        rs.update(float(v))

    db.update_hourly_baseline("192.168.1.5", 14, 2, rs.mean, rs.stddev, rs.n)

    row = db.get_hourly_baseline("192.168.1.5", 14, 2)
    assert row is not None
    assert abs(row["avg_conn"] - rs.mean) < 1e-9
    assert abs(row["stddev_conn"] - rs.stddev) < 1e-9
    assert row["sample_count"] == rs.n


def test_upsert_overwrites_not_accumulates(db):
    db.update_hourly_baseline("10.0.0.9", 0, 0, 5.0, 1.0, 10)
    db.update_hourly_baseline("10.0.0.9", 0, 0, 8.0, 2.0, 20)

    row = db.get_hourly_baseline("10.0.0.9", 0, 0)
    # Second write wins outright — no doubling of sample_count or drift in avg.
    assert row["avg_conn"] == 8.0
    assert row["stddev_conn"] == 2.0
    assert row["sample_count"] == 20


def test_destination_baseline_rehydrates_after_restart(config, db):
    first = BaselineEngine(config, db)
    assert first.record_destination("192.168.1.5", "203.0.113.10", 4444, "tcp")

    restarted = BaselineEngine(config, db)

    assert restarted.is_known_destination("192.168.1.5", "203.0.113.10", 4444, "tcp")
    assert not restarted.record_destination("192.168.1.5", "203.0.113.10", 4444, "tcp")


def test_hourly_connection_baseline_rehydrates_after_restart(config, db):
    instant = datetime(2026, 6, 10, 14, 0, tzinfo=timezone.utc)
    stats = RunningStats()
    for value in [8, 9, 10, 10, 11, 12, 9, 10, 11, 10]:
        stats.update(float(value))

    db.update_hourly_baseline(
        "192.168.1.5",
        hour_of_day=instant.hour,
        day_of_week=instant.weekday(),
        avg_conn=stats.mean,
        stddev_conn=stats.stddev,
        sample_count=stats.n,
    )

    with clock.use_clock(clock.FixedClock(instant)):
        restarted = BaselineEngine(config, db)
        is_spike, z_score = restarted.check_connection_spike("192.168.1.5", 80)

    assert is_spike
    assert z_score > 0


def test_learning_period_does_not_restart_with_daemon(config, db):
    config.monitoring.baseline_learning_hours = 24
    first_start = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)

    with clock.use_clock(clock.FixedClock(first_start)):
        first = BaselineEngine(config, db)
        assert first.is_learning

    after_learning = first_start + timedelta(hours=25)
    with clock.use_clock(clock.FixedClock(after_learning)):
        restarted = BaselineEngine(config, db)
        assert not restarted.is_learning
        assert restarted._start_time == first_start


def test_existing_baseline_seeds_learning_epoch_on_upgrade(config, db):
    config.monitoring.baseline_learning_hours = 24
    first_seen = datetime(2026, 6, 1, 8, 0, tzinfo=timezone.utc)
    now = first_seen + timedelta(days=7)

    with clock.use_clock(clock.FixedClock(first_seen)):
        db.record_dns_domain("existing.example")

    with clock.use_clock(clock.FixedClock(now)):
        baseline = BaselineEngine(config, db)

    assert not baseline.is_learning
    assert baseline._start_time == first_seen
