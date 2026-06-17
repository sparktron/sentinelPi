"""
tests/test_host_profile.py - Per-host behavioural profile detection.

Verifies the host_profile store and detector: it learns each local host's
usual destination ports and internal peers, then flags the first off-profile
value once that dimension's profile is established. It stays quiet during the
global learning phase and persists learned values across detector instances.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpi.detectors.host_profile_detector import HostProfileDetector
from sentinelpi.models import AlertCategory, Severity
from sentinelpi.utils import clock


def _conn(src_ip="192.168.1.50", dst_ip="93.184.216.34", dst_port=443, protocol="tcp", size=0):
    from sentinelpi.capture.packet_capture import CapturedConnection
    return CapturedConnection(
        timestamp=datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=40000,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        flags="S",
        size=size,
    )


def _detector(config, db, baseline, device_tracker):
    config.monitoring.host_profile_min_known_ports = 3
    config.monitoring.host_profile_min_known_peers = 2
    config.monitoring.host_profile_min_known_protocols = 2
    config.monitoring.host_profile_min_known_byte_ranges = 2
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    return HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


def _seed(db, ip, dimension, values):
    for value in values:
        db.record_host_profile_value(ip, dimension, str(value))


def test_record_host_profile_value_newness(db):
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "443") is True
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "443") is False
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "22") is True
    assert db.get_host_profile_values("192.168.1.50", "dst_port") == {"443", "22"}


def test_no_alert_until_port_profile_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [80, 443])

    assert detector.process_event(_conn(dst_port=22)) == []
    assert "22" in db.get_host_profile_values("192.168.1.50", "dst_port")


def test_alerts_on_new_port_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    alerts = detector.process_event(_conn(dst_port=445))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.CONNECTION_ANOMALY
    assert alerts[0].affected_host == "192.168.1.50"
    assert alerts[0].extra["dimension"] == "dst_port"
    assert alerts[0].extra["value"] == "445"
    assert alerts[0].extra["known"] == 3
    assert alerts[0].extra["explanation"]["evidence"][0]["metric"] == "host_dst_port"


def test_known_port_no_alert(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    assert detector.process_event(_conn(dst_port=443)) == []


def test_alerts_on_new_internal_peer_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "peer", ["192.168.1.10", "192.168.1.11"])

    alerts = detector.process_event(_conn(dst_ip="192.168.1.99", dst_port=443))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].related_host == "192.168.1.99"
    assert alerts[0].extra["dimension"] == "peer"
    assert alerts[0].extra["value"] == "192.168.1.99"
    assert alerts[0].extra["known"] == 2
    assert alerts[0].extra["explanation"]["evidence"][0]["metric"] == "host_peer"


def test_alerts_on_new_protocol_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "protocol", ["tcp", "udp"])

    alerts = detector.process_event(_conn(protocol="icmp", dst_port=443))

    proto_alerts = [a for a in alerts if a.extra["dimension"] == "protocol"]
    assert len(proto_alerts) == 1
    assert proto_alerts[0].extra["value"] == "icmp"
    assert proto_alerts[0].extra["explanation"]["evidence"][0]["metric"] == "host_protocol"


def test_known_protocol_no_alert(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "protocol", ["tcp", "udp"])

    alerts = detector.process_event(_conn(protocol="tcp", dst_port=443))
    assert [a for a in alerts if a.extra["dimension"] == "protocol"] == []


def test_alerts_on_new_byte_range_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "byte_range", ["0-1K", "1K-10K"])

    alerts = detector.process_event(_conn(size=5_000_000, dst_port=443))

    byte_alerts = [a for a in alerts if a.extra["dimension"] == "byte_range"]
    assert len(byte_alerts) == 1
    assert byte_alerts[0].extra["value"] == "1M-10M"
    assert byte_alerts[0].extra["explanation"]["evidence"][0]["metric"] == "host_byte_range"


def test_byte_range_dormant_without_size(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "byte_range", ["0-1K", "1K-10K"])

    # size=0 (SYN-only capture / conntrack): the dimension must not record or fire.
    detector.process_event(_conn(size=0, dst_port=443))
    assert db.get_host_profile_values("192.168.1.50", "byte_range") == {"0-1K", "1K-10K"}


def test_byte_bucket_boundaries():
    from sentinelpi.detectors.host_profile_detector import _byte_bucket
    assert _byte_bucket(500) == "0-1K"
    assert _byte_bucket(1_000) == "1K-10K"
    assert _byte_bucket(50_000) == "10K-100K"
    assert _byte_bucket(5_000_000) == "1M-10M"
    assert _byte_bucket(999_000_000) == "10M+"


def test_external_peer_not_profiled(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "peer", ["192.168.1.10", "192.168.1.11"])

    assert detector.process_event(_conn(dst_ip="93.184.216.34", dst_port=443)) == []
    assert "93.184.216.34" not in db.get_host_profile_values("192.168.1.50", "peer")


def test_non_local_source_ignored(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "8.8.8.8", "dst_port", [53, 80, 443])

    assert detector.process_event(_conn(src_ip="8.8.8.8", dst_port=22)) == []


def test_learning_phase_records_but_no_alert(config, db, device_tracker):
    from sentinelpi.baseline.engine import BaselineEngine

    config.monitoring.host_profile_min_known_ports = 3
    config.monitoring.baseline_learning_hours = 24
    learning_baseline = BaselineEngine(config, db)
    learning_baseline._start_time = datetime(2026, 6, 13, 11, 0, tzinfo=timezone.utc)
    detector = HostProfileDetector(config=config, db=db, baseline=learning_baseline, device_tracker=device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    with clock.use_clock(clock.FixedClock(datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc))):
        assert detector.process_event(_conn(dst_port=22)) == []
    assert "22" in db.get_host_profile_values("192.168.1.50", "dst_port")


def test_persists_across_instances(config, db, baseline, device_tracker):
    config.monitoring.host_profile_min_known_ports = 3
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    det1 = HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert len(det1.process_event(_conn(dst_port=22))) == 1

    det2 = HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert det2.process_event(_conn(dst_port=22)) == []
