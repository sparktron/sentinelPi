"""TCP connection-initiation filtering and retransmission regressions."""

from datetime import timedelta
import queue

from sentinelpi.capture.packet_capture import (
    CapturedConnection,
    MAX_RECENT_SYNS,
    PacketCapture,
    build_bpf_filter,
    is_connection_initiation,
)
from sentinelpi.utils import clock


def _syn(timestamp, *, src_port=40000):
    return CapturedConnection(
        timestamp=timestamp,
        src_ip="192.168.1.10",
        src_port=src_port,
        dst_ip="192.168.1.20",
        dst_port=443,
        protocol="tcp",
        flags="S",
    )


def test_capture_filter_and_flag_guard_accept_only_initial_syn():
    capture_filter = build_bpf_filter()

    assert "tcp-syn|tcp-ack" in capture_filter
    assert is_connection_initiation("S") is True
    assert is_connection_initiation("SA") is False
    assert is_connection_initiation("A") is False


def test_retransmitted_syn_counts_once_per_tuple_window():
    capture = PacketCapture(["eth0"], queue.Queue())
    now = clock.now()

    assert capture._is_retransmitted_syn(_syn(now)) is False
    assert capture._is_retransmitted_syn(_syn(now + timedelta(seconds=1))) is True
    assert capture._is_retransmitted_syn(_syn(now + timedelta(seconds=61))) is False


def test_syn_dedup_cache_has_hard_ceiling():
    capture = PacketCapture(["eth0"], queue.Queue())
    now = clock.now()

    for src_port in range(MAX_RECENT_SYNS + 10):
        capture._is_retransmitted_syn(_syn(now, src_port=src_port))

    assert len(capture._recent_syns) == MAX_RECENT_SYNS
