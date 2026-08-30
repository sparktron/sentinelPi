"""Static regressions for least-privilege deployment manifests."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_default_systemd_service_excludes_net_admin():
    service = (ROOT / "systemd" / "sentinelpi.service").read_text(encoding="utf-8")
    capability_lines = [line for line in service.splitlines() if "Capabilities=" in line]

    assert capability_lines
    assert all("CAP_NET_RAW" in line for line in capability_lines)
    assert all("CAP_NET_ADMIN" not in line for line in capability_lines)
    assert "/var/lib/sentinelpi" in service
    assert "MemoryMax=256M\n" in service
    assert "CPUQuota=80%\n" in service
    assert "PrivateDevices=no\n" in service


def test_active_response_systemd_dropin_explicitly_adds_net_admin():
    dropin = (ROOT / "systemd" / "active-response.conf").read_text(encoding="utf-8")

    assert "CAP_NET_RAW CAP_NET_ADMIN" in dropin


def test_default_compose_excludes_net_admin_and_override_adds_it():
    passive = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    response = (ROOT / "docker-compose.response.yml").read_text(encoding="utf-8")

    assert "- NET_RAW" in passive
    assert "- NET_ADMIN" not in passive
    assert "- NET_ADMIN" in response
