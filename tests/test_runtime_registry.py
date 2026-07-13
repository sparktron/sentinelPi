"""Shared runtime component manifest, routing, preflight, and status tests."""

from __future__ import annotations

import pytest

from sentinelpi.config.manager import Config
from sentinelpi.config.preflight import run_preflight
from sentinelpi.main import SentinelPi
from sentinelpi.runtime_registry import RuntimeComponentRegistry, component_manifest
from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app


def test_manifest_covers_every_runtime_component_kind():
    manifest = component_manifest(Config())

    assert len({component.key for component in manifest}) == len(manifest)
    assert {component.kind for component in manifest} == {
        "input",
        "inventory",
        "detector",
        "notifier",
        "responder",
        "service",
    }
    assert any(component.key == "detector:port_scan" for component in manifest)
    assert any(component.key == "notifier:console" for component in manifest)
    assert any(component.key == "responder:firewall" for component in manifest)


def test_registry_routes_only_configured_attached_instances(config):
    config.monitoring.dns_monitoring_enabled = False
    registry = RuntimeComponentRegistry(config)
    arp = object()
    dns = object()
    tracker = object()
    registry.attach("detector:arp", arp)
    registry.attach("detector:dns", dns)
    registry.attach("inventory:device_tracker", tracker)

    assert arp in registry.routed_instances("event")
    assert dns not in registry.routed_instances("event")
    assert registry.pollers() == [
        (tracker, 30, "DeviceTracker", "inventory:device_tracker"),
        (arp, 60, "ARPDetector", "detector:arp"),
    ]


def test_registry_tracks_state_and_activity(config):
    registry = RuntimeComponentRegistry(config)
    detector = object()
    registry.attach("detector:arp", detector)
    registry.mark_started("detector:arp", "event router")
    registry.record_instance_activity(detector)

    arp = next(item for item in registry.snapshot() if item["key"] == "detector:arp")
    assert arp["state"] == "started"
    assert arp["detail"] == "event router"
    assert arp["activity_count"] == 1
    assert arp["last_activity"] is not None

    registry.mark_all_stopped()
    arp = next(item for item in registry.snapshot() if item["key"] == "detector:arp")
    assert arp["state"] == "stopped"


def test_preflight_uses_shared_component_manifest():
    config = Config()
    config.monitoring.dns_monitoring_enabled = False

    by_name = {result.name: result for result in run_preflight(config)}

    assert by_name["component:detector:port_scan"].status == "ok"
    assert "routes=event,poll" in by_name["component:detector:port_scan"].detail
    assert by_name["component:detector:dns"].status == "skip"


def test_sentinel_startup_binds_every_configured_routed_component(tmp_path):
    config_path = tmp_path / "sentinelpi.yaml"
    config_path.write_text(
        "\n".join([
            "monitoring:",
            "  packet_capture_enabled: false",
            "  auth_log_enabled: false",
            "storage:",
            f"  db_path: {tmp_path / 'runtime.db'}",
            "logging:",
            f"  log_dir: {tmp_path / 'logs'}",
            f"  json_alerts_file: {tmp_path / 'alerts.json'}",
        ]),
        encoding="utf-8",
    )
    sentinel = SentinelPi(config_path=str(config_path))
    try:
        routed = [
            component
            for component in sentinel._components.snapshot()
            if component["configured"] and component["routes"]
        ]
        assert routed
        assert all(component["state"] == "ready" for component in routed)
        assert sentinel._build_event_detectors() == sentinel._components.routed_instances("event")
        assert len(sentinel._build_pollers()) == len(sentinel._components.pollers())
    finally:
        sentinel._shutdown()


@pytest.mark.skipif(not FLASK_AVAILABLE, reason="Flask not installed")
def test_status_api_exposes_live_component_matrix(
    config, db, device_tracker, baseline, alert_manager
):
    config.dashboard.access_token = "token"
    registry = RuntimeComponentRegistry(config)
    registry.attach("detector:arp", object())
    registry.mark_started("detector:arp")
    app = create_app(
        config,
        db,
        device_tracker,
        baseline,
        alert_manager,
        component_registry=registry,
    )
    app.config.update(TESTING=True)

    response = app.test_client().get(
        "/api/status", headers={"Authorization": "Bearer token"}
    )

    assert response.status_code == 200
    components = {item["key"]: item for item in response.get_json()["components"]}
    assert components["detector:arp"]["state"] == "started"
    assert components["responder:firewall"]["state"] == "disabled"
