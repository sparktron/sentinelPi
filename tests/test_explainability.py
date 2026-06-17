"""
tests/test_explainability.py - Structured alert explainability.

Covers the Evidence/explain() helpers, that detectors attach an explanation to
their alerts, and that the explanation survives a database round-trip and is
surfaced by the dashboard serializer.
"""

from __future__ import annotations

import pytest

from sentinelpi.detectors.port_scan_detector import PortScanDetector
from sentinelpi.models import Alert, AlertCategory, Evidence, Severity, explain
from sentinelpi.ui.dashboard import _alert_to_dict
from tests.fixtures.sample_data import make_port_scan_events


def test_evidence_to_dict_omits_empty_optionals():
    ev = Evidence(metric="unique_ports", observed=42)
    assert ev.to_dict() == {"metric": "unique_ports", "observed": 42}


def test_evidence_to_dict_includes_set_fields():
    ev = Evidence(metric="cv", observed=0.05, threshold=0.1, comparison="<=", baseline="machine-timed")
    assert ev.to_dict() == {
        "metric": "cv",
        "observed": 0.05,
        "threshold": 0.1,
        "comparison": "<=",
        "baseline": "machine-timed",
    }


def test_explain_builds_payload_with_confidence_basis():
    payload = explain(
        Evidence(metric="unique_ports", observed=42, threshold=20, comparison=">="),
        confidence_basis="fixed 0.9 on threshold breach",
    )
    assert payload["confidence_basis"] == "fixed 0.9 on threshold breach"
    assert payload["evidence"][0]["metric"] == "unique_ports"


def test_explain_without_basis_has_no_basis_key():
    payload = explain(Evidence(metric="x", observed=1))
    assert "confidence_basis" not in payload
    assert len(payload["evidence"]) == 1


@pytest.fixture
def scan_detector(config, db, baseline, device_tracker):
    return PortScanDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


def test_port_scan_alert_carries_explanation(scan_detector):
    events = make_port_scan_events(
        scanner_ip="192.168.1.50", target_ip="192.168.1.100", port_count=50
    )
    alerts = []
    for event in events:
        alerts.extend(scan_detector.process_event(event))

    scans = [a for a in alerts if a.category == AlertCategory.PORT_SCAN]
    assert scans, "expected a port-scan alert"
    explanation = scans[0].extra.get("explanation")
    assert explanation, "port-scan alert should carry an explanation"
    metrics = {e["metric"] for e in explanation["evidence"]}
    assert "unique_ports" in metrics
    first = explanation["evidence"][0]
    assert first["comparison"] == ">="
    assert first["threshold"] is not None
    assert explanation["confidence_basis"]


def test_explanation_survives_db_round_trip(db):
    alert = Alert(
        severity=Severity.MEDIUM,
        category=AlertCategory.PORT_SCAN,
        affected_host="192.168.1.100",
        related_host="192.168.1.50",
        title="Port scan",
        extra={
            "explanation": explain(
                Evidence(metric="unique_ports", observed=42, threshold=20, comparison=">="),
                confidence_basis="fixed 0.9 on threshold breach",
            )
        },
    )
    db.save_alert(alert)
    loaded = db.get_alert(alert.alert_id)
    assert loaded is not None
    assert loaded.extra["explanation"]["evidence"][0]["observed"] == 42
    assert loaded.extra["explanation"]["confidence_basis"] == "fixed 0.9 on threshold breach"


def test_dashboard_serializer_surfaces_explanation():
    alert = Alert(
        severity=Severity.LOW,
        category=AlertCategory.CONNECTION_ANOMALY,
        title="New destination",
        confidence_rationale="first-seen destination",
        extra={"explanation": explain(Evidence(metric="destination", observed="1.2.3.4:443"))},
    )
    payload = _alert_to_dict(alert)
    assert payload["explanation"]["evidence"][0]["metric"] == "destination"
    assert payload["confidence_rationale"] == "first-seen destination"
