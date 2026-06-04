"""
tests/test_alert_enrichment.py - GeoIP/ASN enrichment of alerts (Phase 1 follow-up).

The AlertManager attaches country + ASN context for the external IP in every
alert, centrally, so all detectors benefit. Geo/ASN lookups are monkeypatched
(no databases needed).
"""

from __future__ import annotations

import pytest

from sentinelpi.alerts import manager as mgr
from sentinelpi.models import Alert, AlertCategory, Severity


@pytest.fixture
def patched_geo(monkeypatch):
    geo = {"45.9.148.99": ("RU", "Russia"), "8.8.8.8": ("US", "United States")}
    asn = {"45.9.148.99": (60068, "BadHoster"), "8.8.8.8": (15169, "GOOGLE")}
    monkeypatch.setattr(mgr, "lookup_country", lambda ip: geo.get(ip, ("", ""))[0])
    monkeypatch.setattr(mgr, "lookup_country_name", lambda ip: geo.get(ip, ("", ""))[1])
    monkeypatch.setattr(mgr, "lookup_asn", lambda ip: asn.get(ip, (0, "")))


def _alert(affected="192.168.1.50", related="", desc="base"):
    return Alert(
        severity=Severity.MEDIUM, category=AlertCategory.CONNECTION_ANOMALY,
        affected_host=affected, related_host=related, title="t", description=desc,
    )


def test_enriches_external_related_host(alert_manager, patched_geo):
    alert = _alert(related="45.9.148.99")
    alert_manager._enrich_alert(alert)
    enr = alert.extra["enrichment"]
    assert enr["ip"] == "45.9.148.99"
    assert enr["country"] == "RU" and enr["country_name"] == "Russia"
    assert enr["asn"] == 60068 and enr["asn_org"] == "BadHoster"
    assert "Russia" in alert.description and "AS60068" in alert.description


def test_prefers_related_over_affected(alert_manager, patched_geo):
    # Both external; related_host should win.
    alert = _alert(affected="8.8.8.8", related="45.9.148.99")
    alert_manager._enrich_alert(alert)
    assert alert.extra["enrichment"]["ip"] == "45.9.148.99"


def test_falls_back_to_affected_when_no_related(alert_manager, patched_geo):
    alert = _alert(affected="8.8.8.8", related="")
    alert_manager._enrich_alert(alert)
    assert alert.extra["enrichment"]["ip"] == "8.8.8.8"


def test_private_ips_not_enriched(alert_manager, patched_geo):
    alert = _alert(affected="192.168.1.50", related="10.0.0.9")
    alert_manager._enrich_alert(alert)
    assert "enrichment" not in alert.extra
    assert alert.description == "base"


def test_no_data_means_no_enrichment(alert_manager, patched_geo):
    # External IP not in the fake DBs → lookups return empty → no enrichment.
    alert = _alert(related="203.0.113.200")
    alert_manager._enrich_alert(alert)
    assert "enrichment" not in alert.extra


def test_enrichment_is_idempotent(alert_manager, patched_geo):
    alert = _alert(related="45.9.148.99")
    alert_manager._enrich_alert(alert)
    desc_once = alert.description
    alert_manager._enrich_alert(alert)  # second pass must not double-append
    assert alert.description == desc_once


def test_country_only_enrichment(alert_manager, monkeypatch):
    # Geo available, ASN not — enrichment still happens with just country.
    monkeypatch.setattr(mgr, "lookup_country", lambda ip: "DE")
    monkeypatch.setattr(mgr, "lookup_country_name", lambda ip: "Germany")
    monkeypatch.setattr(mgr, "lookup_asn", lambda ip: (0, ""))
    alert = _alert(related="192.0.2.50")
    alert_manager._enrich_alert(alert)
    enr = alert.extra["enrichment"]
    assert enr["country"] == "DE" and "asn" not in enr
    assert "Germany" in alert.description
