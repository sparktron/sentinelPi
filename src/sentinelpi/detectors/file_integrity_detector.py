"""File-integrity polling for operator-selected paths."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional

from .base import BaseDetector
from ..models import Alert, AlertCategory, Evidence, Severity, explain


class FileIntegrityDetector(BaseDetector):
    """Hash files and alert when a previously observed path changes state or content."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fingerprints: Optional[Dict[str, Optional[str]]] = None

    @staticmethod
    def _fingerprint(path: str) -> Optional[str]:
        try:
            digest = hashlib.sha256()
            with Path(path).open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            return None

    def _poll(self) -> List[Alert]:
        current = {
            path: self._fingerprint(path)
            for path in self.config.monitoring.file_integrity_paths
        }
        if self._fingerprints is None:
            self._fingerprints = current
            return []

        alerts: List[Alert] = []
        for path, fingerprint in current.items():
            previous = self._fingerprints.get(path)
            if previous == fingerprint:
                continue
            change = "deleted or unreadable" if fingerprint is None else (
                "created or readable again" if previous is None else "content changed"
            )
            alerts.append(Alert(
                severity=Severity.HIGH,
                category=AlertCategory.PROCESS_ANOMALY,
                affected_host="localhost",
                title=f"Monitored file {change}: {path}",
                description=(
                    f"The monitored path {path} changed state since the previous integrity check "
                    f"({change})."
                ),
                recommended_action="Verify the change was authorized and restore the file if needed.",
                confidence=1.0,
                confidence_rationale="SHA-256 or readability state changed between polls.",
                dedup_key=f"file_integrity:{path}:{fingerprint or 'missing'}",
                extra=explain(
                    Evidence(
                        metric="sha256",
                        observed=fingerprint or "missing",
                        comparison="changed-from",
                        baseline=previous or "missing",
                    ),
                    confidence_basis="Direct local file-state comparison.",
                ),
            ))
        self._fingerprints = current
        return alerts
