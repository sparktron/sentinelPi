"""
storage/backup.py - Backup and restore for the SentinelPi database.

All durable state — alerts, devices, and every learned baseline (known
destinations, hourly connection stats, DNS domains, per-host countries, active
hours, and behavioural profiles) — lives in the single SQLite database. So a
consistent snapshot of that file is a complete backup of the sensor's memory,
which is what lets baselines survive an SD-card failure or a Pi re-image.

A backup is a gzip-compressed tar archive containing:

- ``manifest.json`` — format tag, schema version, SentinelPi version, creation
  time, and the database checksum.
- ``sentinelpi.db`` — a standalone SQLite snapshot taken with the online backup
  API, so it is point-in-time consistent even while the daemon is running.

Restore validates the checksum and SQLite integrity, moves any existing
database aside (``<db>.pre-restore-<timestamp>``) rather than destroying it, and
clears stale WAL/SHM sidecars. A snapshot from an older schema is allowed — the
normal migration path upgrades it on next startup — but a snapshot from a
*newer* schema is refused unless forced.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from .. import __version__
from ..utils import clock
from .database import SCHEMA_VERSION

logger = logging.getLogger(__name__)

BACKUP_FORMAT = "sentinelpi-backup"
FORMAT_VERSION = 1
MANIFEST_MEMBER = "manifest.json"
DB_MEMBER = "sentinelpi.db"


class BackupError(Exception):
    """Raised when a backup cannot be created or restored."""


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_database(db_path: str, dest_path: str) -> None:
    """Copy a consistent snapshot of ``db_path`` to ``dest_path`` (a standalone DB)."""
    src = sqlite3.connect(db_path, timeout=30.0)
    try:
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def _read_schema_version(db_file: str) -> int:
    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def _verify_sqlite(db_file: str) -> None:
    try:
        conn = sqlite3.connect(db_file)
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise BackupError(f"restored file is not a valid SQLite database: {exc}") from exc
    if not row or row[0] != "ok":
        raise BackupError("restored database failed its integrity check")


def create_backup(db_path: str, dest_path: str) -> dict:
    """
    Write a compressed, self-describing snapshot of ``db_path`` to ``dest_path``.

    Safe to call while the daemon is running. Returns the manifest dict.
    """
    db_path = str(db_path)
    dest_path = str(dest_path)
    if not os.path.exists(db_path):
        raise BackupError(f"database not found: {db_path}")

    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, DB_MEMBER)
        _snapshot_database(db_path, snap)

        manifest = {
            "format": BACKUP_FORMAT,
            "format_version": FORMAT_VERSION,
            "schema_version": _read_schema_version(snap),
            "sentinelpi_version": __version__,
            "created_at": clock.now().isoformat(),
            "db_filename": DB_MEMBER,
            "db_sha256": _sha256(snap),
            "db_bytes": os.path.getsize(snap),
        }

        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest_path, "w:gz") as tar:
            blob = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            info = tarfile.TarInfo(MANIFEST_MEMBER)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
            tar.add(snap, arcname=DB_MEMBER)

    logger.info("Backup written to %s (schema v%d, %d bytes)",
                dest_path, manifest["schema_version"], manifest["db_bytes"])
    return manifest


def read_manifest(archive_path: str) -> dict:
    """Read and validate the manifest from a backup archive."""
    if not os.path.exists(archive_path):
        raise BackupError(f"backup not found: {archive_path}")
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            try:
                member = tar.getmember(MANIFEST_MEMBER)
            except KeyError:
                raise BackupError("not a SentinelPi backup (missing manifest)") from None
            extracted = tar.extractfile(member)
            if extracted is None:
                raise BackupError("backup manifest could not be read")
            manifest = json.loads(extracted.read().decode("utf-8"))
    except tarfile.TarError as exc:
        raise BackupError(f"not a readable backup archive: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise BackupError("not a SentinelPi backup (unrecognized format)")
    return manifest


def restore_backup(archive_path: str, db_path: str, *, force: bool = False) -> dict:
    """
    Restore ``archive_path`` over ``db_path``.

    The daemon should be stopped first. Any existing database is moved to
    ``<db_path>.pre-restore-<timestamp>`` rather than deleted. Returns the
    manifest, augmented with ``restored_to`` and (if applicable)
    ``previous_db_saved_to``.
    """
    db_path = str(db_path)
    manifest = read_manifest(archive_path)

    schema_version = int(manifest.get("schema_version", 0))
    if schema_version > SCHEMA_VERSION and not force:
        raise BackupError(
            f"backup schema v{schema_version} is newer than this build (v{SCHEMA_VERSION}); "
            "upgrade SentinelPi or re-run with --force"
        )

    db_member = manifest.get("db_filename", DB_MEMBER)
    with tempfile.TemporaryDirectory() as tmp:
        extracted = os.path.join(tmp, DB_MEMBER)
        with tarfile.open(archive_path, "r:gz") as tar:
            try:
                member = tar.getmember(db_member)
            except KeyError:
                raise BackupError("backup archive is missing its database") from None
            source = tar.extractfile(member)
            if source is None:
                raise BackupError("backup database could not be read")
            with open(extracted, "wb") as out:
                shutil.copyfileobj(source, out)

        expected = manifest.get("db_sha256")
        if expected and _sha256(extracted) != expected:
            raise BackupError("backup is corrupt (database checksum mismatch)")
        _verify_sqlite(extracted)

        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        saved_to = None
        if os.path.exists(db_path):
            ts = clock.now().strftime("%Y%m%d-%H%M%S")
            saved_to = f"{db_path}.pre-restore-{ts}"
            os.replace(db_path, saved_to)

        # Drop stale WAL/SHM sidecars that belonged to the replaced database.
        for suffix in ("-wal", "-shm"):
            sidecar = db_path + suffix
            if os.path.exists(sidecar):
                os.remove(sidecar)

        shutil.move(extracted, db_path)

    result = dict(manifest)
    result["restored_to"] = db_path
    if saved_to:
        result["previous_db_saved_to"] = saved_to
    logger.info("Restored database from %s to %s (schema v%d)",
                archive_path, db_path, schema_version)
    return result
