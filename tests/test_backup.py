from __future__ import annotations

import gzip
import sqlite3

import pytest

from sentinelpi.storage import backup as backup_mod
from sentinelpi.storage.backup import BackupError
from sentinelpi.storage.database import SCHEMA_VERSION, Database
from sentinelpi.models import Device


def _db_with_device(path: str) -> Database:
    db = Database(path)
    db.upsert_device(Device(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname="laptop"))
    db.record_host_country("192.168.1.50", "US")
    db.close()
    return db


def test_backup_restore_round_trip(tmp_path):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)

    manifest = backup_mod.create_backup(db_path, archive)
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["db_sha256"]

    # Wipe all learned state.
    wipe = Database(db_path)
    with wipe._conn() as conn:
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM host_countries")
    assert wipe.get_all_devices() == []
    wipe.close()  # release the connection before the file is replaced

    result = backup_mod.restore_backup(archive, db_path)
    assert result["restored_to"] == db_path
    assert "previous_db_saved_to" in result

    restored = Database(db_path)
    devices = restored.get_all_devices()
    assert [d.ip for d in devices] == ["192.168.1.50"]
    assert restored.get_host_countries("192.168.1.50") == {"US"}
    restored.close()


def test_read_manifest_reports_metadata(tmp_path):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)
    backup_mod.create_backup(db_path, archive)

    manifest = backup_mod.read_manifest(archive)
    assert manifest["format"] == backup_mod.BACKUP_FORMAT
    assert manifest["sentinelpi_version"]
    assert manifest["db_filename"] == backup_mod.DB_MEMBER


def test_read_manifest_rejects_non_backup(tmp_path):
    bogus = tmp_path / "notes.txt.gz"
    bogus.write_bytes(gzip.compress(b"just some text"))
    with pytest.raises(BackupError):
        backup_mod.read_manifest(str(bogus))


def test_create_backup_missing_database(tmp_path):
    with pytest.raises(BackupError):
        backup_mod.create_backup(str(tmp_path / "nope.db"), str(tmp_path / "out.tar.gz"))


def test_restore_detects_checksum_mismatch(tmp_path, monkeypatch):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)

    # Force a wrong checksum into the manifest at create time.
    real_sha = backup_mod._sha256
    monkeypatch.setattr(backup_mod, "_sha256",
                        lambda path: "0" * 64 if path.endswith(backup_mod.DB_MEMBER) else real_sha(path))
    backup_mod.create_backup(db_path, archive)
    monkeypatch.undo()

    with pytest.raises(BackupError, match="checksum"):
        backup_mod.restore_backup(archive, db_path)


def test_restore_refuses_newer_schema(tmp_path, monkeypatch):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)
    backup_mod.create_backup(db_path, archive)

    # Pretend the build only understands an older schema.
    monkeypatch.setattr(backup_mod, "SCHEMA_VERSION", SCHEMA_VERSION - 1)
    with pytest.raises(BackupError, match="newer"):
        backup_mod.restore_backup(archive, db_path)

    # ...but --force lets it through.
    result = backup_mod.restore_backup(archive, db_path, force=True)
    assert result["restored_to"] == db_path


def test_restore_rejects_corrupt_database(tmp_path):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)
    backup_mod.create_backup(db_path, archive)

    # Replace the snapshot inside the archive with garbage that still matches
    # its checksum, so only the SQLite integrity check can catch it.
    import io
    import json
    import tarfile

    garbage = b"this is not a sqlite database"
    sha = __import__("hashlib").sha256(garbage).hexdigest()
    manifest = backup_mod.read_manifest(archive)
    manifest["db_sha256"] = sha
    with tarfile.open(archive, "w:gz") as tar:
        blob = json.dumps(manifest).encode()
        info = tarfile.TarInfo(backup_mod.MANIFEST_MEMBER)
        info.size = len(blob)
        tar.addfile(info, io.BytesIO(blob))
        info = tarfile.TarInfo(backup_mod.DB_MEMBER)
        info.size = len(garbage)
        tar.addfile(info, io.BytesIO(garbage))

    with pytest.raises(BackupError):
        backup_mod.restore_backup(archive, db_path)


def test_restore_clears_stale_wal_sidecars(tmp_path):
    db_path = str(tmp_path / "sentinelpi.db")
    archive = str(tmp_path / "snap.tar.gz")
    _db_with_device(db_path)
    backup_mod.create_backup(db_path, archive)

    # Simulate leftover WAL/SHM files next to the live database.
    (tmp_path / "sentinelpi.db-wal").write_bytes(b"stale")
    (tmp_path / "sentinelpi.db-shm").write_bytes(b"stale")

    backup_mod.restore_backup(archive, db_path)

    assert not (tmp_path / "sentinelpi.db-wal").exists()
    assert not (tmp_path / "sentinelpi.db-shm").exists()
    # Restored DB still opens cleanly.
    conn = sqlite3.connect(db_path)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()
