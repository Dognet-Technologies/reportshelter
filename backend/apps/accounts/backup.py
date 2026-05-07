"""
Core backup and restore logic for ReportShelter.

All pg_dump / psql operations live here so both management commands
and API views share a single implementation.
"""

from __future__ import annotations

import gzip
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

BACKUP_DIR = Path("/app/backups")
MAX_BACKUPS = 10
BACKUP_GLOB = "backup-*.sql.gz"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _db_env() -> dict[str, str]:
    """Return a copy of os.environ with PGPASSWORD injected."""
    db = settings.DATABASES["default"]
    env = os.environ.copy()
    env["PGPASSWORD"] = db.get("PASSWORD", "")
    return env


def _db_conn_args() -> list[str]:
    """Return psql/pg_dump connection flag list from Django settings."""
    db = settings.DATABASES["default"]
    return [
        "-h", db.get("HOST", "db"),
        "-p", str(db.get("PORT", 5432)),
        "-U", db.get("USER", ""),
        "-d", db.get("NAME", ""),
    ]


def _safe_filename(name: str) -> str:
    """Strip path components — only the basename is accepted."""
    return Path(name).name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_backup(label: str = "manual") -> dict:
    """
    Run pg_dump and store the result as a gzipped SQL file in BACKUP_DIR.

    Returns a dict with keys: filename, size_bytes, path.
    Raises RuntimeError on failure.

    The dump uses --clean --if-exists so that a subsequent psql restore
    drops and recreates all objects cleanly without needing to touch the
    database outside of a normal connection.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    app_version = os.environ.get("APP_VERSION", "unknown").lstrip("v")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"backup-v{app_version}-{label}-{timestamp}.sql.gz"
    filepath = BACKUP_DIR / filename

    cmd = [
        "pg_dump",
        *_db_conn_args(),
        "--no-owner",
        "--no-acl",
        "--clean",          # emit DROP before CREATE
        "--if-exists",      # safe DROP (no error if object missing)
        "-F", "p",          # plain SQL — readable and psql-restorable
    ]

    logger.info("Starting backup: %s", filename)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            env=_db_env(),
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("pg_dump timed out after 300 s") from exc

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(f"pg_dump exited {proc.returncode}: {stderr}")

    with gzip.open(filepath, "wb") as f:
        f.write(proc.stdout)

    size = filepath.stat().st_size
    logger.info("Backup created: %s (%d bytes)", filename, size)

    _rotate_old_backups()

    return {
        "filename": filename,
        "size_bytes": size,
        "path": str(filepath),
    }


def restore_backup(filename: str) -> None:
    """
    Restore the database from a backup file in BACKUP_DIR.

    The dump was created with --clean --if-exists, so psql will drop
    existing objects before recreating them.  Runs inside a single
    transaction; if anything fails the DB is left untouched.

    Raises RuntimeError on failure.
    """
    safe_name = _safe_filename(filename)
    filepath = BACKUP_DIR / safe_name

    if not filepath.exists():
        raise FileNotFoundError(f"Backup not found: {safe_name}")

    logger.warning("Starting restore from: %s", safe_name)

    try:
        with gzip.open(filepath, "rb") as f:
            sql_data = f.read()
    except Exception as exc:
        raise RuntimeError(f"Cannot read backup file: {exc}") from exc

    cmd = [
        "psql",
        *_db_conn_args(),
        "--single-transaction",
        "-v", "ON_ERROR_STOP=1",  # abort on first SQL error
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=sql_data,
            capture_output=True,
            env=_db_env(),
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("psql restore timed out after 300 s") from exc

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(f"psql exited {proc.returncode}: {stderr}")

    logger.warning("Restore completed from: %s", safe_name)


def list_backups() -> list[dict]:
    """
    Return backup metadata sorted newest-first.

    Each entry: filename, size_bytes, created_at (ISO-8601 UTC string).
    """
    if not BACKUP_DIR.exists():
        return []

    result = []
    for p in sorted(BACKUP_DIR.glob(BACKUP_GLOB), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = p.stat()
        result.append({
            "filename": p.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return result


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _rotate_old_backups() -> None:
    """Delete the oldest backups, keeping only MAX_BACKUPS files."""
    backups = sorted(BACKUP_DIR.glob(BACKUP_GLOB), key=lambda p: p.stat().st_mtime)
    to_delete = backups[:-MAX_BACKUPS] if len(backups) > MAX_BACKUPS else []
    for old in to_delete:
        try:
            old.unlink()
            logger.info("Rotated old backup: %s", old.name)
        except OSError as exc:
            logger.warning("Could not delete old backup %s: %s", old.name, exc)
