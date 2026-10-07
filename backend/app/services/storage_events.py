"""Persistent event logbook for configured external storage.

Uses SQLite for durability. Events are emitted only on state transitions,
not every polling cycle. Journal/system context is passed through the
existing redaction layer before persistence.

Schema:
    storage_events
    storage_incidents
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any

from app.utils.redact import redact_text

log = logging.getLogger("scc.storage_events")

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "data",
    "server_command_center.db",
)


class StorageEventStore:
    """SQLite-backed event logbook for storage state transitions.

    Thread-safe. Single-writer pattern (FastAPI runs the collector loop in
    one thread, the store is accessed from the same loop). WAL mode for
    concurrent read access from API endpoints.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or DEFAULT_DB_PATH
        self._init_database()

    def _init_database(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=30000")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS storage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    timestamp_epoch REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    filesystem_uuid TEXT,
                    device_path TEXT,
                    previous_device_path TEXT,
                    mountpoint TEXT,
                    severity TEXT,
                    reason TEXT,
                    diagnosis TEXT,
                    confidence TEXT,
                    kernel_context_json TEXT,
                    system_context_json TEXT,
                    details_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS storage_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    ended_at_utc TEXT,
                    event_type TEXT NOT NULL,
                    filesystem_uuid TEXT,
                    diagnosis TEXT,
                    confidence TEXT,
                    evidence_json TEXT,
                    resolved INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_storage_events_ts
                ON storage_events(timestamp_epoch DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_storage_events_type
                ON storage_events(event_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_storage_events_uuid
                ON storage_events(filesystem_uuid)
            """)
            conn.commit()
        finally:
            conn.close()

    def log_event(
        self,
        event_type: str,
        severity: str = "info",
        filesystem_uuid: str | None = None,
        device_path: str | None = None,
        previous_device_path: str | None = None,
        mountpoint: str | None = None,
        reason: str | None = None,
        diagnosis: str | None = None,
        confidence: str | None = None,
        kernel_context: str | None = None,
        system_context: str | None = None,
        details: dict[str, Any] | None = None,
        deduplicate_within_s: float = 0.0,
    ) -> int:
        """Log a storage event. Returns the row id."""
        ts = time.time()
        ts_utc = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(ts))
        if ts_utc.endswith("+0000"):
            ts_utc = ts_utc[:-5] + "+00:00"

        # Deduplication: if the same event_type was logged within the window
        # for the same UUID, skip inserting a duplicate.
        if deduplicate_within_s > 0.0:
            conn = sqlite3.connect(self._db_path, timeout=30.0)
            try:
                cursor = conn.execute(
                    """
                    SELECT id FROM storage_events
                    WHERE event_type = ?
                      AND filesystem_uuid = ?
                      AND timestamp_epoch >= ?
                    ORDER BY timestamp_epoch DESC LIMIT 1
                    """,
                    (event_type, filesystem_uuid, ts - deduplicate_within_s),
                )
                existing = cursor.fetchone()
                if existing:
                    log.debug("deduplicating %s event within %.1fs window", event_type, deduplicate_within_s)
                    existing_id = existing["id"] if isinstance(existing, (dict, sqlite3.Row)) else (existing[0] if existing else 0)
                    return existing_id or 0
            finally:
                conn.close()

        # Redact any context that might contain secrets
        safe_kernel = redact_text(kernel_context) if kernel_context else None
        safe_system = redact_text(system_context) if system_context else None

        details_json = json.dumps(details or {}, default=str) if details else None

        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                """
                INSERT INTO storage_events (
                    timestamp_utc, timestamp_epoch, event_type, filesystem_uuid,
                    device_path, previous_device_path, mountpoint, severity,
                    reason, diagnosis, confidence, kernel_context_json,
                    system_context_json, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts_utc,
                    ts,
                    event_type,
                    filesystem_uuid,
                    device_path,
                    previous_device_path,
                    mountpoint,
                    severity,
                    reason,
                    diagnosis,
                    confidence,
                    safe_kernel,
                    safe_system,
                    details_json,
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            log.info("logged storage event %s: %s (row=%d)", event_type, reason or "", row_id)
            return row_id
        finally:
            conn.close()

    def get_events(
        self,
        limit: int = 100,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve recent events, optionally filtered by severity."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            if severity:
                cursor = conn.execute(
                    """
                    SELECT * FROM storage_events
                    WHERE severity = ?
                    ORDER BY timestamp_epoch DESC
                    LIMIT ?
                    """,
                    (severity, limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM storage_events
                    ORDER BY timestamp_epoch DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        finally:
            conn.close()

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        """Retrieve a single event by id."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                "SELECT * FROM storage_events WHERE id = ?", (event_id,)
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_latest_event(self) -> dict[str, Any] | None:
        """Get the most recent event."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                "SELECT * FROM storage_events ORDER BY timestamp_epoch DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def count_events(self) -> int:
        """Count total events in the logbook."""
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        try:
            cursor = conn.execute("SELECT COUNT(*) as count FROM storage_events")
            row = cursor.fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for key in ("kernel_context_json", "system_context_json", "details_json"):
            val = d.get(key)
            if val:
                try:
                    d[key] = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    d[key] = val
        return d


# Module-level singleton, initialized lazily
_store: StorageEventStore | None = None
_store_lock = threading.Lock()


def get_store() -> StorageEventStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = StorageEventStore()
    return _store
