"""Local SQLite storage and resilient offline queue for the endpoint agent.

Provides thread-safe storage for normalized events, generated security alerts,
and an outbox queue that buffers events during network drops (PRD Section 6.1 FR-A5/FR-A8).
Configured with WAL mode for non-blocking concurrent operations.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from agent.models import Alert, NormalizedEvent

logger = logging.getLogger("agent.local_store")


class LocalStore:
    """Manages the local SQLite database for events, alerts, and outbox queue."""

    def __init__(
        self,
        db_path: Union[str, Path] = "./data/local_alerts.sqlite",
        max_outbox_events: int = 10000,
    ):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_outbox_events = max_outbox_events
        self._lock = threading.Lock()

        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row

        self._init_db()

    def _init_db(self) -> None:
        """Configures WAL mode and initializes required database schemas."""
        with self._lock:
            cursor = self._conn.cursor()
            # Enable Write-Ahead Logging for fast concurrent reads/writes
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")

            # Table 1: Normalized Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source_event_id INTEGER,
                    process_image TEXT,
                    command_line TEXT,
                    raw_json TEXT NOT NULL,
                    processed INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)

            # Table 2: Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rule_ids TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    mitre_ids TEXT NOT NULL,
                    raw_event TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            # Table 3: Outbox buffer queue for offline resilience
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)

            # Indexes for fast querying
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_processed ON events (processed);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);")
            self._conn.commit()

    # ---------------------------------------------------------
    # Event Operations
    # ---------------------------------------------------------

    def insert_events(self, events: List[NormalizedEvent]) -> int:
        """Inserts a batch of normalized events into the local database."""
        if not events:
            return 0

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = [
            (
                ev.event_id,
                ev.device_id,
                ev.timestamp,
                ev.type,
                ev.source_event_id,
                ev.process_image,
                ev.command_line,
                ev.to_json(),
                0,
                now_str,
            )
            for ev in events
        ]

        with self._lock:
            cursor = self._conn.cursor()
            cursor.executemany(
                """
                INSERT OR IGNORE INTO events
                (event_id, device_id, timestamp, type, source_event_id,
                 process_image, command_line, raw_json, processed, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._conn.commit()
            return cursor.rowcount

    def get_unprocessed_events(self, limit: int = 100) -> List[NormalizedEvent]:
        """Retrieves events that have not yet been evaluated by local detection."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT raw_json FROM events WHERE processed = 0 ORDER BY created_at ASC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()

        events: List[NormalizedEvent] = []
        for r in rows:
            try:
                data = json.loads(r["raw_json"])
                events.append(NormalizedEvent.from_dict(data))
            except Exception as e:
                logger.warning(f"Error deserializing local event: {e}")

        return events

    def mark_events_processed(self, event_ids: List[str]) -> None:
        """Marks specified events as processed."""
        if not event_ids:
            return

        with self._lock:
            cursor = self._conn.cursor()
            cursor.executemany(
                "UPDATE events SET processed = 1 WHERE event_id = ?",
                [(eid,) for eid in event_ids],
            )
            self._conn.commit()

    # ---------------------------------------------------------
    # Alert Operations
    # ---------------------------------------------------------

    def insert_alert(self, alert: Alert) -> None:
        """Stores a generated security alert into the local database."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts
                (alert_id, device_id, timestamp, rule_ids, score, severity,
                 explanation, mitre_ids, raw_event, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.device_id,
                    alert.timestamp,
                    json.dumps(alert.rule_ids),
                    alert.score,
                    alert.severity,
                    alert.explanation,
                    json.dumps(alert.mitre_ids),
                    json.dumps(alert.raw_event),
                    now_str,
                ),
            )
            self._conn.commit()

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Alert]:
        """Retrieves stored alerts, optionally filtered by severity."""
        query = "SELECT * FROM alerts"
        params: List[Any] = []

        if severity:
            query += " WHERE severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

        alerts: List[Alert] = []
        for r in rows:
            try:
                alerts.append(
                    Alert(
                        alert_id=r["alert_id"],
                        device_id=r["device_id"],
                        timestamp=r["timestamp"],
                        rule_ids=json.loads(r["rule_ids"]),
                        score=r["score"],
                        severity=r["severity"],
                        explanation=r["explanation"],
                        mitre_ids=json.loads(r["mitre_ids"]),
                        raw_event=json.loads(r["raw_event"]),
                    )
                )
            except Exception as e:
                logger.warning(f"Error deserializing alert {r['alert_id']}: {e}")

        return alerts

    # ---------------------------------------------------------
    # Outbox Offline Queue Operations
    # ---------------------------------------------------------

    def enqueue_outbox(self, payload: Dict[str, Any], event_count: int) -> int:
        """Buffers a batch payload in the outbox queue during network outages.

        Automatically enforces max_outbox_events by pruning oldest batches if needed.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        batch_id = str(uuid.uuid4())
        payload_str = json.dumps(payload)

        with self._lock:
            cursor = self._conn.cursor()

            # Enforce max outbox capacity
            cursor.execute("SELECT COALESCE(SUM(event_count), 0) AS total FROM outbox;")
            current_total = int(cursor.fetchone()["total"])

            if current_total + event_count > self.max_outbox_events:
                logger.warning(
                    f"Outbox capacity ({self.max_outbox_events}) reached. "
                    "Pruning oldest queued batches to prevent disk exhaustion."
                )
                while current_total + event_count > self.max_outbox_events:
                    cursor.execute("SELECT id, event_count FROM outbox ORDER BY id ASC LIMIT 1;")
                    oldest = cursor.fetchone()
                    if not oldest:
                        break
                    cursor.execute("DELETE FROM outbox WHERE id = ?", (oldest["id"],))
                    current_total -= int(oldest["event_count"])

            cursor.execute(
                """
                INSERT INTO outbox (batch_id, payload, event_count, retry_count, created_at)
                VALUES (?, ?, ?, 0, ?)
                """,
                (batch_id, payload_str, event_count, now_str),
            )
            self._conn.commit()
            return int(cursor.lastrowid or 0)

    def peek_outbox(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves oldest pending batches from the outbox for sending."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT id, batch_id, payload, event_count, retry_count, created_at
                FROM outbox ORDER BY id ASC LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()

        items: List[Dict[str, Any]] = []
        for r in rows:
            try:
                items.append(
                    {
                        "id": r["id"],
                        "batch_id": r["batch_id"],
                        "payload": json.loads(r["payload"]),
                        "event_count": r["event_count"],
                        "retry_count": r["retry_count"],
                        "created_at": r["created_at"],
                    }
                )
            except Exception as e:
                logger.error(f"Error reading outbox item {r['id']}: {e}")

        return items

    def acknowledge_outbox(self, outbox_id: int) -> None:
        """Removes a successfully transmitted batch from the outbox queue."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM outbox WHERE id = ?", (outbox_id,))
            self._conn.commit()

    def increment_outbox_retry(self, outbox_id: int) -> None:
        """Increments the retry counter for an outbox batch after a failed send attempt."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                "UPDATE outbox SET retry_count = retry_count + 1 WHERE id = ?",
                (outbox_id,),
            )
            self._conn.commit()

    def get_outbox_stats(self) -> Dict[str, int]:
        """Returns statistics on the current outbox queue."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) AS total_batches, COALESCE(SUM(event_count), 0) AS total_events
                FROM outbox;
            """)
            row = cursor.fetchone()
            return {
                "total_batches": int(row["total_batches"]),
                "total_events": int(row["total_events"]),
                "pending_batches": int(row["total_batches"]),
                "pending_events": int(row["total_events"]),
            }

    def close(self) -> None:
        """Closes the underlying database connection."""
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
