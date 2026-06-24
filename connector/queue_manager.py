"""
PATENT NOTICE
Module: connector/queue_manager
Implements the offline signal queue for
the open source Tier 3 connector.

When the CompliVibe API is unreachable,
signals are buffered locally in SQLite
and flushed on next successful connection.

Queue behavior (patent invariant 19):
- Maximum 10,000 signals
- When full: oldest signals are dropped
  (not newest — recency is more valuable)
- Flush on every successful API call
- Queue file path is configurable
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

MAX_QUEUE_SIZE = 10000


class QueueManager:
    """SQLite-backed offline signal queue for the Tier 3 connector.

    PATENT INVARIANT 19: Maximum 10,000 signals. When the queue is
    full, oldest signals are dropped (not newest — newer signals are
    more valuable for recency). The queue is flushed on every
    successful API call.
    """

    def __init__(self, db_path: str):
        """Create the SQLite database and signal_queue table.

        Args:
            db_path: Filesystem path for the queue database file.
                     Use ':memory:' for an in-memory queue (tests only).
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signal_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                queued_at TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0
            )
            """
        )
        self._conn.commit()

    def enqueue(self, payload: dict) -> bool:
        """Add a signal to the queue.

        If queue size >= MAX_SIZE (10000): delete the oldest entry.
        Insert the new entry.

        Returns True if enqueued, False on SQLite error.
        Never raises — queue failures must not crash the connector.
        """
        try:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM signal_queue"
            )
            count = cur.fetchone()[0]

            if count >= MAX_QUEUE_SIZE:
                self._conn.execute(
                    "DELETE FROM signal_queue WHERE id = "
                    "(SELECT MIN(id) FROM signal_queue)"
                )

            self._conn.execute(
                "INSERT INTO signal_queue (payload, queued_at, retry_count) "
                "VALUES (?, ?, 0)",
                (
                    json.dumps(payload),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def flush(self, send_fn) -> dict:
        """Attempt to send all queued signals.

        Args:
            send_fn: callable that takes a payload dict and returns
                     True on success, False on failure.

        For each queued signal (oldest first):
          Try send_fn(payload).
          If success: delete from queue.
          If failure: increment retry_count.
            If retry_count >= 3: delete from queue (abandon).

        Returns:
            {"flushed": int, "failed": int, "abandoned": int}
        """
        flushed = 0
        failed = 0
        abandoned = 0

        cur = self._conn.execute(
            "SELECT id, payload, retry_count FROM signal_queue "
            "ORDER BY id ASC"
        )
        rows = cur.fetchall()

        for row_id, payload_str, retry_count in rows:
            try:
                payload = json.loads(payload_str)
            except (json.JSONDecodeError, TypeError):
                self._conn.execute(
                    "DELETE FROM signal_queue WHERE id = ?", (row_id,)
                )
                self._conn.commit()
                abandoned += 1
                continue

            try:
                success = send_fn(payload)
            except Exception:
                success = False

            if success:
                self._conn.execute(
                    "DELETE FROM signal_queue WHERE id = ?", (row_id,)
                )
                flushed += 1
            else:
                new_retry = retry_count + 1
                if new_retry >= 3:
                    self._conn.execute(
                        "DELETE FROM signal_queue WHERE id = ?", (row_id,)
                    )
                    abandoned += 1
                else:
                    self._conn.execute(
                        "UPDATE signal_queue SET retry_count = ? WHERE id = ?",
                        (new_retry, row_id),
                    )
                    failed += 1

        self._conn.commit()
        return {"flushed": flushed, "failed": failed, "abandoned": abandoned}

    def size(self) -> int:
        """Return current queue size."""
        cur = self._conn.execute("SELECT COUNT(*) FROM signal_queue")
        return cur.fetchone()[0]

    def clear(self) -> None:
        """Empty the queue. Used in tests."""
        self._conn.execute("DELETE FROM signal_queue")
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
