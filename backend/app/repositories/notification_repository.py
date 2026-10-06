"""Notification outbox.

Messages are recorded when real SOC events occur (see history_repository.record_event).
No delivery channel (SMTP/Slack/webhook) is configured in this deployment, so rows stay
in the 'not_configured' state — we never claim a message was delivered when it was not.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings

DELIVERY_STATUSES = {"not_configured", "sent", "failed"}
CHANNELS = {"email", "slack", "webhook"}

_SELECT_NOTIFICATION = (
    "SELECT id, event_type, severity, subject, body, channel, delivery_status, created_at "
    "FROM notifications"
)


def _connect() -> sqlite3.Connection:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection() -> Generator[sqlite3.Connection, None, None]:
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def list_notifications(limit: int = 50, severity: str | None = None, offset: int = 0) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    query = _SELECT_NOTIFICATION
    parameters: list[object] = []
    if severity is not None:
        query += " WHERE severity = ?"
        parameters.append(severity)
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.append(limit)
    parameters.append(offset)
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def counts() -> dict:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT delivery_status, COUNT(*) AS n FROM notifications GROUP BY delivery_status"
        ).fetchall()
        total = connection.execute("SELECT COUNT(*) AS n FROM notifications").fetchone()["n"]
    result = {status: 0 for status in DELIVERY_STATUSES}
    for row in rows:
        result[row["delivery_status"]] = int(row["n"])
    result["total"] = int(total)
    return result


def list_pending(limit: int = 50) -> list[dict]:
    """Notifications still waiting for a delivery channel, oldest first."""
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    with _connection() as connection:
        rows = connection.execute(
            _SELECT_NOTIFICATION + " WHERE delivery_status = 'not_configured' "
            "ORDER BY created_at, id LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def mark_delivered(notification_id: int, channel: str, delivery_status: str) -> None:
    """Record the outcome of a real delivery attempt.

    Only 'sent' and 'failed' are written here; 'not_configured' is the initial state
    and means no channel was available, which is never overwritten by a fake success.
    """
    if channel not in CHANNELS:
        raise ValueError("unknown notification channel")
    if delivery_status not in {"sent", "failed"}:
        raise ValueError("delivery_status must be 'sent' or 'failed'")
    with _connection() as connection:
        connection.execute(
            "UPDATE notifications SET channel = ?, delivery_status = ? WHERE id = ?",
            (channel, delivery_status, notification_id),
        )
