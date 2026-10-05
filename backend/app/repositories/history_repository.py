"""SQLite history stores prediction metadata only; never message text or flow features."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from backend.app.core.config import settings
from backend.app.models.database_models import SCHEMA_SQL


def _connect() -> sqlite3.Connection:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with _connection() as connection:
        connection.executescript(SCHEMA_SQL)
    purge_expired()


def purge_expired(now: datetime | None = None) -> int:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=settings.retention_days)
    cutoff_text = cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM analysis_history WHERE created_at < ?", (cutoff_text,))
        return cursor.rowcount


def record_event(module: str, prediction: str, confidence: float, confidence_level: str) -> int:
    if module not in {"network", "phishing"}:
        raise ValueError("unknown history module")
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO analysis_history (module, prediction, confidence, confidence_level) VALUES (?, ?, ?, ?)",
            (module, prediction, confidence, confidence_level),
        )
        event_id = int(cursor.lastrowid)
    purge_expired()
    return event_id


def list_events(limit: int = 50) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    purge_expired()
    with _connection() as connection:
        rows = connection.execute(
            "SELECT id, module, prediction, confidence, confidence_level, created_at "
            "FROM analysis_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]