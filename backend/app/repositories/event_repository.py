"""Persistence for normalized security events."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from backend.app.core.config import settings
from backend.app.schemas.events import EventSeverity, NormalizedEvent


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


def ingest_event(event: NormalizedEvent) -> bool:
    values = event.model_dump(mode="json")
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
    cutoff_text = cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with _connection() as connection:
        connection.execute("DELETE FROM events WHERE ingested_at < ?", (cutoff_text,))
        cursor = connection.execute(
            "INSERT OR IGNORE INTO events "
            "(event_id, timestamp, source, source_type, host, user, src_ip, dst_ip, "
            "src_port, dst_port, protocol, event_type, severity, message, raw_event, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                values["event_id"],
                values["timestamp"],
                values["source"],
                values["source_type"],
                values["host"],
                values["user"],
                values["src_ip"],
                values["dst_ip"],
                values["src_port"],
                values["dst_port"],
                values["protocol"],
                values["event_type"],
                values["severity"],
                values["message"],
                json.dumps(values["raw_event"], ensure_ascii=False, separators=(",", ":")),
                json.dumps(values["metadata"], ensure_ascii=False, separators=(",", ":")),
            ),
        )
        return cursor.rowcount == 1


def _event_from_row(row: sqlite3.Row) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        source=row["source"],
        source_type=row["source_type"],
        host=row["host"],
        user=row["user"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
        event_type=row["event_type"],
        severity=row["severity"],
        message=row["message"],
        raw_event=json.loads(row["raw_event"]),
        metadata=json.loads(row["metadata"]),
    )


def list_events(
    limit: int = 50,
    offset: int = 0,
    source_type: str | None = None,
    severity: EventSeverity | None = None,
) -> list[NormalizedEvent]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    query = (
        "SELECT event_id, timestamp, source, source_type, host, user, src_ip, dst_ip, "
        "src_port, dst_port, protocol, event_type, severity, message, raw_event, metadata "
        "FROM events"
    )
    conditions: list[str] = []
    parameters: list[object] = []
    if source_type is not None:
        conditions.append("source_type = ?")
        parameters.append(source_type)
    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC, event_id DESC LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_event_from_row(row) for row in rows]