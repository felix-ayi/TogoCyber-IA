"""SQLite persistence for the SOC alert triage queue.

Alerts are raised automatically from real detections (see history_repository.record_event).
This module owns the triage lifecycle: status transitions, assignment, comments and tags.
Every value that reaches SQL is bound through `?` placeholders; only hardcoded fragments
are ever concatenated into the query text.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings

ALERT_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "CONFIRMED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "CLOSED",
}
ALERT_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}

# Allowed triage transitions. A closed alert may be reopened for investigation.
_ALLOWED_TRANSITIONS = {
    "NEW": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "INVESTIGATING": {"CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "CLOSED", "NEW"},
    "CONFIRMED": {"INVESTIGATING", "RESOLVED"},
    "FALSE_POSITIVE": {"INVESTIGATING", "CLOSED"},
    "RESOLVED": {"INVESTIGATING", "CLOSED"},
    "CLOSED": {"INVESTIGATING"},
}

# Alert verdicts that also serve as ground-truth feedback for ML monitoring.
_FEEDBACK_VERDICTS = {"FALSE_POSITIVE": "false_positive", "CONFIRMED": "confirmed"}

_SELECT_ALERT = (
    "SELECT id, history_id, incident_id, module, title, severity, risk_score, "
    "status, assignee_user_id, created_at, updated_at FROM alerts"
)
_SELECT_ALERT_BY_ID = _SELECT_ALERT + " WHERE id = ?"


class AlertNotFoundError(LookupError):
    """The alert does not exist."""


class InvalidAlertTransitionError(ValueError):
    """The requested alert status transition is not allowed."""


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


def _tags_for(connection: sqlite3.Connection, alert_id: int) -> list[str]:
    rows = connection.execute(
        "SELECT tag FROM alert_tags WHERE alert_id = ? ORDER BY tag",
        (alert_id,),
    ).fetchall()
    return [row["tag"] for row in rows]


def get_alert(alert_id: int) -> dict:
    with _connection() as connection:
        row = connection.execute(_SELECT_ALERT_BY_ID, (alert_id,)).fetchone()
        if row is None:
            raise AlertNotFoundError("Alerte introuvable.")
        result = dict(row)
        result["tags"] = _tags_for(connection, alert_id)
    return result


def list_alerts(
    limit: int = 50,
    status: str | None = None,
    severity: str | None = None,
    assignee_user_id: int | None = None,
    offset: int = 0,
) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("unknown alert status")
    if severity is not None and severity not in ALERT_SEVERITIES:
        raise ValueError("unknown alert severity")

    query = _SELECT_ALERT
    conditions: list[str] = []
    parameters: list[object] = []
    if status is not None:
        conditions.append("status = ?")
        parameters.append(status)
    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)
    if assignee_user_id is not None:
        conditions.append("assignee_user_id = ?")
        parameters.append(assignee_user_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.append(limit)
    parameters.append(offset)

    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["tags"] = _tags_for(connection, item["id"])
            results.append(item)
    return results


def update_status(
    alert_id: int,
    new_status: str,
    actor_user_id: int,
    note: str | None = None,
) -> dict:
    if new_status not in ALERT_STATUSES:
        raise ValueError("unknown alert status")
    if note is not None and len(note) > 2000:
        raise ValueError("note is too long")
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status, module, history_id FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            raise AlertNotFoundError("Alerte introuvable.")
        previous_status = str(row["status"])
        if new_status not in _ALLOWED_TRANSITIONS[previous_status]:
            raise InvalidAlertTransitionError(
                f"Transition impossible : {previous_status} vers {new_status}."
            )
        connection.execute(
            "UPDATE alerts SET status = ?, updated_at = "
            "strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (new_status, alert_id),
        )
        connection.execute(
            "INSERT INTO alert_status_events "
            "(alert_id, actor_user_id, previous_status, new_status, note) "
            "VALUES (?, ?, ?, ?, ?)",
            (alert_id, actor_user_id, previous_status, new_status, note),
        )
        # Analyst verdicts double as model feedback for ML monitoring.
        verdict = _FEEDBACK_VERDICTS.get(new_status)
        if verdict is not None:
            history_id = row["history_id"]
            model_name = model_version = None
            if history_id is not None:
                history = connection.execute(
                    "SELECT model_name, model_version FROM analysis_history WHERE id = ?",
                    (history_id,),
                ).fetchone()
                if history is not None:
                    model_name = history["model_name"]
                    model_version = history["model_version"]
            connection.execute(
                "INSERT INTO model_feedback "
                "(alert_id, history_id, module, model_name, model_version, verdict, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (alert_id, history_id, row["module"], model_name, model_version, verdict, actor_user_id),
            )
    return get_alert(alert_id)


def assign(alert_id: int, assignee_user_id: int | None, actor_user_id: int) -> dict:
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        if assignee_user_id is not None and connection.execute(
            "SELECT 1 FROM users WHERE id = ? AND is_active = 1", (assignee_user_id,)
        ).fetchone() is None:
            raise ValueError("assigned user does not exist or is inactive")
        connection.execute(
            "UPDATE alerts SET assignee_user_id = ?, updated_at = "
            "strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (assignee_user_id, alert_id),
        )
    return get_alert(alert_id)


def list_status_events(alert_id: int) -> list[dict]:
    with _connection() as connection:
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        rows = connection.execute(
            "SELECT id, alert_id, actor_user_id, previous_status, new_status, note, created_at "
            "FROM alert_status_events WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_comment(alert_id: int, author_user_id: int, body: str) -> dict:
    body = body.strip()
    if not body:
        raise ValueError("comment body must not be empty")
    if len(body) > 4000:
        raise ValueError("comment is too long")
    with _connection() as connection:
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        cursor = connection.execute(
            "INSERT INTO alert_comments (alert_id, author_user_id, body) VALUES (?, ?, ?)",
            (alert_id, author_user_id, body),
        )
        comment_id = int(cursor.lastrowid)
        row = connection.execute(
            "SELECT id, alert_id, author_user_id, body, created_at "
            "FROM alert_comments WHERE id = ?",
            (comment_id,),
        ).fetchone()
    return dict(row)


def list_comments(alert_id: int) -> list[dict]:
    with _connection() as connection:
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        rows = connection.execute(
            "SELECT id, alert_id, author_user_id, body, created_at "
            "FROM alert_comments WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _normalize_tag(tag: str) -> str:
    normalized = tag.strip().lower()
    if not normalized:
        raise ValueError("tag must not be empty")
    if len(normalized) > 48:
        raise ValueError("tag is too long")
    return normalized


def add_tag(alert_id: int, tag: str) -> list[str]:
    normalized = _normalize_tag(tag)
    with _connection() as connection:
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        connection.execute(
            "INSERT OR IGNORE INTO alert_tags (alert_id, tag) VALUES (?, ?)",
            (alert_id, normalized),
        )
        return _tags_for(connection, alert_id)


def remove_tag(alert_id: int, tag: str) -> list[str]:
    normalized = _normalize_tag(tag)
    with _connection() as connection:
        if connection.execute(
            "SELECT 1 FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone() is None:
            raise AlertNotFoundError("Alerte introuvable.")
        connection.execute(
            "DELETE FROM alert_tags WHERE alert_id = ? AND tag = ?",
            (alert_id, normalized),
        )
        return _tags_for(connection, alert_id)


def status_counts() -> dict[str, int]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS c FROM alerts GROUP BY status"
        ).fetchall()
    counts = {status: 0 for status in ALERT_STATUSES}
    for row in rows:
        counts[row["status"]] = int(row["c"])
    return counts


# Alerts in these statuses still need SOC attention; the rest are terminal.
_ACTIVE_INCIDENT_STATUSES = ("OPEN", "ACKNOWLEDGED")

# Static, hardcoded aggregates for the SOC dashboard. Open alert statuses are spelled
# out inline so each statement stays a single module-level literal (no user input, no
# dynamic SQL assembly).
_COUNT_OPEN_ALERTS = (
    "SELECT COUNT(*) AS c FROM alerts "
    "WHERE status IN ('NEW', 'INVESTIGATING', 'CONFIRMED')"
)
_COUNT_UNASSIGNED_OPEN_ALERTS = (
    "SELECT COUNT(*) AS c FROM alerts "
    "WHERE assignee_user_id IS NULL AND status IN ('NEW', 'INVESTIGATING', 'CONFIRMED')"
)
_COUNT_CRITICAL_OPEN_ALERTS = (
    "SELECT COUNT(*) AS c FROM alerts "
    "WHERE severity = 'CRITICAL' AND status IN ('NEW', 'INVESTIGATING', 'CONFIRMED')"
)


def soc_overview() -> dict:
    """Aggregate live SOC metrics from the alert and incident tables.

    Every figure is computed from rows that actually exist; nothing is estimated or
    synthesised. Used by the SOC dashboard.
    """
    with _connection() as connection:
        status_rows = connection.execute(
            "SELECT status, COUNT(*) AS c FROM alerts GROUP BY status"
        ).fetchall()
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()
        open_row = connection.execute(_COUNT_OPEN_ALERTS).fetchone()
        unassigned_row = connection.execute(_COUNT_UNASSIGNED_OPEN_ALERTS).fetchone()
        critical_row = connection.execute(_COUNT_CRITICAL_OPEN_ALERTS).fetchone()
        incident_rows = connection.execute(
            "SELECT status, COUNT(*) AS c FROM incidents GROUP BY status"
        ).fetchall()

    by_status = {status: 0 for status in ALERT_STATUSES}
    for row in status_rows:
        by_status[row["status"]] = int(row["c"])
    by_severity = {severity: 0 for severity in ALERT_SEVERITIES}
    for row in severity_rows:
        by_severity[row["severity"]] = int(row["c"])
    incidents_by_status = {status: 0 for status in ("OPEN", "ACKNOWLEDGED", "RESOLVED")}
    for row in incident_rows:
        if row["status"] in incidents_by_status:
            incidents_by_status[row["status"]] = int(row["c"])

    return {
        "alerts": {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "by_severity": by_severity,
            "open": int(open_row["c"]),
            "unassigned_open": int(unassigned_row["c"]),
            "critical_open": int(critical_row["c"]),
        },
        "incidents": {
            "total": sum(incidents_by_status.values()),
            "by_status": incidents_by_status,
            "active": sum(
                incidents_by_status[status] for status in _ACTIVE_INCIDENT_STATUSES
            ),
        },
    }

