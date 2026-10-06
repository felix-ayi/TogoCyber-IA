"""Cross-cutting SOC read models: alert investigation timeline and global search.

These queries span several tables (detections, alerts, incidents, comments, audit) but
never mutate anything. Every user-supplied value is bound through `?` placeholders; the
only concatenated SQL text is hardcoded. LIKE patterns escape the wildcard metacharacters
so a search term is matched literally and cannot widen its own scope.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings


class AlertNotFoundError(LookupError):
    """The alert under investigation does not exist."""


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


# Hardcoded, single-literal statements. LIKE patterns are always bound parameters using
# '\' as the ESCAPE character so %, _ and \ in the search term are treated literally.
_ALERT_SEARCH = (
    "SELECT id, title, severity, status, created_at FROM alerts "
    "WHERE title LIKE ? ESCAPE '\\' "
    "OR EXISTS (SELECT 1 FROM alert_tags t WHERE t.alert_id = alerts.id AND t.tag LIKE ? ESCAPE '\\') "
    "ORDER BY created_at DESC, id DESC LIMIT ?"
)
_INCIDENT_SEARCH = (
    "SELECT id, module, prediction, severity, status, created_at FROM incidents "
    "WHERE module LIKE ? ESCAPE '\\' OR prediction LIKE ? ESCAPE '\\' "
    "ORDER BY id DESC LIMIT ?"
)
_HISTORY_SEARCH = (
    "SELECT id, module, prediction, severity, confidence_level, created_at "
    "FROM analysis_history "
    "WHERE module LIKE ? ESCAPE '\\' OR prediction LIKE ? ESCAPE '\\' "
    "ORDER BY id DESC LIMIT ?"
)
_AUDIT_SEARCH = (
    "SELECT id, action, outcome, target_type, target_id, created_at FROM audit_events "
    "WHERE action LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?"
)


def _like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def global_search(term: str, limit: int = 20) -> dict:
    """Search alerts, incidents, detections and audit actions for a literal term.

    Returns results grouped by entity type. Raises ValueError on an empty term or an
    out-of-range limit.
    """
    term = term.strip()
    if not term:
        raise ValueError("search term must not be empty")
    if len(term) > 200:
        raise ValueError("search term is too long")
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")

    pattern = _like_pattern(term)
    with _connection() as connection:
        alert_rows = connection.execute(_ALERT_SEARCH, (pattern, pattern, limit)).fetchall()
        incident_rows = connection.execute(_INCIDENT_SEARCH, (pattern, pattern, limit)).fetchall()
        history_rows = connection.execute(_HISTORY_SEARCH, (pattern, pattern, limit)).fetchall()
        audit_rows = connection.execute(_AUDIT_SEARCH, (pattern, limit)).fetchall()

    return {
        "term": term,
        "alerts": [dict(row) for row in alert_rows],
        "incidents": [dict(row) for row in incident_rows],
        "detections": [dict(row) for row in history_rows],
        "audit_events": [dict(row) for row in audit_rows],
    }


def _user_emails(connection: sqlite3.Connection) -> dict[int, str]:
    rows = connection.execute("SELECT id, email FROM users").fetchall()
    return {int(row["id"]): row["email"] for row in rows}


def alert_timeline(alert_id: int) -> list[dict]:
    """Build a single chronological investigation timeline for one alert.

    Merges the source detection, alert status transitions, comments, any linked
    incident's status transitions, and audit events that targeted the alert. Raises
    AlertNotFoundError when the alert does not exist.
    """
    events: list[dict] = []
    with _connection() as connection:
        alert = connection.execute(
            "SELECT id, history_id, incident_id, module, title, severity, risk_score, created_at "
            "FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert is None:
            raise AlertNotFoundError("Alerte introuvable.")
        emails = _user_emails(connection)

        history_id = alert["history_id"]
        if history_id is not None:
            detection = connection.execute(
                "SELECT module, prediction, severity, risk_score, confidence_level, created_at "
                "FROM analysis_history WHERE id = ?",
                (history_id,),
            ).fetchone()
            if detection is not None:
                events.append(
                    {
                        "timestamp": detection["created_at"],
                        "kind": "detection",
                        "title": f"Détection {detection['module']}",
                        "detail": (
                            f"{detection['prediction']} · sévérité {detection['severity']} · "
                            f"risque {detection['risk_score']}/100"
                        ),
                        "actor_user_id": None,
                        "actor_email": None,
                    }
                )

        status_rows = connection.execute(
            "SELECT actor_user_id, previous_status, new_status, note, created_at "
            "FROM alert_status_events WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
        for row in status_rows:
            actor = row["actor_user_id"]
            previous = row["previous_status"]
            label = (
                "Alerte créée"
                if previous is None
                else f"Statut : {previous} → {row['new_status']}"
            )
            events.append(
                {
                    "timestamp": row["created_at"],
                    "kind": "alert_status",
                    "title": label,
                    "detail": row["note"],
                    "actor_user_id": actor,
                    "actor_email": emails.get(int(actor)) if actor is not None else None,
                }
            )

        comment_rows = connection.execute(
            "SELECT author_user_id, body, created_at FROM alert_comments "
            "WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
        for row in comment_rows:
            actor = row["author_user_id"]
            events.append(
                {
                    "timestamp": row["created_at"],
                    "kind": "comment",
                    "title": "Commentaire",
                    "detail": row["body"],
                    "actor_user_id": actor,
                    "actor_email": emails.get(int(actor)) if actor is not None else None,
                }
            )

        incident_id = alert["incident_id"]
        if incident_id is not None:
            incident_rows = connection.execute(
                "SELECT actor_user_id, previous_status, new_status, created_at "
                "FROM incident_status_events WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
            for row in incident_rows:
                actor = row["actor_user_id"]
                previous = row["previous_status"]
                label = (
                    f"Incident #{incident_id} ouvert"
                    if previous is None
                    else f"Incident #{incident_id} : {previous} → {row['new_status']}"
                )
                events.append(
                    {
                        "timestamp": row["created_at"],
                        "kind": "incident_status",
                        "title": label,
                        "detail": None,
                        "actor_user_id": actor,
                        "actor_email": emails.get(int(actor)) if actor is not None else None,
                    }
                )

        audit_rows = connection.execute(
            "SELECT actor_user_id, action, outcome, created_at FROM audit_events "
            "WHERE target_type = 'alert' AND target_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
        for row in audit_rows:
            actor = row["actor_user_id"]
            events.append(
                {
                    "timestamp": row["created_at"],
                    "kind": "audit",
                    "title": f"Audit · {row['action']}",
                    "detail": row["outcome"],
                    "actor_user_id": actor,
                    "actor_email": emails.get(int(actor)) if actor is not None else None,
                }
            )

    events.sort(key=lambda event: (event["timestamp"], event["kind"]))
    return events
