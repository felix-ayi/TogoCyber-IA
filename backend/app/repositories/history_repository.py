"""SQLite history stores prediction metadata only; never message text or flow features."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from backend.app.core.config import settings
from backend.app.models.database_models import SCHEMA_SQL
from backend.app.repositories.audit_repository import AUDIT_ACTIONS, AUDIT_TARGET_TYPES

# Row-preserving rebuild of audit_events for when its CHECK constraints predate newer
# actions or target types. SQLite cannot ALTER a CHECK, so the table is recreated and
# every row copied across. __ACTION_LIST__ and __TARGET_TYPE_LIST__ are filled from the
# hardcoded AUDIT_ACTIONS / AUDIT_TARGET_TYPES constants (never user input), mirroring
# the SCHEMA_SQL module-constant pattern.
_AUDIT_MIGRATION_TEMPLATE = """
    CREATE TABLE audit_events_migrated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        action TEXT NOT NULL CHECK (action IN (
            __ACTION_LIST__
        )),
        outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
        target_type TEXT CHECK (target_type IN (__TARGET_TYPE_LIST__)),
        target_id INTEGER,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    INSERT INTO audit_events_migrated
        (id, actor_user_id, action, outcome, target_type, target_id, created_at)
        SELECT id, actor_user_id, action, outcome, target_type, target_id, created_at
        FROM audit_events;
    DROP TABLE audit_events;
    ALTER TABLE audit_events_migrated RENAME TO audit_events;
    CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
        ON audit_events(created_at DESC, id DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_events_actor
        ON audit_events(actor_user_id, created_at DESC);
    CREATE TRIGGER IF NOT EXISTS audit_events_prevent_update
    BEFORE UPDATE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit events are immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS audit_events_prevent_delete
    BEFORE DELETE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit events are immutable');
    END;
    """


def _connect() -> sqlite3.Connection:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def database_ok() -> bool:
    """Cheap liveness probe for the SQLite store (used by the health endpoint)."""
    try:
        with _connection() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False


_MODULE_LABELS = {"network": "réseau", "phishing": "phishing/SMS"}


def _alert_title(module: str, prediction: str, severity: str) -> str:
    label = _MODULE_LABELS.get(module, module)
    return f"Détection {label} : {prediction} ({severity})"


def initialize_database() -> None:
    with _connection() as connection:
        connection.executescript(SCHEMA_SQL)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(analysis_history)").fetchall()
        }
        if "user_id" not in columns:
            connection.execute(
                "ALTER TABLE analysis_history ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
            )
        optional_columns = {
            "risk_score": "INTEGER CHECK (risk_score BETWEEN 0 AND 100)",
            "severity": "TEXT CHECK (severity IN ('VERY_LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))",
            "model_name": "TEXT",
            "model_version": "TEXT",
        }
        for name, declaration in optional_columns.items():
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE analysis_history ADD COLUMN {name} {declaration}"
                )
        _migrate_audit_events(connection)
    purge_expired()


def _migrate_audit_events(connection: sqlite3.Connection) -> None:
    """Rebuild audit_events when its CHECK constraints predate newer actions/target types.

    SQLite cannot ALTER a CHECK constraint, so the table is recreated and every row
    copied across; the immutability triggers and indexes are then restored. Idempotent:
    it is a no-op once the newer actions and target types are present.
    """
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
    ).fetchone()
    if row is None:
        return
    existing_sql = row["sql"] or ""
    if all(f"'{action}'" in existing_sql for action in AUDIT_ACTIONS) and all(
        f"'{target}'" in existing_sql for target in AUDIT_TARGET_TYPES
    ):
        return
    action_list = ",\n        ".join(f"'{action}'" for action in sorted(AUDIT_ACTIONS))
    target_list = ", ".join(f"'{target}'" for target in sorted(AUDIT_TARGET_TYPES))
    migration_sql = (
        _AUDIT_MIGRATION_TEMPLATE.replace("__ACTION_LIST__", action_list).replace(
            "__TARGET_TYPE_LIST__", target_list
        )
    )
    connection.executescript(migration_sql)


def purge_expired(now: datetime | None = None) -> int:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=settings.retention_days)
    cutoff_text = cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM analysis_history WHERE created_at < ?", (cutoff_text,))
        purged = cursor.rowcount
        # Ephemeral SOC artefacts share the same retention window: the notification outbox
        # and correlation findings (the latter cascade to correlation_finding_alerts).
        # Alerts, incidents, model_feedback and the immutable audit log are deliberately
        # never purged here — they are the operational record of the SOC.
        connection.execute("DELETE FROM notifications WHERE created_at < ?", (cutoff_text,))
        connection.execute("DELETE FROM correlation_findings WHERE created_at < ?", (cutoff_text,))
        connection.execute("DELETE FROM events WHERE ingested_at < ?", (cutoff_text,))
        return purged


def record_event(
    module: str,
    prediction: str,
    confidence: float,
    confidence_level: str,
    user_id: int | None = None,
    risk_score: int | None = None,
    severity: str | None = None,
    model_name: str | None = None,
    model_version: str | None = None,
) -> int:
    if module not in {"network", "phishing"}:
        raise ValueError("unknown history module")
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO analysis_history "
            "(module, prediction, confidence, confidence_level, user_id, risk_score, severity, model_name, model_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                module,
                prediction,
                confidence,
                confidence_level,
                user_id,
                risk_score,
                severity,
                model_name,
                model_version,
            ),
        )
        event_id = int(cursor.lastrowid)
        incident_id = None
        if user_id is not None and severity in {"HIGH", "CRITICAL"} and risk_score is not None:
            incident_cursor = connection.execute(
                "INSERT INTO incidents "
                "(history_id, owner_user_id, module, prediction, risk_score, severity) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, user_id, module, prediction, risk_score, severity),
            )
            incident_id = int(incident_cursor.lastrowid)
            connection.execute(
                "INSERT INTO incident_status_events "
                "(incident_id, previous_status, new_status) VALUES (?, NULL, 'OPEN')",
                (incident_id,),
            )
        # Alerts are the SOC triage queue: a broader net than incidents (MEDIUM and up),
        # linked to the source detection and, when one was raised, its incident.
        if severity in {"MEDIUM", "HIGH", "CRITICAL"} and risk_score is not None:
            alert_cursor = connection.execute(
                "INSERT INTO alerts "
                "(history_id, incident_id, module, title, severity, risk_score) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, incident_id, module, _alert_title(module, prediction, severity), severity, risk_score),
            )
            alert_id = int(alert_cursor.lastrowid)
            connection.execute(
                "INSERT INTO alert_status_events "
                "(alert_id, previous_status, new_status) VALUES (?, NULL, 'NEW')",
                (alert_id,),
            )
            # HIGH/CRITICAL alerts are queued for operator notification. No delivery
            # channel is configured in this deployment, so the outbox row is recorded
            # with delivery_status 'not_configured' rather than pretending it was sent.
            if severity in {"HIGH", "CRITICAL"}:
                title = _alert_title(module, prediction, severity)
                connection.execute(
                    "INSERT INTO notifications "
                    "(event_type, severity, subject, body, channel, delivery_status) "
                    "VALUES (?, ?, ?, ?, ?, 'not_configured')",
                    (
                        "alert.raised",
                        severity,
                        title,
                        f"Alerte #{alert_id} créée (module {_MODULE_LABELS.get(module, module)}, "
                        f"score de risque {risk_score}/100).",
                        "email",
                    ),
                )
    purge_expired()
    return event_id


def get_incident_id_for_history(history_id: int) -> int | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT id FROM incidents WHERE history_id = ?",
            (history_id,),
        ).fetchone()
    return int(row["id"]) if row is not None else None


def list_incidents(
    limit: int = 50,
    user_id: int | None = None,
    status: str | None = None,
    offset: int = 0,
) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if status is not None and status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("unknown incident status")

    query = (
        "SELECT id, history_id, owner_user_id, module, prediction, risk_score, "
        "severity, status, created_at, updated_at FROM incidents"
    )
    conditions: list[str] = []
    parameters: list[object] = []
    if user_id is not None:
        conditions.append("owner_user_id = ?")
        parameters.append(user_id)
    if status is not None:
        conditions.append("status = ?")
        parameters.append(status)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_incident_status_events(incident_id: int, user_id: int | None = None) -> list[dict] | None:
    with _connection() as connection:
        incident_query = "SELECT 1 FROM incidents WHERE id = ?"
        incident_parameters: list[object] = [incident_id]
        if user_id is not None:
            incident_query += " AND owner_user_id = ?"
            incident_parameters.append(user_id)
        if connection.execute(incident_query, incident_parameters).fetchone() is None:
            return None
        rows = connection.execute(
            "SELECT id, incident_id, actor_user_id, previous_status, new_status, created_at "
            "FROM incident_status_events WHERE incident_id = ? ORDER BY id",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


class IncidentNotFoundError(LookupError):
    """The incident does not exist or is outside the caller's scope."""


class InvalidIncidentTransitionError(ValueError):
    """The requested incident status transition is not allowed."""


def update_incident_status(
    incident_id: int,
    new_status: str,
    actor_user_id: int,
) -> dict:
    if new_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("unknown incident status")
    allowed_transitions = {
        "OPEN": {"ACKNOWLEDGED"},
        "ACKNOWLEDGED": {"OPEN", "RESOLVED"},
        "RESOLVED": {"ACKNOWLEDGED"},
    }
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise IncidentNotFoundError("Incident introuvable.")
        previous_status = str(row["status"])
        if new_status not in allowed_transitions[previous_status]:
            raise InvalidIncidentTransitionError(
                f"Transition impossible : {previous_status} vers {new_status}."
            )
        connection.execute(
            "UPDATE incidents SET status = ?, updated_at = "
            "strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (new_status, incident_id),
        )
        connection.execute(
            "INSERT INTO incident_status_events "
            "(incident_id, actor_user_id, previous_status, new_status) VALUES (?, ?, ?, ?)",
            (incident_id, actor_user_id, previous_status, new_status),
        )
        updated = connection.execute(
            "SELECT id, history_id, owner_user_id, module, prediction, risk_score, "
            "severity, status, created_at, updated_at FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
    return dict(updated)


def list_events(limit: int = 50, user_id: int | None = None, offset: int = 0) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    purge_expired()
    with _connection() as connection:
        if user_id is None:
            rows = connection.execute(
                "SELECT id, module, prediction, confidence, confidence_level, created_at "
                ", risk_score, severity, model_name, model_version "
                "FROM analysis_history ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT id, module, prediction, confidence, confidence_level, created_at "
                ", risk_score, severity, model_name, model_version "
                "FROM analysis_history WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (user_id, limit, offset),
            ).fetchall()
    return [dict(row) for row in rows]