"""Append-only persistence for security-relevant actions without request contents."""

import sqlite3
from contextlib import contextmanager

from backend.app.core.config import settings

AUDIT_ACTIONS = {
    "auth.registered",
    "auth.login.succeeded",
    "auth.login.failed",
    "auth.login.rate_limited",
    "auth.logout",
    "user.provisioned",
    "user.role_changed",
    "user.activated",
    "user.deactivated",
    "user.deleted",
    "user.password_reset",
    "incident.status_changed",
    "alert.status_changed",
    "alert.assigned",
    "alert.comment_added",
    "alert.tag_added",
    "alert.tag_removed",
    "ioc.created",
    "ioc.updated",
    "ioc.deleted",
    "ioc.tag_added",
    "ioc.tag_removed",
    "rule.created",
    "rule.updated",
    "rule.deleted",
    "correlation.run",
    "notification.dispatch",
    "playbook.created",
    "playbook.updated",
    "playbook.deleted",
}
AUDIT_TARGET_TYPES = {"auth", "user", "incident", "alert", "ioc", "rule", "playbook"}
_TARGET_TYPES = AUDIT_TARGET_TYPES
_OUTCOMES = {"success", "failure"}


@contextmanager
def _connection():
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def record_event(
    action: str,
    outcome: str,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
) -> int:
    if action not in AUDIT_ACTIONS:
        raise ValueError("unsupported audit action")
    if outcome not in _OUTCOMES:
        raise ValueError("unsupported audit outcome")
    if target_type is not None and target_type not in _TARGET_TYPES:
        raise ValueError("unsupported audit target")
    if target_type is None and target_id is not None:
        raise ValueError("audit target ID requires a target type")
    if target_type in {"user", "incident", "alert", "ioc", "rule", "playbook"} and target_id is None:
        raise ValueError("this target type requires an ID")
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO audit_events "
            "(actor_user_id, action, outcome, target_type, target_id) VALUES (?, ?, ?, ?, ?)",
            (actor_user_id, action, outcome, target_type, target_id),
        )
        return int(cursor.lastrowid)


def list_events(limit: int = 50, action: str | None = None, offset: int = 0) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if action is not None and action not in AUDIT_ACTIONS:
        raise ValueError("unsupported audit action")
    query = (
        "SELECT id, actor_user_id, action, outcome, target_type, target_id, created_at "
        "FROM audit_events"
    )
    parameters: tuple[object, ...] = ()
    if action is not None:
        query += " WHERE action = ?"
        parameters = (action,)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    parameters += (limit, offset)
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]
