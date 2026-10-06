"""Response playbooks: analyst-authored, ordered procedures attached to a module/severity.

Playbooks are documentation of the response process. They reference real modules and
severity tiers but never fabricate telemetry or automated actions against external systems.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings

PLAYBOOK_MODULES = {"network", "phishing", "any"}
PLAYBOOK_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}

_SELECT_PLAYBOOK = (
    "SELECT id, name, description, module, min_severity, created_by, created_at, updated_at "
    "FROM playbooks"
)
_SELECT_PLAYBOOK_BY_ID = _SELECT_PLAYBOOK + " WHERE id = ?"
_SELECT_STEPS = (
    "SELECT position, instruction FROM playbook_steps WHERE playbook_id = ? ORDER BY position, id"
)


class PlaybookNotFoundError(LookupError):
    """The playbook does not exist."""


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


def _normalise_steps(steps) -> list[str]:
    if steps is None:
        return []
    cleaned = [str(step).strip() for step in steps]
    cleaned = [step for step in cleaned if step]
    if len(cleaned) > 50:
        raise ValueError("a playbook cannot exceed 50 steps")
    for step in cleaned:
        if len(step) > 2000:
            raise ValueError("each step must be 2000 characters or fewer")
    return cleaned


def _validate(module: str, min_severity: str) -> None:
    if module not in PLAYBOOK_MODULES:
        raise ValueError("unknown playbook module")
    if min_severity not in PLAYBOOK_SEVERITIES:
        raise ValueError("unknown minimum severity")


def _with_steps(connection: sqlite3.Connection, row: sqlite3.Row) -> dict:
    result = dict(row)
    result["steps"] = [dict(step) for step in connection.execute(_SELECT_STEPS, (row["id"],)).fetchall()]
    return result


def _replace_steps(connection: sqlite3.Connection, playbook_id: int, steps: list[str]) -> None:
    connection.execute("DELETE FROM playbook_steps WHERE playbook_id = ?", (playbook_id,))
    for position, instruction in enumerate(steps, start=1):
        connection.execute(
            "INSERT INTO playbook_steps (playbook_id, position, instruction) VALUES (?, ?, ?)",
            (playbook_id, position, instruction),
        )


def create_playbook(
    name: str,
    module: str,
    min_severity: str,
    created_by: int | None = None,
    description: str | None = None,
    steps: list[str] | None = None,
) -> dict:
    name = (name or "").strip()
    if not name or len(name) > 200:
        raise ValueError("playbook name must be 1-200 characters")
    _validate(module, min_severity)
    cleaned_steps = _normalise_steps(steps)
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO playbooks (name, description, module, min_severity, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, description, module, min_severity, created_by),
        )
        playbook_id = int(cursor.lastrowid)
        _replace_steps(connection, playbook_id, cleaned_steps)
        row = connection.execute(_SELECT_PLAYBOOK_BY_ID, (playbook_id,)).fetchone()
        return _with_steps(connection, row)


def get_playbook(playbook_id: int) -> dict:
    with _connection() as connection:
        row = connection.execute(_SELECT_PLAYBOOK_BY_ID, (playbook_id,)).fetchone()
        if row is None:
            raise PlaybookNotFoundError("Playbook introuvable.")
        return _with_steps(connection, row)


def list_playbooks(module: str | None = None) -> list[dict]:
    if module is not None and module not in PLAYBOOK_MODULES:
        raise ValueError("unknown playbook module")
    query = _SELECT_PLAYBOOK
    parameters: list[object] = []
    if module is not None:
        query += " WHERE module = ?"
        parameters.append(module)
    query += " ORDER BY updated_at DESC, id DESC"
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
        return [_with_steps(connection, row) for row in rows]


def update_playbook(playbook_id: int, **fields) -> dict:
    allowed = {"name", "description", "module", "min_severity", "steps"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"cannot update fields: {', '.join(sorted(unknown))}")
    current = get_playbook(playbook_id)
    merged = {**current, **fields}
    if "name" in fields:
        name = (fields["name"] or "").strip()
        if not name or len(name) > 200:
            raise ValueError("playbook name must be 1-200 characters")
        merged["name"] = name
    _validate(merged["module"], merged["min_severity"])
    cleaned_steps = _normalise_steps(merged.get("steps"))
    with _connection() as connection:
        connection.execute(
            "UPDATE playbooks SET name = ?, description = ?, module = ?, min_severity = ?, "
            "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (
                merged["name"],
                merged["description"],
                merged["module"],
                merged["min_severity"],
                playbook_id,
            ),
        )
        _replace_steps(connection, playbook_id, cleaned_steps)
        row = connection.execute(_SELECT_PLAYBOOK_BY_ID, (playbook_id,)).fetchone()
        return _with_steps(connection, row)


def delete_playbook(playbook_id: int) -> None:
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        if cursor.rowcount == 0:
            raise PlaybookNotFoundError("Playbook introuvable.")
