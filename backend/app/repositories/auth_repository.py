"""SQLite persistence for account identities, sessions, and login throttling."""

import hashlib
import hmac
import sqlite3
import time
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings


class DuplicateUserError(ValueError):
    """An account already exists for the normalized email address."""


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


def create_user(email: str, password_hash: str, role: str = "User") -> dict:
    if role not in {"Admin", "Analyst", "User"}:
        raise ValueError("unknown user role")
    with _connection() as connection:
        try:
            cursor = connection.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, password_hash, role),
            )
        except sqlite3.IntegrityError as exc:
            if "users.email" in str(exc):
                raise DuplicateUserError("Un compte existe déjà pour cette adresse e-mail.") from exc
            raise
        user_id = int(cursor.lastrowid)
    return {"id": user_id, "email": email, "role": role, "is_active": True}


def find_user_by_email(email: str) -> dict | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT id, email, password_hash, role, is_active FROM users WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
    return dict(row) if row is not None else None


def find_active_user(user_id: int) -> dict | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT id, email, role, is_active FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def list_users_detailed() -> list[dict]:
    """Users enriched with account status and last successful login (from audit)."""
    with _connection() as connection:
        rows = connection.execute(
            "SELECT u.id, u.email, u.role, u.is_active, u.created_at, "
            "(SELECT MAX(a.created_at) FROM audit_events a "
            " WHERE a.actor_user_id = u.id AND a.action = 'auth.login.succeeded') AS last_login "
            "FROM users u ORDER BY u.id"
        ).fetchall()
    return [
        {**dict(row), "is_active": bool(row["is_active"])}
        for row in rows
    ]


def get_user_by_id(user_id: int) -> dict | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT id, email, role, is_active, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return {**dict(row), "is_active": bool(row["is_active"])} if row is not None else None


def count_active_admins(exclude_user_id: int | None = None) -> int:
    query = "SELECT COUNT(*) AS c FROM users WHERE role = 'Admin' AND is_active = 1"
    parameters: tuple[object, ...] = ()
    if exclude_user_id is not None:
        query += " AND id != ?"
        parameters = (exclude_user_id,)
    with _connection() as connection:
        return int(connection.execute(query, parameters).fetchone()["c"])


def update_user_role(user_id: int, role: str) -> dict | None:
    with _connection() as connection:
        connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    return get_user_by_id(user_id)


def set_user_active(user_id: int, is_active: bool) -> dict | None:
    with _connection() as connection:
        connection.execute(
            "UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id)
        )
        if not is_active:
            connection.execute(
                "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (int(time.time()), user_id),
            )
    return get_user_by_id(user_id)


def replace_password_hash(user_id: int, password_hash: str) -> None:
    with _connection() as connection:
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )
        connection.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (int(time.time()), user_id),
        )


def delete_user(user_id: int) -> bool:
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0


def create_session(user_id: int, token_id_hash: str, expires_at: int) -> None:
    with _connection() as connection:
        connection.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ? OR "
            "(revoked_at IS NOT NULL AND revoked_at <= ?)",
            (int(time.time()), int(time.time()) - 7 * 24 * 60 * 60),
        )
        connection.execute(
            "INSERT INTO auth_sessions (user_id, token_id_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, token_id_hash, expires_at),
        )


def session_is_active(user_id: int, token_id_hash: str, now: int | None = None) -> bool:
    with _connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM auth_sessions WHERE user_id = ? AND token_id_hash = ? "
            "AND revoked_at IS NULL AND expires_at > ?",
            (user_id, token_id_hash, int(time.time()) if now is None else now),
        ).fetchone()
    return row is not None


def revoke_session(token_id_hash: str, now: int | None = None) -> None:
    with _connection() as connection:
        connection.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE token_id_hash = ? AND revoked_at IS NULL",
            (int(time.time()) if now is None else now, token_id_hash),
        )


def client_identifier_hash(client_identifier: str) -> str:
    return hmac.new(
        settings.auth_secret_key.encode("utf-8"),
        client_identifier.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def begin_login_attempt(
    client_hash: str,
    now: int,
    window_start: int,
    max_attempts: int,
) -> bool:
    with _connection() as connection:
        connection.execute(
            "DELETE FROM auth_login_attempts WHERE attempted_at < ?",
            (window_start,),
        )
        row = connection.execute(
            "SELECT COUNT(*) AS attempt_count FROM auth_login_attempts "
            "WHERE client_hash = ? AND attempted_at >= ?",
            (client_hash, window_start),
        ).fetchone()
        if int(row["attempt_count"]) >= max_attempts:
            return False
        connection.execute(
            "INSERT INTO auth_login_attempts (client_hash, attempted_at) VALUES (?, ?)",
            (client_hash, now),
        )
        return True


def clear_login_attempts(client_hash: str) -> None:
    with _connection() as connection:
        connection.execute(
            "DELETE FROM auth_login_attempts WHERE client_hash = ?",
            (client_hash,),
        )


def initialize_bootstrap_admin(email: str, password_hash: str) -> None:
    if not email:
        return
    if find_user_by_email(email) is None:
        create_user(email, password_hash, "Admin")
