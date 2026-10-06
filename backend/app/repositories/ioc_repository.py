"""SQLite persistence for the locally-curated threat-intelligence indicator store.

Indicators are added and maintained by analysts; nothing here invents or imports data
from an external feed. Values are validated and normalised per type before storage, and
every value that reaches SQL is bound through `?` placeholders.
"""

import ipaddress
import re
import sqlite3
from contextlib import contextmanager
from collections.abc import Generator

from backend.app.core.config import settings

IOC_TYPES = {"ip", "domain", "url", "hash", "email"}
IOC_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
IOC_STATUSES = {"ACTIVE", "EXPIRED", "REVOKED"}

_HASH_LENGTHS = {32, 40, 64, 128}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
_HEX_RE = re.compile(r"^[a-f0-9]+$")

_SELECT_IOC = (
    "SELECT id, type, value, severity, confidence, source, description, status, "
    "expires_at, created_by, created_at, updated_at FROM iocs"
)
_SELECT_IOC_BY_ID = _SELECT_IOC + " WHERE id = ?"


class IocNotFoundError(LookupError):
    """The indicator does not exist."""


class DuplicateIocError(ValueError):
    """An identical (type, value) indicator already exists."""


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


def _normalize_value(ioc_type: str, value: str) -> str:
    """Validate and canonicalise an indicator value for its declared type."""
    value = value.strip()
    if not value:
        raise ValueError("indicator value must not be empty")
    if len(value) > 2048:
        raise ValueError("indicator value is too long")

    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("adresse IP invalide.") from exc
    if ioc_type == "hash":
        candidate = value.lower()
        if len(candidate) not in _HASH_LENGTHS or not _HEX_RE.match(candidate):
            raise ValueError("empreinte invalide (MD5/SHA-1/SHA-256/SHA-512 attendue).")
        return candidate
    if ioc_type == "email":
        candidate = value.lower()
        if not _EMAIL_RE.match(candidate):
            raise ValueError("adresse e-mail invalide.")
        return candidate
    if ioc_type == "domain":
        candidate = value.lower().rstrip(".")
        if not _DOMAIN_RE.match(candidate):
            raise ValueError("nom de domaine invalide.")
        return candidate
    if ioc_type == "url":
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("URL invalide (http:// ou https:// attendu).")
        return value
    raise ValueError("unknown indicator type")


def _tags_for(connection: sqlite3.Connection, ioc_id: int) -> list[str]:
    rows = connection.execute(
        "SELECT tag FROM ioc_tags WHERE ioc_id = ? ORDER BY tag", (ioc_id,)
    ).fetchall()
    return [row["tag"] for row in rows]


def _row_to_dict(connection: sqlite3.Connection, row: sqlite3.Row) -> dict:
    item = dict(row)
    item["tags"] = _tags_for(connection, item["id"])
    return item


def create_ioc(
    ioc_type: str,
    value: str,
    severity: str,
    confidence: int,
    created_by: int | None = None,
    source: str | None = None,
    description: str | None = None,
    status: str = "ACTIVE",
    expires_at: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    if ioc_type not in IOC_TYPES:
        raise ValueError("unknown indicator type")
    if severity not in IOC_SEVERITIES:
        raise ValueError("unknown severity")
    if status not in IOC_STATUSES:
        raise ValueError("unknown status")
    if not 0 <= confidence <= 100:
        raise ValueError("confidence must be between 0 and 100")
    normalized = _normalize_value(ioc_type, value)
    with _connection() as connection:
        try:
            cursor = connection.execute(
                "INSERT INTO iocs (type, value, severity, confidence, source, description, "
                "status, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ioc_type,
                    normalized,
                    severity,
                    confidence,
                    source,
                    description,
                    status,
                    expires_at,
                    created_by,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateIocError("Un indicateur identique existe déjà.") from exc
        ioc_id = int(cursor.lastrowid)
        for tag in _clean_tags(tags):
            connection.execute(
                "INSERT OR IGNORE INTO ioc_tags (ioc_id, tag) VALUES (?, ?)", (ioc_id, tag)
            )
        row = connection.execute(_SELECT_IOC_BY_ID, (ioc_id,)).fetchone()
        return _row_to_dict(connection, row)


def _clean_tags(tags: list[str] | None) -> list[str]:
    cleaned: list[str] = []
    for tag in tags or []:
        normalized = tag.strip().lower()
        if not normalized or len(normalized) > 48:
            raise ValueError("tag must be 1-48 characters")
        if normalized not in cleaned:
            cleaned.append(normalized)
    return cleaned


def get_ioc(ioc_id: int) -> dict:
    with _connection() as connection:
        row = connection.execute(_SELECT_IOC_BY_ID, (ioc_id,)).fetchone()
        if row is None:
            raise IocNotFoundError("Indicateur introuvable.")
        return _row_to_dict(connection, row)


def list_iocs(
    limit: int = 50,
    ioc_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    tag: str | None = None,
    offset: int = 0,
) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if ioc_type is not None and ioc_type not in IOC_TYPES:
        raise ValueError("unknown indicator type")
    if status is not None and status not in IOC_STATUSES:
        raise ValueError("unknown status")
    if severity is not None and severity not in IOC_SEVERITIES:
        raise ValueError("unknown severity")

    query = _SELECT_IOC
    conditions: list[str] = []
    parameters: list[object] = []
    if ioc_type is not None:
        conditions.append("type = ?")
        parameters.append(ioc_type)
    if status is not None:
        conditions.append("status = ?")
        parameters.append(status)
    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)
    if tag is not None:
        conditions.append(
            "EXISTS (SELECT 1 FROM ioc_tags t WHERE t.ioc_id = iocs.id AND t.tag = ?)"
        )
        parameters.append(tag.strip().lower())
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.append(limit)
    parameters.append(offset)

    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
        return [_row_to_dict(connection, row) for row in rows]


_UPDATABLE_FIELDS = {
    "severity": IOC_SEVERITIES,
    "status": IOC_STATUSES,
}

# Static full-column update: mutable fields are merged over the stored row in Python so
# the statement text never varies (no dynamic SQL assembly).
_UPDATE_IOC = (
    "UPDATE iocs SET severity = ?, confidence = ?, source = ?, description = ?, "
    "status = ?, expires_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
    "WHERE id = ?"
)


def update_ioc(ioc_id: int, **fields) -> dict:
    """Update mutable indicator fields. `type` and `value` are immutable once created."""
    allowed = {"severity", "confidence", "source", "description", "status", "expires_at"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"cannot update fields: {', '.join(sorted(unknown))}")
    for name, valid_values in _UPDATABLE_FIELDS.items():
        if name in fields and fields[name] is not None and fields[name] not in valid_values:
            raise ValueError(f"unknown {name}")
    if "confidence" in fields and fields["confidence"] is not None:
        if not 0 <= fields["confidence"] <= 100:
            raise ValueError("confidence must be between 0 and 100")

    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(_SELECT_IOC_BY_ID, (ioc_id,)).fetchone()
        if row is None:
            raise IocNotFoundError("Indicateur introuvable.")
        merged = dict(row)
        merged.update(fields)
        connection.execute(
            _UPDATE_IOC,
            (
                merged["severity"],
                merged["confidence"],
                merged["source"],
                merged["description"],
                merged["status"],
                merged["expires_at"],
                ioc_id,
            ),
        )
        updated = connection.execute(_SELECT_IOC_BY_ID, (ioc_id,)).fetchone()
        return _row_to_dict(connection, updated)


def delete_ioc(ioc_id: int) -> None:
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
        if cursor.rowcount == 0:
            raise IocNotFoundError("Indicateur introuvable.")


def add_tag(ioc_id: int, tag: str) -> list[str]:
    normalized = _clean_tags([tag])[0]
    with _connection() as connection:
        if connection.execute("SELECT 1 FROM iocs WHERE id = ?", (ioc_id,)).fetchone() is None:
            raise IocNotFoundError("Indicateur introuvable.")
        connection.execute(
            "INSERT OR IGNORE INTO ioc_tags (ioc_id, tag) VALUES (?, ?)", (ioc_id, normalized)
        )
        return _tags_for(connection, ioc_id)


def remove_tag(ioc_id: int, tag: str) -> list[str]:
    normalized = _clean_tags([tag])[0]
    with _connection() as connection:
        if connection.execute("SELECT 1 FROM iocs WHERE id = ?", (ioc_id,)).fetchone() is None:
            raise IocNotFoundError("Indicateur introuvable.")
        connection.execute(
            "DELETE FROM ioc_tags WHERE ioc_id = ? AND tag = ?", (ioc_id, normalized)
        )
        return _tags_for(connection, ioc_id)


def lookup(value: str) -> list[dict]:
    """Return ACTIVE indicators whose value matches the supplied observable.

    The term is matched against the stored (normalised) value for every indicator type;
    a plain substring match on the raw value would miss canonical forms, so we compare
    against the exact normalised value where the type allows it.
    """
    value = value.strip()
    if not value:
        raise ValueError("lookup value must not be empty")
    candidates = {value, value.lower()}
    # Best-effort normalisation per type; invalid forms are simply skipped.
    for ioc_type in IOC_TYPES:
        try:
            candidates.add(_normalize_value(ioc_type, value))
        except ValueError:
            continue
    placeholders = ", ".join("?" for _ in candidates)
    query = _SELECT_IOC + " WHERE status = 'ACTIVE' AND value IN (" + placeholders + ")"
    query += " ORDER BY severity DESC, id DESC LIMIT ?"
    parameters = [*candidates, 50]
    with _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
        return [_row_to_dict(connection, row) for row in rows]


def status_counts() -> dict[str, int]:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS c FROM iocs GROUP BY status"
        ).fetchall()
    counts = {status: 0 for status in IOC_STATUSES}
    for row in rows:
        counts[row["status"]] = int(row["c"])
    return counts
