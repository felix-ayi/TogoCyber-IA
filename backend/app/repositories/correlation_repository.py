"""Detection rules and the alert correlation engine.

Rules are analyst-authored thresholds ("at least N alerts of severity >= S for module M
within W minutes"). `run_correlation` evaluates every active rule against the alerts that
actually exist and records a finding linking the matched alerts. Nothing is synthesised:
a finding is only created when real alerts satisfy a real rule.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

from backend.app.core.config import settings

RULE_MODULES = {"network", "phishing", "any"}
SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}
_SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
FINDING_STATUSES = {"OPEN", "ACKNOWLEDGED", "CLOSED"}

_SELECT_RULE = (
    "SELECT id, name, description, module, min_severity, threshold, window_minutes, "
    "is_active, created_by, created_at, updated_at FROM detection_rules"
)
_SELECT_RULE_BY_ID = _SELECT_RULE + " WHERE id = ?"
_SELECT_FINDING = (
    "SELECT id, rule_id, alert_count, window_start, window_end, status, created_at "
    "FROM correlation_findings"
)
_SELECT_FINDING_BY_ID = _SELECT_FINDING + " WHERE id = ?"
_ALERTS_SINCE = (
    "SELECT id, module, severity, created_at FROM alerts WHERE created_at >= ? ORDER BY id"
)
_ACTIVE_RULES = _SELECT_RULE + " WHERE is_active = 1 ORDER BY id"
_OPEN_FINDINGS_FOR_RULE = (
    "SELECT id FROM correlation_findings WHERE rule_id = ? AND status = 'OPEN'"
)
_FINDING_ALERT_IDS = (
    "SELECT alert_id FROM correlation_finding_alerts WHERE finding_id = ? ORDER BY alert_id"
)


class RuleNotFoundError(LookupError):
    """The detection rule does not exist."""


class FindingNotFoundError(LookupError):
    """The correlation finding does not exist."""


class InvalidFindingTransitionError(ValueError):
    """The requested finding status transition is not allowed."""


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


def _validate_rule(module: str, min_severity: str, threshold: int, window_minutes: int) -> None:
    if module not in RULE_MODULES:
        raise ValueError("unknown rule module")
    if min_severity not in SEVERITIES:
        raise ValueError("unknown minimum severity")
    if not 2 <= threshold <= 100:
        raise ValueError("threshold must be between 2 and 100")
    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")


def create_rule(
    name: str,
    module: str,
    min_severity: str,
    threshold: int,
    window_minutes: int,
    created_by: int | None = None,
    description: str | None = None,
    is_active: bool = True,
) -> dict:
    name = name.strip()
    if not name or len(name) > 200:
        raise ValueError("rule name must be 1-200 characters")
    _validate_rule(module, min_severity, threshold, window_minutes)
    with _connection() as connection:
        cursor = connection.execute(
            "INSERT INTO detection_rules (name, description, module, min_severity, "
            "threshold, window_minutes, is_active, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, description, module, min_severity, threshold, window_minutes, int(bool(is_active)), created_by),
        )
        row = connection.execute(_SELECT_RULE_BY_ID, (int(cursor.lastrowid),)).fetchone()
    return dict(row)


def get_rule(rule_id: int) -> dict:
    with _connection() as connection:
        row = connection.execute(_SELECT_RULE_BY_ID, (rule_id,)).fetchone()
    if row is None:
        raise RuleNotFoundError("Règle introuvable.")
    return dict(row)


def list_rules(include_inactive: bool = True) -> list[dict]:
    query = _SELECT_RULE
    if not include_inactive:
        query += " WHERE is_active = 1"
    query += " ORDER BY id DESC"
    with _connection() as connection:
        rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def update_rule(rule_id: int, **fields) -> dict:
    allowed = {"name", "description", "module", "min_severity", "threshold", "window_minutes", "is_active"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"cannot update fields: {', '.join(sorted(unknown))}")
    current = get_rule(rule_id)
    merged = {**current, **fields}
    if "name" in fields:
        name = (fields["name"] or "").strip()
        if not name or len(name) > 200:
            raise ValueError("rule name must be 1-200 characters")
        merged["name"] = name
    _validate_rule(merged["module"], merged["min_severity"], merged["threshold"], merged["window_minutes"])
    with _connection() as connection:
        connection.execute(
            "UPDATE detection_rules SET name = ?, description = ?, module = ?, "
            "min_severity = ?, threshold = ?, window_minutes = ?, is_active = ?, "
            "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
            (
                merged["name"],
                merged["description"],
                merged["module"],
                merged["min_severity"],
                merged["threshold"],
                merged["window_minutes"],
                int(bool(merged["is_active"])),
                rule_id,
            ),
        )
        row = connection.execute(_SELECT_RULE_BY_ID, (rule_id,)).fetchone()
    return dict(row)


def delete_rule(rule_id: int) -> None:
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))
        if cursor.rowcount == 0:
            raise RuleNotFoundError("Règle introuvable.")


def _cutoff_text(window_minutes: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    return cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _matches(rule: sqlite3.Row, alert: sqlite3.Row) -> bool:
    if rule["module"] != "any" and alert["module"] != rule["module"]:
        return False
    return _SEVERITY_RANK.get(alert["severity"], 0) >= _SEVERITY_RANK[rule["min_severity"]]


def run_correlation() -> dict:
    """Evaluate every active rule over recent alerts and record any new findings."""
    created: list[int] = []
    with _connection() as connection:
        rules = connection.execute(_ACTIVE_RULES).fetchall()
        for rule in rules:
            cutoff = _cutoff_text(rule["window_minutes"])
            alerts = connection.execute(_ALERTS_SINCE, (cutoff,)).fetchall()
            matched = [a for a in alerts if _matches(rule, a)]
            if len(matched) < rule["threshold"]:
                continue
            matched_ids = sorted(int(a["id"]) for a in matched)
            # Skip when an OPEN finding for this rule already covers exactly these alerts.
            existing = connection.execute(_OPEN_FINDINGS_FOR_RULE, (rule["id"],)).fetchall()
            already = False
            for finding in existing:
                ids = [int(r["alert_id"]) for r in connection.execute(_FINDING_ALERT_IDS, (finding["id"],)).fetchall()]
                if ids == matched_ids:
                    already = True
                    break
            if already:
                continue
            window_start = min(a["created_at"] for a in matched)
            window_end = max(a["created_at"] for a in matched)
            cursor = connection.execute(
                "INSERT INTO correlation_findings (rule_id, alert_count, window_start, window_end) "
                "VALUES (?, ?, ?, ?)",
                (rule["id"], len(matched_ids), window_start, window_end),
            )
            finding_id = int(cursor.lastrowid)
            for alert_id in matched_ids:
                connection.execute(
                    "INSERT INTO correlation_finding_alerts (finding_id, alert_id) VALUES (?, ?)",
                    (finding_id, alert_id),
                )
            created.append(finding_id)
    return {"rules_evaluated": len(rules) if rules else 0, "findings_created": created}


def _finding_alert_ids(connection: sqlite3.Connection, finding_id: int) -> list[int]:
    rows = connection.execute(_FINDING_ALERT_IDS, (finding_id,)).fetchall()
    return [int(row["alert_id"]) for row in rows]


def get_finding(finding_id: int) -> dict:
    with _connection() as connection:
        row = connection.execute(_SELECT_FINDING_BY_ID, (finding_id,)).fetchone()
        if row is None:
            raise FindingNotFoundError("Corrélation introuvable.")
        result = dict(row)
        result["alert_ids"] = _finding_alert_ids(connection, finding_id)
    return result


def list_findings(
    limit: int = 50,
    finding_status: str | None = None,
    rule_id: int | None = None,
    offset: int = 0,
) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if finding_status is not None and finding_status not in FINDING_STATUSES:
        raise ValueError("unknown finding status")
    query = _SELECT_FINDING
    conditions: list[str] = []
    parameters: list[object] = []
    if finding_status is not None:
        conditions.append("status = ?")
        parameters.append(finding_status)
    if rule_id is not None:
        conditions.append("rule_id = ?")
        parameters.append(rule_id)
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
            item["alert_ids"] = _finding_alert_ids(connection, item["id"])
            results.append(item)
    return results


_FINDING_TRANSITIONS = {
    "OPEN": {"ACKNOWLEDGED", "CLOSED"},
    "ACKNOWLEDGED": {"OPEN", "CLOSED"},
    "CLOSED": {"ACKNOWLEDGED"},
}


def update_finding_status(finding_id: int, new_status: str) -> dict:
    if new_status not in FINDING_STATUSES:
        raise ValueError("unknown finding status")
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status FROM correlation_findings WHERE id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise FindingNotFoundError("Corrélation introuvable.")
        if new_status not in _FINDING_TRANSITIONS[row["status"]]:
            raise InvalidFindingTransitionError(
                f"Transition impossible : {row['status']} vers {new_status}."
            )
        connection.execute(
            "UPDATE correlation_findings SET status = ? WHERE id = ?", (new_status, finding_id)
        )
    return get_finding(finding_id)
