"""ML monitoring computed exclusively from stored detections and analyst feedback.

We do not persist raw features, so classic feature-drift metrics (PSI/KS on inputs) are
impossible here and are NOT fabricated. Instead we report honest, reproducible signals:
prediction/severity distributions per module, the model versions actually in use, the
false-positive rate derived from analyst verdicts, and a prediction-rate drift between
the two halves of the observation window.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

from backend.app.core.config import settings

_MALICIOUS_PREDICTIONS = {"malicious", "phishing"}

_HISTORY_IN_WINDOW = (
    "SELECT module, prediction, severity, model_name, model_version, created_at "
    "FROM analysis_history WHERE created_at >= ? ORDER BY id"
)
_ALL_FEEDBACK = (
    "SELECT module, model_name, model_version, verdict, created_at "
    "FROM model_feedback WHERE created_at >= ? ORDER BY id"
)
_SELECT_FEEDBACK = (
    "SELECT id, alert_id, history_id, module, model_name, model_version, verdict, "
    "created_by, created_at FROM model_feedback ORDER BY id DESC LIMIT ? OFFSET ?"
)


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


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def monitoring_summary(days: int = 30) -> dict:
    if not 1 <= days <= 30:
        raise ValueError("days must be between 1 and 30")
    now = datetime.now(timezone.utc)
    start_text = _iso(now - timedelta(days=days))
    mid_text = _iso(now - timedelta(days=days / 2))

    with _connection() as connection:
        history_rows = connection.execute(_HISTORY_IN_WINDOW, (start_text,)).fetchall()
        feedback_rows = connection.execute(_ALL_FEEDBACK, (start_text,)).fetchall()

    modules: dict[str, dict] = {}
    for row in history_rows:
        module = row["module"]
        bucket = modules.setdefault(
            module,
            {
                "total": 0,
                "malicious": 0,
                "by_prediction": {},
                "by_severity": {},
                "recent_total": 0,
                "recent_malicious": 0,
                "prior_total": 0,
                "prior_malicious": 0,
                "models": {},
            },
        )
        is_malicious = row["prediction"] in _MALICIOUS_PREDICTIONS
        bucket["total"] += 1
        bucket["malicious"] += int(is_malicious)
        bucket["by_prediction"][row["prediction"]] = bucket["by_prediction"].get(row["prediction"], 0) + 1
        if row["severity"]:
            bucket["by_severity"][row["severity"]] = bucket["by_severity"].get(row["severity"], 0) + 1
        model_key = f"{row['model_name'] or 'unknown'}@{row['model_version'] or 'unknown'}"
        bucket["models"][model_key] = bucket["models"].get(model_key, 0) + 1
        if row["created_at"] >= mid_text:
            bucket["recent_total"] += 1
            bucket["recent_malicious"] += int(is_malicious)
        else:
            bucket["prior_total"] += 1
            bucket["prior_malicious"] += int(is_malicious)

    module_summaries = {}
    for module, bucket in modules.items():
        recent_rate = _rate(bucket["recent_malicious"], bucket["recent_total"])
        prior_rate = _rate(bucket["prior_malicious"], bucket["prior_total"])
        drift = (
            round(recent_rate - prior_rate, 4)
            if recent_rate is not None and prior_rate is not None
            else None
        )
        module_summaries[module] = {
            "total": bucket["total"],
            "malicious": bucket["malicious"],
            "malicious_rate": _rate(bucket["malicious"], bucket["total"]),
            "by_prediction": bucket["by_prediction"],
            "by_severity": bucket["by_severity"],
            "models": bucket["models"],
            "drift": {
                "recent_malicious_rate": recent_rate,
                "prior_malicious_rate": prior_rate,
                "delta": drift,
                "note": (
                    "Écart du taux de prédiction malveillante entre la seconde et la "
                    "première moitié de la fenêtre. Calculé sur les détections stockées."
                ),
            },
        }

    feedback = {"false_positive": 0, "confirmed": 0, "by_model": {}}
    for row in feedback_rows:
        verdict = row["verdict"]
        if verdict in feedback:
            feedback[verdict] += 1
        model_key = f"{row['model_name'] or 'unknown'}@{row['model_version'] or 'unknown'}"
        per_model = feedback["by_model"].setdefault(
            model_key, {"false_positive": 0, "confirmed": 0}
        )
        if verdict in per_model:
            per_model[verdict] += 1
    total_verdicts = feedback["false_positive"] + feedback["confirmed"]
    feedback["total"] = total_verdicts
    feedback["false_positive_rate"] = _rate(feedback["false_positive"], total_verdicts)

    return {
        "window_days": days,
        "total_analyses": len(history_rows),
        "modules": module_summaries,
        "feedback": feedback,
    }


def list_feedback(limit: int = 50, offset: int = 0) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    with _connection() as connection:
        rows = connection.execute(_SELECT_FEEDBACK, (limit, offset)).fetchall()
    return [dict(row) for row in rows]
