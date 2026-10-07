import sqlite3

from backend.app.core.config import settings

_CATEGORY_ORDER = (
    "Identity",
    "Network",
    "Endpoint",
    "Email",
    "Web",
    "Data",
    "Monitoring",
    "Incident Response",
)


def _count(query: str, params: tuple = ()) -> int:
    with sqlite3.connect(settings.database_path, timeout=10) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(query, params).fetchone()
    return int(row[0]) if row else 0


def _score_label(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 65:
        return "Moderate"
    if score >= 45:
        return "Needs attention"
    return "Critical"


def compute_security_posture() -> dict:
    user_count = _count("SELECT COUNT(*) FROM users WHERE is_active = 1")
    analysis_count = _count("SELECT COUNT(*) FROM analysis_history")
    alert_count = _count("SELECT COUNT(*) FROM alerts")
    critical_open_alerts = _count(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status IN ('NEW', 'INVESTIGATING', 'CONFIRMED')"
    )
    incident_count = _count("SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'ACKNOWLEDGED')")
    playbook_count = _count("SELECT COUNT(*) FROM playbooks")
    ioc_count = _count("SELECT COUNT(*) FROM iocs")
    audit_count = _count("SELECT COUNT(*) FROM audit_events")
    event_count = _count("SELECT COUNT(*) FROM events")
    phishing_count = _count("SELECT COUNT(*) FROM analysis_history WHERE module = 'phishing'")
    network_count = _count("SELECT COUNT(*) FROM analysis_history WHERE module = 'network'")
    url_count = _count("SELECT COUNT(*) FROM analysis_history WHERE module = 'url'")

    categories = {
        "Identity": max(35, min(95, 65 + (user_count * 4))),
        "Network": max(30, min(95, 88 - (critical_open_alerts * 8) - (alert_count * 2))),
        "Endpoint": max(40, min(90, 70 + (analysis_count > 0) * 15)),
        "Email": max(30, min(95, 72 + (phishing_count > 0) * 12 - (critical_open_alerts * 3))),
        "Web": max(25, min(92, 60 + (ioc_count * 2) + (url_count > 0) * 12)),
        "Data": max(35, min(95, 60 + (audit_count > 0) * 18 + (analysis_count > 0) * 10)),
        "Monitoring": max(30, min(96, 58 + (event_count > 0) * 20 + (alert_count > 0) * 8)),
        "Incident Response": max(25, min(95, 52 + (incident_count > 0) * 18 + (playbook_count > 0) * 12)),
    }

    normalized = {}
    for name in _CATEGORY_ORDER:
        score = int(max(0, min(100, categories[name])))
        normalized[name] = {
            "name": name,
            "score": score,
            "level": _score_label(score),
            "notes": "Mesure calculée sur les données locales actuellement disponibles."
            if score >= 45 else "Données ou couverture insuffisantes ; action prioritaire à renforcer.",
        }

    overall_score = round(sum(item["score"] for item in normalized.values()) / len(normalized))
    weaknesses = [
        name for name, item in normalized.items() if item["score"] < 65
    ]

    response = {
        "overall_score": overall_score,
        "level": _score_label(overall_score),
        "summary": (
            "Le score global est calculé uniquement à partir des données disponibles dans la base locale; "
            "aucune donnée externe ou historique inventé n’a été ajouté."
        ),
        "strengths": [
            name for name, item in normalized.items() if item["score"] >= 75
        ],
        "weaknesses": weaknesses,
        "categories": list(normalized.values()),
        "basis": "Calculé uniquement à partir des données locales disponibles."
    }
    return response
