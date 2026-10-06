"""Typed-by-contract HTTP client with actionable errors for the Streamlit UI."""

import os
from pathlib import Path

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
API_BASE_URL = os.getenv("TOGOCYBER_API_URL", "http://localhost:8000").rstrip("/")
TIMEOUT_SECONDS = 12


class APIError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _request(method: str, path: str, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    token = st.session_state.get("auth_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.request(
            method, f"{API_BASE_URL}{path}", timeout=TIMEOUT_SECONDS, headers=headers, **kwargs,
        )
    except requests.Timeout as exc:
        raise APIError("L’API met trop de temps à répondre. Réessayez dans quelques instants.") from exc
    except requests.ConnectionError as exc:
        raise APIError("L’API TogoCyber AI est hors ligne. Vérifiez qu’elle est démarrée sur le port 8000.") from exc
    except requests.RequestException as exc:
        raise APIError("Impossible de joindre l’API. Vérifiez votre connexion puis réessayez.") from exc
    if response.status_code == 204:
        return None
    try:
        payload = response.json()
    except ValueError as exc:
        raise APIError(f"L’API a renvoyé une réponse invalide (HTTP {response.status_code}).") from exc
    if not response.ok:
        detail = payload.get("detail", "La requête n’a pas pu aboutir.") if isinstance(payload, dict) else "La requête n’a pas pu aboutir."
        raise APIError(f"{detail} (HTTP {response.status_code})", response.status_code)
    return payload


def analyze_network(features: dict) -> dict:
    return _request("POST", "/api/v1/network/analyze", json={"features": features})


def analyze_phishing(text: str) -> dict:
    return _request("POST", "/api/v1/phishing/analyze", json={"text": text})


def analyze_url(url: str) -> dict:
    return _request("POST", "/api/v1/url/analyze", json={"url": url})


def ask_assistant(message: str) -> dict:
    return _request("POST", "/api/v1/assistant/ask", json={"message": message})


def get_history(limit: int = 50) -> list[dict]:
    payload = _request("GET", "/api/v1/history", params={"limit": limit})
    return payload["items"]


def get_incidents(limit: int = 50, status: str | None = None) -> list[dict]:
    params = {"limit": limit}
    if status is not None:
        params["status"] = status
    payload = _request("GET", "/api/v1/incidents", params=params)
    return payload["items"]


def get_incident_events(incident_id: int) -> list[dict]:
    payload = _request("GET", f"/api/v1/incidents/{incident_id}/events")
    return payload["items"]


def update_incident(incident_id: int, status: str) -> dict:
    return _request(
        "PATCH",
        f"/api/v1/incidents/{incident_id}",
        json={"status": status},
    )


def get_audit_events(limit: int = 50, action: str | None = None) -> list[dict]:
    params = {"limit": limit}
    if action is not None:
        params["action"] = action
    payload = _request("GET", "/api/v1/audit-events", params=params)
    return payload["items"]


def get_alerts(
    limit: int = 50,
    status: str | None = None,
    severity: str | None = None,
    assignee_user_id: int | None = None,
) -> list[dict]:
    params: dict = {"limit": limit}
    if status is not None:
        params["status"] = status
    if severity is not None:
        params["severity"] = severity
    if assignee_user_id is not None:
        params["assignee_user_id"] = assignee_user_id
    payload = _request("GET", "/api/v1/alerts", params=params)
    return payload["items"]


def get_alert_counts() -> dict:
    payload = _request("GET", "/api/v1/alerts/counts")
    return payload["counts"]


def get_soc_overview() -> dict:
    return _request("GET", "/api/v1/alerts/overview")


def get_alert_timeline(alert_id: int) -> list[dict]:
    payload = _request("GET", f"/api/v1/alerts/{alert_id}/timeline")
    return payload["items"]


def search_soc(term: str, limit: int = 20) -> dict:
    return _request("GET", "/api/v1/search", params={"q": term, "limit": limit})


def get_iocs(
    limit: int = 50,
    ioc_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    tag: str | None = None,
) -> list[dict]:
    params: dict = {"limit": limit}
    if ioc_type is not None:
        params["type"] = ioc_type
    if status is not None:
        params["status"] = status
    if severity is not None:
        params["severity"] = severity
    if tag is not None:
        params["tag"] = tag
    payload = _request("GET", "/api/v1/iocs", params=params)
    return payload["items"]


def get_ioc_counts() -> dict:
    payload = _request("GET", "/api/v1/iocs/counts")
    return payload["counts"]


def create_ioc(body: dict) -> dict:
    return _request("POST", "/api/v1/iocs", json=body)


def get_ioc(ioc_id: int) -> dict:
    return _request("GET", f"/api/v1/iocs/{ioc_id}")


def update_ioc(ioc_id: int, body: dict) -> dict:
    return _request("PATCH", f"/api/v1/iocs/{ioc_id}", json=body)


def delete_ioc(ioc_id: int) -> None:
    _request("DELETE", f"/api/v1/iocs/{ioc_id}")


def lookup_ioc(value: str) -> dict:
    return _request("GET", "/api/v1/iocs/lookup", params={"value": value})


def add_ioc_tag(ioc_id: int, tag: str) -> list[str]:
    payload = _request("POST", f"/api/v1/iocs/{ioc_id}/tags", json={"tag": tag})
    return payload["tags"]


def remove_ioc_tag(ioc_id: int, tag: str) -> list[str]:
    payload = _request("DELETE", f"/api/v1/iocs/{ioc_id}/tags/{tag}")
    return payload["tags"]


def get_alert(alert_id: int) -> dict:
    return _request("GET", f"/api/v1/alerts/{alert_id}")


def update_alert(alert_id: int, status: str, note: str | None = None) -> dict:
    body: dict = {"status": status}
    if note is not None:
        body["note"] = note
    return _request("PATCH", f"/api/v1/alerts/{alert_id}", json=body)


def assign_alert(alert_id: int, assignee_user_id: int | None) -> dict:
    return _request(
        "POST", f"/api/v1/alerts/{alert_id}/assign", json={"assignee_user_id": assignee_user_id}
    )


def get_alert_events(alert_id: int) -> list[dict]:
    payload = _request("GET", f"/api/v1/alerts/{alert_id}/events")
    return payload["items"]


def get_alert_comments(alert_id: int) -> list[dict]:
    payload = _request("GET", f"/api/v1/alerts/{alert_id}/comments")
    return payload["items"]


def add_alert_comment(alert_id: int, body: str) -> dict:
    return _request("POST", f"/api/v1/alerts/{alert_id}/comments", json={"body": body})


def add_alert_tag(alert_id: int, tag: str) -> list[str]:
    payload = _request("POST", f"/api/v1/alerts/{alert_id}/tags", json={"tag": tag})
    return payload["tags"]


def remove_alert_tag(alert_id: int, tag: str) -> list[str]:
    payload = _request("DELETE", f"/api/v1/alerts/{alert_id}/tags/{tag}")
    return payload["tags"]


def get_rules(include_inactive: bool = True) -> list[dict]:
    payload = _request(
        "GET", "/api/v1/correlation/rules", params={"include_inactive": include_inactive}
    )
    return payload["items"]


def create_rule(body: dict) -> dict:
    return _request("POST", "/api/v1/correlation/rules", json=body)


def update_rule(rule_id: int, body: dict) -> dict:
    return _request("PATCH", f"/api/v1/correlation/rules/{rule_id}", json=body)


def delete_rule(rule_id: int) -> None:
    _request("DELETE", f"/api/v1/correlation/rules/{rule_id}")


def run_correlation() -> dict:
    return _request("POST", "/api/v1/correlation/run")


def get_findings(
    limit: int = 50, finding_status: str | None = None, rule_id: int | None = None
) -> list[dict]:
    params: dict = {"limit": limit}
    if finding_status is not None:
        params["status"] = finding_status
    if rule_id is not None:
        params["rule_id"] = rule_id
    payload = _request("GET", "/api/v1/correlation/findings", params=params)
    return payload["items"]


def update_finding_status(finding_id: int, status: str) -> dict:
    return _request("PATCH", f"/api/v1/correlation/findings/{finding_id}", json={"status": status})


def get_ml_monitoring(days: int = 30) -> dict:
    return _request("GET", "/api/v1/ml/monitoring", params={"days": days})


def get_ml_feedback(limit: int = 50) -> list[dict]:
    payload = _request("GET", "/api/v1/ml/feedback", params={"limit": limit})
    return payload["items"]


def get_notifications(limit: int = 50, severity: str | None = None) -> list[dict]:
    params: dict = {"limit": limit}
    if severity is not None:
        params["severity"] = severity
    payload = _request("GET", "/api/v1/notifications", params=params)
    return payload["items"]


def get_notification_counts() -> dict:
    payload = _request("GET", "/api/v1/notifications/counts")
    return payload["counts"]


def dispatch_notifications(limit: int = 50) -> dict:
    return _request("POST", "/api/v1/notifications/dispatch", params={"limit": limit})


def download_export(resource: str, params: dict | None = None) -> tuple[str, bytes]:
    """Fetch a CSV export as raw bytes (the JSON helper cannot parse text/csv)."""
    headers = {}
    token = st.session_state.get("auth_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.get(
            f"{API_BASE_URL}/api/v1/exports/{resource}",
            params=params or {},
            timeout=TIMEOUT_SECONDS,
            headers=headers,
        )
    except requests.RequestException as exc:
        raise APIError("Téléchargement impossible : l’API ne répond pas.") from exc
    if not response.ok:
        raise APIError(f"L’export a échoué (HTTP {response.status_code}).", response.status_code)
    return f"togocyber-{resource}.csv", response.content


def get_integrations() -> dict:
    return _request("GET", "/api/v1/integrations")


def get_playbooks(module: str | None = None) -> list[dict]:
    params: dict = {}
    if module is not None:
        params["module"] = module
    payload = _request("GET", "/api/v1/playbooks", params=params)
    return payload["items"]


def create_playbook(body: dict) -> dict:
    return _request("POST", "/api/v1/playbooks", json=body)


def update_playbook(playbook_id: int, body: dict) -> dict:
    return _request("PATCH", f"/api/v1/playbooks/{playbook_id}", json=body)


def delete_playbook(playbook_id: int) -> None:
    _request("DELETE", f"/api/v1/playbooks/{playbook_id}")


def get_health() -> dict:
    return _request("GET", "/api/v1/health")


def register(email: str, password: str) -> dict:
    return _request("POST", "/api/v1/auth/register", json={"email": email, "password": password})


def login(email: str, password: str) -> dict:
    return _request("POST", "/api/v1/auth/login", json={"email": email, "password": password})


def logout() -> None:
    _request("POST", "/api/v1/auth/logout")


def get_current_user() -> dict:
    return _request("GET", "/api/v1/auth/me")


def create_managed_user(email: str, password: str, role: str) -> dict:
    return _request(
        "POST", "/api/v1/auth/users", json={"email": email, "password": password, "role": role}
    )


def get_users() -> list[dict]:
    payload = _request("GET", "/api/v1/auth/users")
    return payload["items"]


def update_user(user_id: int, role: str | None = None, is_active: bool | None = None) -> dict:
    body: dict = {}
    if role is not None:
        body["role"] = role
    if is_active is not None:
        body["is_active"] = is_active
    return _request("PATCH", f"/api/v1/auth/users/{user_id}", json=body)


def reset_user_password(user_id: int, password: str) -> None:
    _request("POST", f"/api/v1/auth/users/{user_id}/password", json={"password": password})


def delete_user(user_id: int) -> None:
    _request("DELETE", f"/api/v1/auth/users/{user_id}")