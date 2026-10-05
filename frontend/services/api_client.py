"""Typed-by-contract HTTP client with actionable errors for the Streamlit UI."""

import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
API_BASE_URL = os.getenv("TOGOCYBER_API_URL", "http://localhost:8000").rstrip("/")
TIMEOUT_SECONDS = 12


class APIError(RuntimeError):
    pass


def _request(method: str, path: str, **kwargs):
    try:
        response = requests.request(
            method, f"{API_BASE_URL}{path}", timeout=TIMEOUT_SECONDS, **kwargs,
        )
    except requests.Timeout as exc:
        raise APIError("L’API met trop de temps à répondre. Réessayez dans quelques instants.") from exc
    except requests.ConnectionError as exc:
        raise APIError("L’API TogoCyber AI est hors ligne. Vérifiez qu’elle est démarrée sur le port 8000.") from exc
    except requests.RequestException as exc:
        raise APIError("Impossible de joindre l’API. Vérifiez votre connexion puis réessayez.") from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise APIError(f"L’API a renvoyé une réponse invalide (HTTP {response.status_code}).") from exc
    if not response.ok:
        detail = payload.get("detail", "La requête n’a pas pu aboutir.") if isinstance(payload, dict) else "La requête n’a pas pu aboutir."
        raise APIError(f"{detail} (HTTP {response.status_code})")
    return payload


def analyze_network(features: dict) -> dict:
    return _request("POST", "/api/v1/network/analyze", json={"features": features})


def analyze_phishing(text: str) -> dict:
    return _request("POST", "/api/v1/phishing/analyze", json={"text": text})


def ask_assistant(message: str) -> dict:
    return _request("POST", "/api/v1/assistant/ask", json={"message": message})


def get_history(limit: int = 50) -> list[dict]:
    payload = _request("GET", "/api/v1/history", params={"limit": limit})
    return payload["items"]


def get_health() -> dict:
    return _request("GET", "/api/v1/health")