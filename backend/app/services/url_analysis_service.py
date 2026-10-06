"""Local URL-structure checks. This service never resolves or fetches URLs."""

import ipaddress
import re
from urllib.parse import urlsplit

from backend.app.services.risk_engine import Severity, severity_for_score

MAX_URL_LENGTH = 2048
_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SUSPICIOUS_TERMS = {
    "account",
    "bank",
    "login",
    "otp",
    "password",
    "secure",
    "update",
    "verify",
}
_SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "tinyurl.com",
}


def _normalize_host(hostname: str) -> tuple[str, bool]:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Le nom de domaine de l’URL est invalide.") from exc
        labels = normalized.split(".")
        if (
            not normalized
            or len(normalized) > 253
            or any(not _HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
        ):
            raise ValueError("Le nom de domaine de l’URL est invalide.")
        return normalized, False
    return address.compressed.lower(), True


def analyze_url(url: str) -> dict:
    if not isinstance(url, str):
        raise ValueError("Saisissez une URL http ou https valide.")
    candidate = url.strip()
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        raise ValueError(f"L’URL doit contenir entre 1 et {MAX_URL_LENGTH} caractères.")
    if any(character.isspace() or ord(character) < 0x20 for character in candidate):
        raise ValueError("L’URL ne doit pas contenir d’espaces ni de caractères de contrôle.")
    if "\\" in candidate:
        raise ValueError("L’URL contient un séparateur non valide.")

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("L’URL ou son port est invalide.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ValueError("Saisissez une URL complète commençant par http:// ou https://.")

    hostname, is_ip_address = _normalize_host(parsed.hostname)
    suspicious_score = 0
    indicators: list[dict[str, object]] = []

    def add_indicator(name: str, points: int) -> None:
        nonlocal suspicious_score
        suspicious_score += points
        indicators.append({"name": name, "contribution": points})

    if parsed.username is not None or parsed.password is not None:
        add_indicator("Informations d’identification intégrées avant le domaine", 25)
    if any(label.startswith("xn--") for label in hostname.split(".")):
        add_indicator("Nom de domaine international encodé en punycode", 20)
    if is_ip_address:
        add_indicator("Adresse IP utilisée directement à la place d’un domaine", 20)
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        add_indicator("Nom d’hôte local ou réservé", 20)
    if parsed.scheme.lower() == "http":
        add_indicator("Connexion sans chiffrement HTTPS", 8)
    if any(
        hostname == shortener or hostname.endswith(f".{shortener}")
        for shortener in _SHORTENER_DOMAINS
    ):
        add_indicator("Domaine de raccourcissement de liens", 20)
    if port is not None and port not in {80, 443}:
        add_indicator("Port non standard explicite", 12)
    if not is_ip_address and len(hostname.split(".")) > 4:
        add_indicator("Nombre élevé de sous-domaines", 10)
    if len(hostname) > 50:
        add_indicator("Nom de domaine particulièrement long", 10)

    inspected_parts = f"{hostname}{parsed.path}{parsed.query}".lower()
    matched_terms = sorted(term for term in _SUSPICIOUS_TERMS if term in inspected_parts)
    if matched_terms:
        add_indicator("Mots fréquemment associés aux demandes de compte ou de vérification", 10)
    if len(candidate) > 150:
        add_indicator("URL particulièrement longue", 8)
    if "%25" in candidate.lower():
        add_indicator("Encodage URL imbriqué", 10)

    score = min(suspicious_score, 100)
    return {
        "status": "success",
        "module": "url",
        "suspicion_score": score,
        "severity": severity_for_score(score),
        "indicators": indicators,
        "recommendations": [
            "N’ouvrez pas le lien si vous ne pouvez pas confirmer son origine par un canal indépendant.",
            "Vérifiez le nom de domaine lettre par lettre et évitez de saisir des identifiants via un lien reçu.",
            "Ce contrôle local n’utilise ni réputation externe ni accès au site ; un score faible ne garantit pas l’innocuité.",
        ],
        "caution": (
            "Score heuristique de structure, non calibré sur une base de réputation. "
            "L’URL n’a pas été visitée et n’établit pas qu’un site soit malveillant."
        ),
    }


__all__ = ["MAX_URL_LENGTH", "Severity", "analyze_url"]
