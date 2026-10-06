"""Deterministic risk normalization for model probabilities and explanations."""

import math
from typing import Literal, TypedDict

Severity = Literal["VERY_LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEVERITY_THRESHOLDS: tuple[tuple[int, Severity], ...] = (
    (20, "VERY_LOW"),
    (40, "LOW"),
    (60, "MEDIUM"),
    (80, "HIGH"),
    (100, "CRITICAL"),
)


class RiskIndicator(TypedDict):
    name: str
    contribution: float
    direction: Literal["raises_risk", "lowers_risk", "neutral"]


class RiskAssessment(TypedDict):
    risk_score: int
    severity: Severity
    confidence: float
    classification: str
    indicators: list[RiskIndicator]
    recommendations: list[str]


def _probability(value: float, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite number between zero and one")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0 <= numeric <= 1:
        raise ValueError(f"{field} must be a finite number between zero and one")
    return numeric


def severity_for_score(score: int) -> Severity:
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk score must be an integer between zero and one hundred")
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score <= threshold:
            return severity
    raise ValueError("risk score must be an integer between zero and one hundred")


def _recommendations(module: str, classification: str) -> list[str]:
    if module == "phishing":
        if classification == "phishing":
            return [
                "Ne cliquez pas sur les liens et ne communiquez aucun mot de passe ni code OTP.",
                "Vérifiez la demande auprès de l’organisation via un canal officiel indépendant.",
                "Signalez le message à votre opérateur ou à votre équipe informatique.",
            ]
        return [
            "Aucun signal fort n’a été relevé ; cela ne garantit pas que le message est sûr.",
            "Confirmez toute demande urgente ou financière via un canal officiel indépendant.",
        ]
    if module == "network":
        if classification == "malicious":
            return [
                "Faites vérifier cette alerte par l’équipe de sécurité autorisée.",
                "Confrontez le résultat aux journaux et au contexte avant toute action.",
            ]
        return [
            "Aucun signal fort n’a été relevé dans les caractéristiques fournies.",
            "Continuez la surveillance habituelle ; cette prédiction ne garantit pas l’absence de menace.",
        ]
    raise ValueError(f"unsupported risk module: {module}")


def assess_risk(
    module: str,
    classification: str,
    threat_probability: float,
    confidence: float,
    explanation: list[dict] | None = None,
) -> RiskAssessment:
    expected = {
        "phishing": {"phishing", "legitimate"},
        "network": {"malicious", "benign"},
    }
    if module not in expected or classification not in expected[module]:
        raise ValueError(f"unsupported classification for risk assessment: {module}/{classification}")

    probability = _probability(threat_probability, "threat_probability")
    normalized_confidence = _probability(confidence, "confidence")
    score = round(probability * 100)
    indicators: list[RiskIndicator] = []
    for item in explanation or []:
        name = item.get("feature", item.get("term"))
        contribution = item.get("contribution")
        if not isinstance(name, str) or not name:
            continue
        numeric_contribution = float(contribution)
        if not math.isfinite(numeric_contribution):
            raise ValueError("explanation contributions must be finite")
        direction: Literal["raises_risk", "lowers_risk", "neutral"] = (
            "raises_risk" if numeric_contribution > 0 else
            "lowers_risk" if numeric_contribution < 0 else "neutral"
        )
        indicators.append({
            "name": name,
            "contribution": numeric_contribution,
            "direction": direction,
        })

    return {
        "risk_score": score,
        "severity": severity_for_score(score),
        "confidence": normalized_confidence,
        "classification": classification,
        "indicators": indicators,
        "recommendations": _recommendations(module, classification),
    }
