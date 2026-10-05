"""Build privacy-conscious, portable analysis reports for dashboard users."""

import json
from datetime import datetime, timezone

from frontend.services.response_guidance import get_action_guidance


def build_analysis_report(result: dict, generated_at: datetime | None = None) -> str:
    probability_key = (
        "phishing_probability"
        if "phishing_probability" in result
        else "malicious_probability"
    )
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")

    report = {
        "schema_version": "1.0",
        "generated_at": timestamp.astimezone(timezone.utc).isoformat(),
        "module": result["module"],
        "prediction": result["prediction"],
        "threat_probability": result[probability_key],
        "confidence": result["confidence"],
        "confidence_level": result["confidence_level"],
        "explanation": result.get("explanation", []),
        "explanation_truncated": result.get("explanation_truncated", False),
        "recommended_actions": get_action_guidance(
            result["module"], result["prediction"],
        ),
        "privacy": {
            "submitted_content_included": False,
            "note": "Le texte soumis et les caractéristiques brutes ne sont pas inclus.",
        },
        "disclaimer": (
            "Prototype de recherche : résultat indicatif, non certifié. "
            "Une explication locale n'établit pas une causalité."
        ),
    }
    return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
