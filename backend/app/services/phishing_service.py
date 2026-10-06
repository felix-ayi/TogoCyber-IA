from threading import BoundedSemaphore

from ml.phishing.explain import explain_phishing
from ml.phishing.explain import PHISHING_EXPLANATION_MAX_CHARS
from ml.phishing.predict import predict_phishing
from backend.app.repositories.history_repository import get_incident_id_for_history, record_event
from backend.app.services.risk_engine import assess_risk

MAX_CONCURRENT_PHISHING_ANALYSES = 2
_analysis_slots = BoundedSemaphore(MAX_CONCURRENT_PHISHING_ANALYSES)


class AnalysisCapacityExceeded(RuntimeError):
    """The process is already handling its allowed phishing-analysis workload."""


def analyze_phishing(text: str, user_id: int | None = None) -> dict:
    if not _analysis_slots.acquire(blocking=False):
        raise AnalysisCapacityExceeded("Trop d’analyses de phishing simultanées. Réessayez dans quelques instants.")
    try:
        result = predict_phishing(text)
        explanation = explain_phishing(text)
        risk = assess_risk(
            "phishing",
            result["prediction"],
            result["phishing_probability"],
            result["confidence"],
            explanation,
        )
        history_id = record_event(
            "phishing", result["prediction"], result["confidence"], result["confidence_level"],
            user_id=user_id,
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            model_name=result["model"],
            model_version=result["model_version"],
        )
        incident_id = get_incident_id_for_history(history_id) if user_id is not None else None
        return {
            "status": "success",
            "module": "phishing",
            **result,
            "explanation": explanation,
            **risk,
            "explanation_truncated": len(text.strip()) > PHISHING_EXPLANATION_MAX_CHARS,
            "history_id": history_id,
            "incident_id": incident_id,
        }
    finally:
        _analysis_slots.release()