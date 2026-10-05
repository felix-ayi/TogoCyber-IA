from threading import BoundedSemaphore

from ml.phishing.explain import explain_phishing
from ml.phishing.explain import PHISHING_EXPLANATION_MAX_CHARS
from ml.phishing.predict import predict_phishing
from backend.app.repositories.history_repository import record_event

MAX_CONCURRENT_PHISHING_ANALYSES = 2
_analysis_slots = BoundedSemaphore(MAX_CONCURRENT_PHISHING_ANALYSES)


class AnalysisCapacityExceeded(RuntimeError):
    """The process is already handling its allowed phishing-analysis workload."""


def analyze_phishing(text: str) -> dict:
    if not _analysis_slots.acquire(blocking=False):
        raise AnalysisCapacityExceeded("Trop d’analyses de phishing simultanées. Réessayez dans quelques instants.")
    try:
        result = predict_phishing(text)
        explanation = explain_phishing(text)
        history_id = record_event(
            "phishing", result["prediction"], result["confidence"], result["confidence_level"],
        )
        return {
            "status": "success",
            "module": "phishing",
            **result,
            "explanation": explanation,
            "explanation_truncated": len(text.strip()) > PHISHING_EXPLANATION_MAX_CHARS,
            "history_id": history_id,
        }
    finally:
        _analysis_slots.release()