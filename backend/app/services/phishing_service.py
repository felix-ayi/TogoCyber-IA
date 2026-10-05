from ml.phishing.explain import explain_phishing
from ml.phishing.predict import predict_phishing
from backend.app.repositories.history_repository import record_event


def analyze_phishing(text: str) -> dict:
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
        "history_id": history_id,
    }