from ml.network.explain import explain_network
from ml.network.predict import predict_network
from backend.app.repositories.history_repository import get_incident_id_for_history, record_event
from backend.app.services.risk_engine import assess_risk


def analyze_network(features: dict, user_id: int | None = None) -> dict:
    result = predict_network(features)
    explanation = explain_network(features)
    risk = assess_risk(
        "network",
        result["prediction"],
        result["malicious_probability"],
        result["confidence"],
        explanation,
    )
    history_id = record_event(
        "network", result["prediction"], result["confidence"], result["confidence_level"],
        user_id=user_id,
        risk_score=risk["risk_score"],
        severity=risk["severity"],
        model_name=result["model"],
        model_version=result["model_version"],
    )
    incident_id = get_incident_id_for_history(history_id) if user_id is not None else None
    return {
        "status": "success",
        "module": "network",
        **result,
        "explanation": explanation,
        **risk,
        "history_id": history_id,
        "incident_id": incident_id,
    }