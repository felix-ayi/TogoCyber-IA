from ml.network.explain import explain_network
from ml.network.predict import predict_network
from backend.app.repositories.history_repository import record_event


def analyze_network(features: dict) -> dict:
    result = predict_network(features)
    explanation = explain_network(features)
    history_id = record_event(
        "network", result["prediction"], result["confidence"], result["confidence_level"],
    )
    return {
        "status": "success",
        "module": "network",
        **result,
        "explanation": explanation,
        "history_id": history_id,
    }