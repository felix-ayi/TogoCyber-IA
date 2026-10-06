"""Network inference with the shared, versioned canonical feature schema."""

from backend.app.core.security import confidence_level
from ml.common.preprocessing import NETWORK_FEATURES, network_features_from_mapping
from ml.common.utils import load_model, registered_model_metadata


def predict_network(values: dict) -> dict:
    row = network_features_from_mapping(values)
    model = load_model("network")
    metadata = registered_model_metadata("network")
    probability = float(model.predict_proba(row)[0, 1])
    label = "malicious" if probability >= 0.5 else "benign"
    confidence = max(probability, 1 - probability)
    level = confidence_level(confidence)
    return {
        "prediction": label,
        "malicious_probability": probability,
        "confidence": confidence,
        "confidence_level": level,
        "features": {name: float(row.iloc[0][name]) for name in NETWORK_FEATURES},
        "model": metadata.get("model", "network"),
        "model_version": metadata.get("version", "unversioned"),
    }