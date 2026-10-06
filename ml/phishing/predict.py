"""Privacy-preserving inference: the caller receives results; text is not persisted."""

from backend.app.core.security import confidence_level, validate_message_text
from ml.common.utils import load_model, registered_model_metadata


def predict_phishing(text: str) -> dict:
    message = validate_message_text(text)
    model = load_model("phishing")
    metadata = registered_model_metadata("phishing")
    probabilities = model.predict_proba([message])[0]
    classes = list(model.named_steps["classifier"].classes_)
    phishing_probability = float(probabilities[classes.index(1)])
    prediction = "phishing" if phishing_probability >= 0.5 else "legitimate"
    confidence = max(phishing_probability, 1 - phishing_probability)
    level = confidence_level(confidence)
    return {
        "prediction": prediction,
        "phishing_probability": phishing_probability,
        "confidence": confidence,
        "confidence_level": level,
        "model": metadata.get("model", "phishing"),
        "model_version": metadata.get("version", "unversioned"),
    }