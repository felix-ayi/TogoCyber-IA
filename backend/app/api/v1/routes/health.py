from fastapi import APIRouter

from backend.app.core.config import settings
from ml.common.utils import MODELS_DIR, registered_model_metadata

router = APIRouter()

@router.get("/health")
def health_check():
    models = {
        "network": (MODELS_DIR / "network.joblib").is_file(),
        "phishing": (MODELS_DIR / "phishing.joblib").is_file(),
    }
    model_details = {}
    if models["network"]:
        metadata = registered_model_metadata("network")
        model_details["network"] = {
            "algorithm": metadata.get("model", "inconnu"),
            "source": metadata.get("training_dataset", "source inconnue"),
            "test_dataset": metadata.get("test_dataset", "inconnu"),
            "test_rows": metadata.get("test_rows"),
            "metrics": metadata.get("metrics", {}),
            "comparison_metrics": metadata.get("comparison_metrics", {}),
        }
    if models["phishing"]:
        metadata = registered_model_metadata("phishing")
        model_details["phishing"] = {
            "algorithm": metadata.get("model", "inconnu"),
            "source": metadata.get("training_corpus", "source inconnue"),
            "test_dataset": "partition de test réservée",
            "test_rows": metadata.get("test_rows"),
            "metrics": metadata.get("metrics", {}),
            "comparison_metrics": metadata.get("comparison_metrics", {}),
        }
    return {
        "status": "healthy",
        "service": "TogoCyber AI API",
        "version": settings.api_version,
        "models": models,
        "model_sources": {
            name: details["source"] for name, details in model_details.items()
        },
        "model_details": model_details,
        "assistant_configured": bool(settings.openai_api_key),
    }
