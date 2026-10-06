from fastapi import APIRouter

from backend.app.core.config import settings
from backend.app.repositories import history_repository, notification_repository
from backend.app.services import integrations_service
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
        "checks": _dependency_checks(),
    }


def _dependency_checks() -> dict:
    """Real dependency state, reported honestly and never raising.

    A liveness probe must stay up even before the store is initialised, so each check
    degrades to an explicit status rather than propagating an exception. Nothing here is
    simulated: a dependency that cannot be reached is reported as unavailable.
    """
    database_ok = history_repository.database_ok()
    if database_ok:
        try:
            pending = notification_repository.counts().get("not_configured", 0)
        except Exception:  # pragma: no cover - table missing on a fresh store
            pending = None
    else:
        pending = None
    try:
        integrations = integrations_service.status_summary()
        integrations_configured = integrations["configured"]
        integrations_total = integrations["total"]
    except Exception:  # pragma: no cover - environment probing is best-effort
        integrations_configured = None
        integrations_total = None
    return {
        "database": "ok" if database_ok else "unavailable",
        "pending_notifications": pending,
        "integrations_configured": integrations_configured,
        "integrations_total": integrations_total,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
    }
