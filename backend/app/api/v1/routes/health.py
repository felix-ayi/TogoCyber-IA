import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.repositories import history_repository, notification_repository
from backend.app.services import integrations_service
from ml.common.utils import load_model, registered_model_metadata

router = APIRouter()
logger = logging.getLogger(__name__)


def _model_status(name: str) -> tuple[bool, dict]:
    try:
        load_model(name)
        metadata = registered_model_metadata(name)
    except FileNotFoundError:
        return False, {}
    except Exception:
        logger.exception("Model readiness check failed for %s", name)
        return False, {}
    return True, metadata


@router.get("/health/live")
def liveness_check():
    return {"status": "alive"}


@router.get("/health/ready")
def readiness_check():
    checks = _dependency_checks()
    models = {
        name: _model_status(name)[0] for name in ("network", "phishing")
    }
    ready = checks["database"] == "ok"
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "checks": checks,
            "models": models,
        },
    )


@router.get("/health")
def health_check():
    models = {}
    model_details = {}
    for name in ("network", "phishing"):
        models[name], metadata = _model_status(name)
        if not models[name]:
            continue
        model_details[name] = {
            "algorithm": metadata.get("model", "inconnu"),
            "source": metadata.get(
                "training_dataset" if name == "network" else "training_corpus",
                "source inconnue",
            ),
            "test_dataset": (
                metadata.get("test_dataset", "inconnu")
                if name == "network"
                else "partition de test réservée"
            ),
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
