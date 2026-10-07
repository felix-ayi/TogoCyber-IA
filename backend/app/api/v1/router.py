from fastapi import APIRouter

from backend.app.api.v1.routes.health import router as health_router
from backend.app.api.v1.routes.network import router as network_router
from backend.app.api.v1.routes.phishing import router as phishing_router
from backend.app.api.v1.routes.assistant import router as assistant_router
from backend.app.api.v1.routes.history import router as history_router
from backend.app.api.v1.routes.auth import router as auth_router
from backend.app.api.v1.routes.incidents import router as incidents_router
from backend.app.api.v1.routes.alerts import router as alerts_router
from backend.app.api.v1.routes.search import router as search_router
from backend.app.api.v1.routes.iocs import router as iocs_router
from backend.app.api.v1.routes.correlation import router as correlation_router
from backend.app.api.v1.routes.ml_monitoring import router as ml_monitoring_router
from backend.app.api.v1.routes.notifications import router as notifications_router
from backend.app.api.v1.routes.playbooks import router as playbooks_router
from backend.app.api.v1.routes.integrations import router as integrations_router
from backend.app.api.v1.routes.exports import router as exports_router
from backend.app.api.v1.routes.url_analysis import router as url_analysis_router
from backend.app.api.v1.routes.audit import router as audit_router
from backend.app.api.v1.routes.events import router as events_router

router = APIRouter(prefix="/api/v1")

router.include_router(health_router, tags=["Health"])
router.include_router(network_router, tags=["Network Detection"])
router.include_router(phishing_router, tags=["Phishing Detection"])
router.include_router(assistant_router, tags=["AI Assistant"])
router.include_router(history_router, tags=["Analysis History"])
router.include_router(auth_router)
router.include_router(incidents_router)
router.include_router(alerts_router)
router.include_router(search_router)
router.include_router(iocs_router)
router.include_router(correlation_router)
router.include_router(ml_monitoring_router)
router.include_router(notifications_router)
router.include_router(playbooks_router)
router.include_router(integrations_router)
router.include_router(exports_router)
router.include_router(url_analysis_router)
router.include_router(audit_router)
router.include_router(events_router)
