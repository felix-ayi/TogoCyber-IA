from fastapi import APIRouter

from backend.app.api.v1.routes.health import router as health_router
from backend.app.api.v1.routes.network import router as network_router
from backend.app.api.v1.routes.phishing import router as phishing_router
from backend.app.api.v1.routes.assistant import router as assistant_router
from backend.app.api.v1.routes.history import router as history_router

router = APIRouter(prefix="/api/v1")

router.include_router(health_router, tags=["Health"])
router.include_router(network_router, tags=["Network Detection"])
router.include_router(phishing_router, tags=["Phishing Detection"])
router.include_router(assistant_router, tags=["AI Assistant"])
router.include_router(history_router, tags=["Analysis History"])
