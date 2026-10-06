from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import ml_monitoring_repository
from backend.app.schemas.ml_monitoring import FeedbackListResponse, MonitoringResponse

router = APIRouter(prefix="/ml", tags=["ML Monitoring"])

_soc_roles = require_roles("Admin", "Analyst")


@router.get("/monitoring", response_model=MonitoringResponse, dependencies=[Depends(_soc_roles)])
def monitoring(days: int = Query(default=30, ge=1, le=30)):
    try:
        return ml_monitoring_repository.monitoring_summary(days=days)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/feedback", response_model=FeedbackListResponse, dependencies=[Depends(_soc_roles)])
def feedback(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
):
    try:
        return {"items": ml_monitoring_repository.list_feedback(limit=limit, offset=offset)}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
