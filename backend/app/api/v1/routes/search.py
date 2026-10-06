from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import investigation_repository
from backend.app.schemas.investigation import SearchResponse

router = APIRouter(prefix="/search", tags=["SOC Investigation"])

# Global search spans alerts, incidents, detections and audit records: SOC roles only.
_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=SearchResponse, dependencies=[Depends(_soc_roles)])
def search(
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=20, ge=1, le=50),
):
    try:
        return investigation_repository.global_search(q, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
