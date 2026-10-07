from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import event_repository
from backend.app.schemas.events import (
    EventIngestResponse,
    EventListResponse,
    EventSeverity,
    SuricataEveIngestRequest,
)
from backend.app.services.event_ingestion_service import normalize_suricata_event

router = APIRouter(prefix="/events", tags=["Event Ingestion"])
_soc_roles = require_roles("Admin", "Analyst")


@router.post("/ingest/suricata", response_model=EventIngestResponse)
def ingest_suricata_event(
    request: SuricataEveIngestRequest,
    user: dict = Depends(_soc_roles),
):
    try:
        event = normalize_suricata_event(request.event)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    inserted = event_repository.ingest_event(event)
    return {"event": event, "inserted": inserted}


@router.get("", response_model=EventListResponse)
def list_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    source_type: str | None = Query(default=None, min_length=1, max_length=64),
    severity: EventSeverity | None = None,
    user: dict = Depends(_soc_roles),
):
    try:
        items = event_repository.list_events(
            limit=limit, offset=offset, source_type=source_type, severity=severity
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return {"items": items}