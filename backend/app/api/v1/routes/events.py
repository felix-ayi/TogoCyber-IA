from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import alert_repository, event_repository
from backend.app.schemas.events import (
    EventIngestResponse,
    EventListResponse,
    EventSeverity,
    SuricataEveIngestRequest,
)
from backend.app.services.detection_engine import assess_suricata_event
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
    detection = assess_suricata_event(event)
    alert_id = None
    if inserted and detection["should_alert"]:
        mitre = detection["mitre"]
        tags = [
            "source:suricata",
            f"mitre:{mitre['technique']}",
            f"signature:{event.metadata.get('signature_id') or 'unknown'}",
        ]
        if event.src_ip:
            tags.append(f"src_ip:{event.src_ip}")
        if event.dst_ip:
            tags.append(f"dst_ip:{event.dst_ip}")
        title = event.message or "Suricata alert détectée"
        alert = alert_repository.create_from_detection(
            title=f"Suricata — {title}",
            severity=detection["severity"],
            risk_score=detection["risk_score"],
            actor_user_id=user.get("id") if isinstance(user, dict) else None,
            tags=tags,
        )
        alert_id = alert["id"]
    return {
        "event": event,
        "inserted": inserted,
        "alert_id": alert_id,
        "detection": detection if inserted else None,
    }


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