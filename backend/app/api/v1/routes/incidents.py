from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import get_current_user, require_roles
from backend.app.repositories import history_repository
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.schemas.incidents import (
    IncidentListResponse,
    IncidentStatusEventListResponse,
    IncidentStatusUpdate,
    IncidentResponse,
)

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("", response_model=IncidentListResponse)
def incidents(
    limit: int = Query(default=50, ge=1, le=100),
    incident_status: str | None = Query(
        default=None, alias="status", pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$"
    ),
    offset: int = Query(default=0, ge=0, le=10000),
    user: dict = Depends(get_current_user),
):
    user_id = None if user["role"] in {"Admin", "Analyst"} else user["id"]
    return {
        "items": history_repository.list_incidents(
            limit=limit,
            user_id=user_id,
            status=incident_status,
            offset=offset,
        )
    }


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    request: IncidentStatusUpdate,
    user: dict = Depends(require_roles("Admin", "Analyst")),
):
    try:
        updated = history_repository.update_incident_status(
            incident_id,
            request.status,
            user["id"],
        )
        record_audit_event(
            "incident.status_changed",
            "success",
            user["id"],
            "incident",
            incident_id,
        )
        return updated
    except history_repository.IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except history_repository.InvalidIncidentTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "/{incident_id}/events",
    response_model=IncidentStatusEventListResponse,
)
def incident_events(incident_id: int, user: dict = Depends(get_current_user)):
    user_id = None if user["role"] in {"Admin", "Analyst"} else user["id"]
    events = history_repository.get_incident_status_events(incident_id, user_id=user_id)
    if events is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident introuvable.")
    return {"items": events}
