from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import alert_repository, investigation_repository
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.schemas.alerts import (
    AlertAssignRequest,
    AlertComment,
    AlertCommentCreate,
    AlertCommentListResponse,
    AlertListResponse,
    AlertResponse,
    AlertStatusCounts,
    AlertStatusEventListResponse,
    AlertStatusUpdate,
    AlertTagListResponse,
    AlertTagRequest,
    SocOverviewResponse,
)
from backend.app.schemas.investigation import AlertTimelineResponse

router = APIRouter(prefix="/alerts", tags=["Alert Triage"])

# The alert queue is a SOC function: analysts and administrators only.
_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=AlertListResponse, dependencies=[Depends(_soc_roles)])
def alerts(
    limit: int = Query(default=50, ge=1, le=100),
    alert_status: str | None = Query(
        default=None,
        alias="status",
        pattern="^(NEW|INVESTIGATING|CONFIRMED|FALSE_POSITIVE|RESOLVED|CLOSED)$",
    ),
    severity: str | None = Query(
        default=None, alias="severity", pattern="^(MEDIUM|HIGH|CRITICAL)$"
    ),
    assignee_user_id: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0, le=10000),
):
    try:
        items = alert_repository.list_alerts(
            limit=limit,
            status=alert_status,
            severity=severity,
            assignee_user_id=assignee_user_id,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"items": items}


@router.get("/counts", response_model=AlertStatusCounts, dependencies=[Depends(_soc_roles)])
def alert_counts():
    return {"counts": alert_repository.status_counts()}


@router.get("/overview", response_model=SocOverviewResponse, dependencies=[Depends(_soc_roles)])
def soc_overview():
    return alert_repository.soc_overview()


@router.get("/{alert_id}", response_model=AlertResponse, dependencies=[Depends(_soc_roles)])
def alert(alert_id: int):
    try:
        return alert_repository.get_alert(alert_id)
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    request: AlertStatusUpdate,
    user: dict = Depends(_soc_roles),
):
    try:
        updated = alert_repository.update_status(
            alert_id, request.status, user["id"], request.note
        )
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except alert_repository.InvalidAlertTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("alert.status_changed", "success", user["id"], "alert", alert_id)
    return updated


@router.post("/{alert_id}/assign", response_model=AlertResponse)
def assign_alert(
    alert_id: int,
    request: AlertAssignRequest,
    user: dict = Depends(_soc_roles),
):
    try:
        updated = alert_repository.assign(alert_id, request.assignee_user_id, user["id"])
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("alert.assigned", "success", user["id"], "alert", alert_id)
    return updated


@router.get(
    "/{alert_id}/events",
    response_model=AlertStatusEventListResponse,
    dependencies=[Depends(_soc_roles)],
)
def alert_events(alert_id: int):
    try:
        return {"items": alert_repository.list_status_events(alert_id)}
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/{alert_id}/timeline",
    response_model=AlertTimelineResponse,
    dependencies=[Depends(_soc_roles)],
)
def alert_timeline(alert_id: int):
    try:
        return {"alert_id": alert_id, "items": investigation_repository.alert_timeline(alert_id)}
    except investigation_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/{alert_id}/comments",
    response_model=AlertCommentListResponse,
    dependencies=[Depends(_soc_roles)],
)
def alert_comments(alert_id: int):
    try:
        return {"items": alert_repository.list_comments(alert_id)}
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/{alert_id}/comments",
    response_model=AlertComment,
    status_code=status.HTTP_201_CREATED,
)
def add_alert_comment(
    alert_id: int,
    request: AlertCommentCreate,
    user: dict = Depends(_soc_roles),
):
    try:
        return alert_repository.add_comment(alert_id, user["id"], request.body)
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/{alert_id}/tags", response_model=AlertTagListResponse)
def add_alert_tag(
    alert_id: int,
    request: AlertTagRequest,
    user: dict = Depends(_soc_roles),
):
    try:
        return {"tags": alert_repository.add_tag(alert_id, request.tag)}
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.delete("/{alert_id}/tags/{tag}", response_model=AlertTagListResponse)
def remove_alert_tag(
    alert_id: int,
    tag: str,
    user: dict = Depends(_soc_roles),
):
    try:
        return {"tags": alert_repository.remove_tag(alert_id, tag)}
    except alert_repository.AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
