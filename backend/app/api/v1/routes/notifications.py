from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import notification_repository
from backend.app.schemas.notifications import (
    NotificationCountsResponse,
    NotificationDispatchResponse,
    NotificationListResponse,
)
from backend.app.services import notification_service

router = APIRouter(prefix="/notifications", tags=["Notifications"])

_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=NotificationListResponse, dependencies=[Depends(_soc_roles)])
def list_notifications(
    limit: int = Query(default=50, ge=1, le=100),
    severity: str | None = Query(
        default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"
    ),
    offset: int = Query(default=0, ge=0, le=10000),
):
    try:
        items = notification_repository.list_notifications(
            limit=limit, severity=severity, offset=offset
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"items": items}


@router.get("/counts", response_model=NotificationCountsResponse, dependencies=[Depends(_soc_roles)])
def notification_counts():
    return {"counts": notification_repository.counts()}


@router.post("/dispatch", response_model=NotificationDispatchResponse)
def dispatch_notifications(
    limit: int = Query(default=50, ge=1, le=200), user: dict = Depends(_soc_roles)
):
    # Attempts a real delivery only if a channel is configured; otherwise the outbox is
    # left untouched and reported honestly. No message is ever marked 'sent' without a
    # successful transport.
    try:
        return notification_service.dispatch_outbox(limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
