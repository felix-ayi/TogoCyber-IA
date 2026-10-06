from fastapi import APIRouter, Depends, Query

from backend.app.core.auth import require_roles
from backend.app.repositories import audit_repository
from backend.app.schemas.audit import AuditAction, AuditEventListResponse

router = APIRouter(prefix="/audit-events", tags=["Security Audit"])


@router.get(
    "",
    response_model=AuditEventListResponse,
    dependencies=[Depends(require_roles("Admin"))],
)
def audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    action: AuditAction | None = None,
    offset: int = Query(default=0, ge=0, le=10000),
):
    return {"items": audit_repository.list_events(limit=limit, action=action, offset=offset)}
