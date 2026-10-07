from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import ioc_repository
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.schemas.iocs import (
    IocCreate,
    IocListResponse,
    IocLookupResponse,
    IocResponse,
    IocStatusCounts,
    IocTagListResponse,
    IocTagRequest,
    IocUpdate,
)

router = APIRouter(prefix="/iocs", tags=["Threat Intelligence"])

# Indicator management is a SOC function: analysts and administrators only.
_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=IocListResponse, dependencies=[Depends(_soc_roles)])
def list_iocs(
    limit: int = Query(default=50, ge=1, le=100),
    ioc_type: str | None = Query(
        default=None, alias="type", pattern="^(ip|domain|url|hash|email)$"
    ),
    ioc_status: str | None = Query(
        default=None, alias="status", pattern="^(ACTIVE|EXPIRED|REVOKED)$"
    ),
    severity: str | None = Query(
        default=None, alias="severity", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"
    ),
    tag: str | None = Query(default=None, max_length=48),
    offset: int = Query(default=0, ge=0, le=10000),
):
    try:
        items = ioc_repository.list_iocs(
            limit=limit, ioc_type=ioc_type, status=ioc_status, severity=severity, tag=tag,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"items": items}


@router.get("/counts", response_model=IocStatusCounts, dependencies=[Depends(_soc_roles)])
def ioc_counts():
    return {"counts": ioc_repository.status_counts()}


@router.get("/lookup", response_model=IocLookupResponse, dependencies=[Depends(_soc_roles)])
def lookup_ioc(value: str = Query(min_length=1, max_length=2048)):
    try:
        matches = ioc_repository.lookup(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    # No external threat-intel provider is configured in this deployment; lookups are
    # served from the local indicator store only. Reported honestly, never simulated.
    return {"value": value, "matches": matches, "external_sources": []}


@router.post(
    "", response_model=IocResponse, status_code=status.HTTP_201_CREATED
)
def create_ioc(request: IocCreate, user: dict = Depends(_soc_roles)):
    try:
        created = ioc_repository.create_ioc(
            ioc_type=request.type,
            value=request.value,
            severity=request.severity,
            confidence=request.confidence,
            created_by=user["id"],
            source=request.source,
            description=request.description,
            status=request.status,
            expires_at=request.expires_at,
            tags=request.tags,
        )
    except ioc_repository.DuplicateIocError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("ioc.created", "success", user["id"], "ioc", created["id"])
    return created


@router.get("/{ioc_id}", response_model=IocResponse, dependencies=[Depends(_soc_roles)])
def get_ioc(ioc_id: int):
    try:
        return ioc_repository.get_ioc(ioc_id)
    except ioc_repository.IocNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/{ioc_id}", response_model=IocResponse)
def update_ioc(ioc_id: int, request: IocUpdate, user: dict = Depends(_soc_roles)):
    try:
        updated = ioc_repository.update_ioc(ioc_id, **request.model_dump(exclude_unset=True))
    except ioc_repository.IocNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("ioc.updated", "success", user["id"], "ioc", ioc_id)
    return updated


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ioc(ioc_id: int, user: dict = Depends(_soc_roles)):
    try:
        ioc_repository.delete_ioc(ioc_id)
    except ioc_repository.IocNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_audit_event("ioc.deleted", "success", user["id"], "ioc", ioc_id)
    return None


@router.post("/{ioc_id}/tags", response_model=IocTagListResponse)
def add_ioc_tag(ioc_id: int, request: IocTagRequest, user: dict = Depends(_soc_roles)):
    try:
        tags = ioc_repository.add_tag(ioc_id, request.tag)
    except ioc_repository.IocNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("ioc.tag_added", "success", user["id"], "ioc", ioc_id)
    return {"tags": tags}


@router.delete("/{ioc_id}/tags/{tag}", response_model=IocTagListResponse)
def remove_ioc_tag(ioc_id: int, tag: str, user: dict = Depends(_soc_roles)):
    try:
        tags = ioc_repository.remove_tag(ioc_id, tag)
    except ioc_repository.IocNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("ioc.tag_removed", "success", user["id"], "ioc", ioc_id)
    return {"tags": tags}
