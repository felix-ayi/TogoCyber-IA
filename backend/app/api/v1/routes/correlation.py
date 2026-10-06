from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import correlation_repository
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.schemas.correlation import (
    CorrelationRunResponse,
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdate,
    RuleCreate,
    RuleListResponse,
    RuleResponse,
    RuleUpdate,
)

router = APIRouter(prefix="/correlation", tags=["Detection & Correlation"])

_soc_roles = require_roles("Admin", "Analyst")


@router.get("/rules", response_model=RuleListResponse, dependencies=[Depends(_soc_roles)])
def list_rules(include_inactive: bool = Query(default=True)):
    return {"items": correlation_repository.list_rules(include_inactive=include_inactive)}


@router.post(
    "/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED
)
def create_rule(request: RuleCreate, user: dict = Depends(_soc_roles)):
    try:
        rule = correlation_repository.create_rule(
            name=request.name,
            module=request.module,
            min_severity=request.min_severity,
            threshold=request.threshold,
            window_minutes=request.window_minutes,
            created_by=user["id"],
            description=request.description,
            is_active=request.is_active,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("rule.created", "success", user["id"], "rule", rule["id"])
    return rule


@router.get("/rules/{rule_id}", response_model=RuleResponse, dependencies=[Depends(_soc_roles)])
def get_rule(rule_id: int):
    try:
        return correlation_repository.get_rule(rule_id)
    except correlation_repository.RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
def update_rule(rule_id: int, request: RuleUpdate, user: dict = Depends(_soc_roles)):
    try:
        rule = correlation_repository.update_rule(rule_id, **request.model_dump(exclude_unset=True))
    except correlation_repository.RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("rule.updated", "success", user["id"], "rule", rule_id)
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: int, user: dict = Depends(_soc_roles)):
    try:
        correlation_repository.delete_rule(rule_id)
    except correlation_repository.RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_audit_event("rule.deleted", "success", user["id"], "rule", rule_id)
    return None


@router.post("/run", response_model=CorrelationRunResponse)
def run_correlation(user: dict = Depends(_soc_roles)):
    result = correlation_repository.run_correlation()
    record_audit_event("correlation.run", "success", user["id"])
    return result


@router.get("/findings", response_model=FindingListResponse, dependencies=[Depends(_soc_roles)])
def list_findings(
    limit: int = Query(default=50, ge=1, le=100),
    finding_status: str | None = Query(
        default=None, alias="status", pattern="^(OPEN|ACKNOWLEDGED|CLOSED)$"
    ),
    rule_id: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0, le=10000),
):
    try:
        items = correlation_repository.list_findings(
            limit=limit, finding_status=finding_status, rule_id=rule_id, offset=offset
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"items": items}


@router.get(
    "/findings/{finding_id}", response_model=FindingResponse, dependencies=[Depends(_soc_roles)]
)
def get_finding(finding_id: int):
    try:
        return correlation_repository.get_finding(finding_id)
    except correlation_repository.FindingNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
def update_finding(finding_id: int, request: FindingStatusUpdate, user: dict = Depends(_soc_roles)):
    try:
        return correlation_repository.update_finding_status(finding_id, request.status)
    except correlation_repository.FindingNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except correlation_repository.InvalidFindingTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
