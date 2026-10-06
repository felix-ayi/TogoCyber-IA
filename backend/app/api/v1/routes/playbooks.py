from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.core.auth import require_roles
from backend.app.repositories import playbook_repository
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.schemas.playbooks import (
    PlaybookCreate,
    PlaybookListResponse,
    PlaybookResponse,
    PlaybookUpdate,
)

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=PlaybookListResponse, dependencies=[Depends(_soc_roles)])
def list_playbooks(
    module: str | None = Query(default=None, pattern="^(network|phishing|any)$")
):
    try:
        return {"items": playbook_repository.list_playbooks(module=module)}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(request: PlaybookCreate, user: dict = Depends(_soc_roles)):
    try:
        playbook = playbook_repository.create_playbook(
            name=request.name,
            module=request.module,
            min_severity=request.min_severity,
            created_by=user["id"],
            description=request.description,
            steps=request.steps,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("playbook.created", "success", user["id"], "playbook", playbook["id"])
    return playbook


@router.get("/{playbook_id}", response_model=PlaybookResponse, dependencies=[Depends(_soc_roles)])
def get_playbook(playbook_id: int):
    try:
        return playbook_repository.get_playbook(playbook_id)
    except playbook_repository.PlaybookNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
def update_playbook(playbook_id: int, request: PlaybookUpdate, user: dict = Depends(_soc_roles)):
    try:
        playbook = playbook_repository.update_playbook(
            playbook_id, **request.model_dump(exclude_unset=True)
        )
    except playbook_repository.PlaybookNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("playbook.updated", "success", user["id"], "playbook", playbook_id)
    return playbook


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(playbook_id: int, user: dict = Depends(_soc_roles)):
    try:
        playbook_repository.delete_playbook(playbook_id)
    except playbook_repository.PlaybookNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_audit_event("playbook.deleted", "success", user["id"], "playbook", playbook_id)
    return None
