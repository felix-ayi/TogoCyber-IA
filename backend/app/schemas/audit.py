from typing import Literal

from pydantic import BaseModel

AuditAction = Literal[
    "auth.registered",
    "auth.login.succeeded",
    "auth.login.failed",
    "auth.login.rate_limited",
    "auth.logout",
    "user.provisioned",
    "user.role_changed",
    "user.activated",
    "user.deactivated",
    "user.deleted",
    "user.password_reset",
    "incident.status_changed",
    "alert.status_changed",
    "alert.assigned",
    "ioc.created",
    "ioc.updated",
    "ioc.deleted",
    "rule.created",
    "rule.updated",
    "rule.deleted",
    "correlation.run",
    "playbook.created",
    "playbook.updated",
    "playbook.deleted",
]


class AuditEventResponse(BaseModel):
    id: int
    actor_user_id: int | None
    action: AuditAction
    outcome: Literal["success", "failure"]
    target_type: Literal[
        "auth", "user", "incident", "alert", "ioc", "rule", "playbook"
    ] | None
    target_id: int | None
    created_at: str


class AuditEventListResponse(BaseModel):
    items: list[AuditEventResponse]
