from typing import Literal

from pydantic import BaseModel, Field

AlertStatus = Literal[
    "NEW",
    "INVESTIGATING",
    "CONFIRMED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "CLOSED",
]
AlertSeverity = Literal["MEDIUM", "HIGH", "CRITICAL"]


class AlertResponse(BaseModel):
    id: int
    history_id: int | None
    incident_id: int | None
    module: Literal["network", "phishing"]
    title: str
    severity: AlertSeverity
    risk_score: int = Field(ge=0, le=100)
    status: AlertStatus
    assignee_user_id: int | None
    created_at: str
    updated_at: str
    tags: list[str] = []


class AlertListResponse(BaseModel):
    items: list[AlertResponse]


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)

    model_config = {"extra": "forbid"}


class AlertAssignRequest(BaseModel):
    assignee_user_id: int | None = None

    model_config = {"extra": "forbid"}


class AlertStatusEvent(BaseModel):
    id: int
    alert_id: int
    actor_user_id: int | None
    previous_status: AlertStatus | None
    new_status: AlertStatus
    note: str | None
    created_at: str


class AlertStatusEventListResponse(BaseModel):
    items: list[AlertStatusEvent]


class AlertCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)

    model_config = {"extra": "forbid"}


class AlertComment(BaseModel):
    id: int
    alert_id: int
    author_user_id: int | None
    body: str
    created_at: str


class AlertCommentListResponse(BaseModel):
    items: list[AlertComment]


class AlertTagRequest(BaseModel):
    tag: str = Field(min_length=1, max_length=48)

    model_config = {"extra": "forbid"}


class AlertTagListResponse(BaseModel):
    tags: list[str]


class AlertStatusCounts(BaseModel):
    counts: dict[str, int]


class SocAlertOverview(BaseModel):
    total: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    open: int
    unassigned_open: int
    critical_open: int


class SocIncidentOverview(BaseModel):
    total: int
    by_status: dict[str, int]
    active: int


class SocOverviewResponse(BaseModel):
    alerts: SocAlertOverview
    incidents: SocIncidentOverview

