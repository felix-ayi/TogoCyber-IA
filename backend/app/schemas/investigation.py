from typing import Literal

from pydantic import BaseModel

TimelineKind = Literal[
    "detection",
    "alert_status",
    "comment",
    "incident_status",
    "audit",
]


class TimelineEvent(BaseModel):
    timestamp: str
    kind: TimelineKind
    title: str
    detail: str | None = None
    actor_user_id: int | None = None
    actor_email: str | None = None


class AlertTimelineResponse(BaseModel):
    alert_id: int
    items: list[TimelineEvent]


class SearchAlertHit(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    created_at: str


class SearchIncidentHit(BaseModel):
    id: int
    module: str
    prediction: str
    severity: str | None
    status: str
    created_at: str


class SearchDetectionHit(BaseModel):
    id: int
    module: str
    prediction: str
    severity: str | None
    confidence_level: str | None
    created_at: str


class SearchAuditHit(BaseModel):
    id: int
    action: str
    outcome: str
    target_type: str | None
    target_id: int | None
    created_at: str


class SearchResponse(BaseModel):
    term: str
    alerts: list[SearchAlertHit]
    incidents: list[SearchIncidentHit]
    detections: list[SearchDetectionHit]
    audit_events: list[SearchAuditHit]
