from typing import Literal

from pydantic import BaseModel, Field


IncidentStatus = Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus

    model_config = {"extra": "forbid"}


class IncidentResponse(BaseModel):
    id: int
    history_id: int | None
    owner_user_id: int | None
    module: Literal["network", "phishing"]
    prediction: str
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["HIGH", "CRITICAL"]
    status: IncidentStatus
    created_at: str
    updated_at: str


class IncidentListResponse(BaseModel):
    items: list[IncidentResponse]


class IncidentStatusEvent(BaseModel):
    id: int
    incident_id: int
    actor_user_id: int | None
    previous_status: IncidentStatus | None
    new_status: IncidentStatus
    created_at: str


class IncidentStatusEventListResponse(BaseModel):
    items: list[IncidentStatusEvent]
