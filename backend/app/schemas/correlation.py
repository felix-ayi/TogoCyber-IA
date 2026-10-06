from typing import Literal

from pydantic import BaseModel, Field

RuleModule = Literal["network", "phishing", "any"]
MinSeverity = Literal["MEDIUM", "HIGH", "CRITICAL"]
FindingStatus = Literal["OPEN", "ACKNOWLEDGED", "CLOSED"]


class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    module: RuleModule
    min_severity: MinSeverity
    threshold: int = Field(ge=2, le=100)
    window_minutes: int = Field(ge=1, le=1440)
    description: str | None = Field(default=None, max_length=2000)
    is_active: bool = True

    model_config = {"extra": "forbid"}


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    module: RuleModule | None = None
    min_severity: MinSeverity | None = None
    threshold: int | None = Field(default=None, ge=2, le=100)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    description: str | None = Field(default=None, max_length=2000)
    is_active: bool | None = None

    model_config = {"extra": "forbid"}


class RuleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    module: RuleModule
    min_severity: MinSeverity
    threshold: int
    window_minutes: int
    is_active: bool
    created_by: int | None
    created_at: str
    updated_at: str


class RuleListResponse(BaseModel):
    items: list[RuleResponse]


class FindingResponse(BaseModel):
    id: int
    rule_id: int
    alert_count: int
    window_start: str
    window_end: str
    status: FindingStatus
    created_at: str
    alert_ids: list[int] = []


class FindingListResponse(BaseModel):
    items: list[FindingResponse]


class FindingStatusUpdate(BaseModel):
    status: FindingStatus

    model_config = {"extra": "forbid"}


class CorrelationRunResponse(BaseModel):
    rules_evaluated: int
    findings_created: list[int]
