from typing import Literal

from pydantic import BaseModel, Field

IocType = Literal["ip", "domain", "url", "hash", "email"]
IocSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
IocStatus = Literal["ACTIVE", "EXPIRED", "REVOKED"]


class IocCreate(BaseModel):
    type: IocType
    value: str = Field(min_length=1, max_length=2048)
    severity: IocSeverity
    confidence: int = Field(ge=0, le=100)
    source: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    status: IocStatus = "ACTIVE"
    expires_at: str | None = None
    tags: list[str] = []

    model_config = {"extra": "forbid"}


class IocUpdate(BaseModel):
    severity: IocSeverity | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    source: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    status: IocStatus | None = None
    expires_at: str | None = None

    model_config = {"extra": "forbid"}


class IocResponse(BaseModel):
    id: int
    type: IocType
    value: str
    severity: IocSeverity
    confidence: int
    source: str | None
    description: str | None
    status: IocStatus
    expires_at: str | None
    created_by: int | None
    created_at: str
    updated_at: str
    tags: list[str] = []


class IocListResponse(BaseModel):
    items: list[IocResponse]


class IocTagRequest(BaseModel):
    tag: str = Field(min_length=1, max_length=48)

    model_config = {"extra": "forbid"}


class IocTagListResponse(BaseModel):
    tags: list[str]


class IocLookupResponse(BaseModel):
    value: str
    matches: list[IocResponse]
    external_sources: list[str] = []


class IocStatusCounts(BaseModel):
    counts: dict[str, int]
