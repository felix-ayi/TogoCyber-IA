from typing import Literal

from pydantic import BaseModel, Field

PlaybookModule = Literal["network", "phishing", "any"]
PlaybookSeverity = Literal["MEDIUM", "HIGH", "CRITICAL"]


class PlaybookStep(BaseModel):
    position: int
    instruction: str


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    module: PlaybookModule
    min_severity: PlaybookSeverity
    description: str | None = Field(default=None, max_length=2000)
    steps: list[str] = Field(default_factory=list, max_length=50)

    model_config = {"extra": "forbid"}


class PlaybookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    module: PlaybookModule | None = None
    min_severity: PlaybookSeverity | None = None
    description: str | None = Field(default=None, max_length=2000)
    steps: list[str] | None = Field(default=None, max_length=50)

    model_config = {"extra": "forbid"}


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: str | None
    module: PlaybookModule
    min_severity: PlaybookSeverity
    created_by: int | None
    created_at: str
    updated_at: str
    steps: list[PlaybookStep] = []


class PlaybookListResponse(BaseModel):
    items: list[PlaybookResponse]
