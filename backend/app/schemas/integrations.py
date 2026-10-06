from typing import Literal

from pydantic import BaseModel


class IntegrationAdapter(BaseModel):
    key: str
    name: str
    category: str
    status: Literal["configured", "not_configured"]
    required_env: list[str]
    detail: str


class IntegrationStatusResponse(BaseModel):
    adapters: list[IntegrationAdapter]
    configured: int
    not_configured: int
    total: int
