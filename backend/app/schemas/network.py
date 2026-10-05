from typing import Literal

from pydantic import BaseModel, Field


class NetworkAnalysisRequest(BaseModel):
    features: dict[str, float] = Field(description="All feature names from the canonical network API schema.")

    model_config = {"extra": "forbid"}


class NetworkExplanation(BaseModel):
    feature: str
    contribution: float


class NetworkAnalysisResponse(BaseModel):
    status: Literal["success"]
    module: Literal["network"]
    prediction: Literal["malicious", "benign"]
    malicious_probability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    confidence_level: Literal["low", "medium", "high"]
    features: dict[str, float]
    explanation: list[NetworkExplanation]
    history_id: int