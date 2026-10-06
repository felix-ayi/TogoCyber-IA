from typing import Literal

from pydantic import BaseModel, Field


class PhishingAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000, description="SMS, email, or URL text; not persisted.")

    model_config = {"extra": "forbid"}


class PhishingExplanation(BaseModel):
    term: str
    contribution: float


class PhishingAnalysisResponse(BaseModel):
    status: Literal["success"]
    module: Literal["phishing"]
    prediction: Literal["phishing", "legitimate"]
    phishing_probability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    confidence_level: Literal["low", "medium", "high"]
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["VERY_LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    classification: Literal["phishing", "legitimate"]
    indicators: list[dict]
    recommendations: list[str]
    explanation: list[PhishingExplanation]
    explanation_truncated: bool
    history_id: int
    incident_id: int | None = None