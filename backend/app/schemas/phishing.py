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
    explanation: list[PhishingExplanation]
    explanation_truncated: bool
    history_id: int