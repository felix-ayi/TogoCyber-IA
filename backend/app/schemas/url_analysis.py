from typing import Literal

from pydantic import BaseModel, Field

from backend.app.services.url_analysis_service import MAX_URL_LENGTH


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    model_config = {"extra": "forbid"}


class URLIndicator(BaseModel):
    name: str
    contribution: int = Field(gt=0, le=100)


class URLAnalysisResponse(BaseModel):
    status: Literal["success"]
    module: Literal["url"]
    suspicion_score: int = Field(ge=0, le=100)
    severity: Literal["VERY_LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    indicators: list[URLIndicator]
    recommendations: list[str]
    caution: str
