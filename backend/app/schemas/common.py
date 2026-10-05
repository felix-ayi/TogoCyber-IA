from pydantic import BaseModel, Field


class AnalysisResponse(BaseModel):
    status: str = "success"
    module: str
    prediction: str
    confidence: float = Field(ge=0, le=1)
    confidence_level: str
    explanation: list[dict]
    history_id: int