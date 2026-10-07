from pydantic import BaseModel, Field


class SecurityCategory(BaseModel):
    name: str
    score: int = Field(..., ge=0, le=100)
    level: str
    notes: str


class SecurityPostureResponse(BaseModel):
    overall_score: int = Field(..., ge=0, le=100)
    level: str
    summary: str
    strengths: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    categories: list[SecurityCategory] = Field(default_factory=list)
    basis: str = "Calculé uniquement à partir des données locales disponibles."
