from pydantic import BaseModel, Field


class DemoStep(BaseModel):
    order: int = Field(..., ge=1)
    name: str
    description: str


class DemoScenario(BaseModel):
    scenario: str = "AI4YOUTH DEMO"
    mode: str = "demo"
    notice: str = "SCÉNARIO DE DÉMONSTRATION — DONNÉES SYNTHÉTIQUES"
    risk_score: int = Field(..., ge=0, le=100)
    severity: str = "CRITICAL"
    asset: str = "SERVER-001"
    incident_title: str
    facts: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    steps: list[DemoStep] = Field(default_factory=list)
