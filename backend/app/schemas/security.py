from pydantic import BaseModel, Field


class SecurityCategory(BaseModel):
    name: str
    score: int = Field(..., ge=0, le=100)
    level: str
    notes: str


class RiskGraphNode(BaseModel):
    id: str
    type: str
    label: str
    severity: str | None = None


class RiskGraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class RiskGraphResponse(BaseModel):
    notice: str = "Graphique construit uniquement à partir des données locales disponibles."
    nodes: list[RiskGraphNode] = Field(default_factory=list)
    edges: list[RiskGraphEdge] = Field(default_factory=list)


class SecurityPostureResponse(BaseModel):
    overall_score: int = Field(..., ge=0, le=100)
    level: str
    summary: str
    strengths: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    categories: list[SecurityCategory] = Field(default_factory=list)
    basis: str = "Calculé uniquement à partir des données locales disponibles."
