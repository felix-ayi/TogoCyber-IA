from pydantic import BaseModel


class DriftSignal(BaseModel):
    recent_malicious_rate: float | None
    prior_malicious_rate: float | None
    delta: float | None
    note: str


class ModuleMonitoring(BaseModel):
    total: int
    malicious: int
    malicious_rate: float | None
    by_prediction: dict[str, int]
    by_severity: dict[str, int]
    models: dict[str, int]
    drift: DriftSignal


class FeedbackSummary(BaseModel):
    false_positive: int
    confirmed: int
    total: int
    false_positive_rate: float | None
    by_model: dict[str, dict[str, int]]


class MonitoringResponse(BaseModel):
    window_days: int
    total_analyses: int
    modules: dict[str, ModuleMonitoring]
    feedback: FeedbackSummary


class FeedbackItem(BaseModel):
    id: int
    alert_id: int | None
    history_id: int | None
    module: str
    model_name: str | None
    model_version: str | None
    verdict: str
    created_by: int | None
    created_at: str


class FeedbackListResponse(BaseModel):
    items: list[FeedbackItem]
