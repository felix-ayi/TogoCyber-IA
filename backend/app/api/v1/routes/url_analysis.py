from fastapi import APIRouter, Depends, HTTPException

from backend.app.core.auth import get_current_user
from backend.app.schemas.url_analysis import URLAnalysisRequest, URLAnalysisResponse
from backend.app.services.url_analysis_service import analyze_url as inspect_url

router = APIRouter(prefix="/url", tags=["URL Inspection"])


@router.post("/analyze", response_model=URLAnalysisResponse)
def analyze_url(request: URLAnalysisRequest, _: dict = Depends(get_current_user)):
    try:
        return inspect_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
