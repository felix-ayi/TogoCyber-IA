from fastapi import APIRouter, HTTPException

from backend.app.schemas.phishing import PhishingAnalysisRequest, PhishingAnalysisResponse
from backend.app.services.phishing_service import (
    AnalysisCapacityExceeded,
    analyze_phishing as phishing_analysis,
)

router = APIRouter(prefix="/phishing", tags=["Phishing Detection"])


@router.post("/analyze", response_model=PhishingAnalysisResponse)
def analyze_phishing(request: PhishingAnalysisRequest):
    try:
        return phishing_analysis(request.text)
    except AnalysisCapacityExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
