from fastapi import APIRouter, HTTPException

from backend.app.core.auth import get_current_user
from backend.app.schemas.network import NetworkAnalysisRequest, NetworkAnalysisResponse
from backend.app.services.network_service import analyze_network as network_analysis
from fastapi import Depends

router = APIRouter(prefix="/network", tags=["Network Detection"])


@router.post("/analyze", response_model=NetworkAnalysisResponse)
def analyze_network(request: NetworkAnalysisRequest, user: dict = Depends(get_current_user)):
    try:
        return network_analysis(request.features, user_id=user["id"])
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
