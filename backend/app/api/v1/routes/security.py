from fastapi import APIRouter

from backend.app.schemas.security import SecurityPostureResponse
from backend.app.services.security_posture_service import compute_security_posture

router = APIRouter(prefix="/security", tags=["Security Posture"])


@router.get("/posture", response_model=SecurityPostureResponse)
def get_security_posture() -> SecurityPostureResponse:
    payload = compute_security_posture()
    return SecurityPostureResponse(**payload)
