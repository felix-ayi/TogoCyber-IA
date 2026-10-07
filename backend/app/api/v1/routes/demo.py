from fastapi import APIRouter

from backend.app.schemas.demo import DemoScenario
from backend.app.services.demo_service import build_demo_scenario

router = APIRouter(prefix="/demo", tags=["Demo Mode"])


@router.get("/scenario", response_model=DemoScenario)
def get_demo_scenario() -> DemoScenario:
    return build_demo_scenario()
