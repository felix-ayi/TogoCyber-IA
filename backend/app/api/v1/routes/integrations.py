from fastapi import APIRouter, Depends

from backend.app.core.auth import require_roles
from backend.app.schemas.integrations import IntegrationStatusResponse
from backend.app.services.integrations_service import status_summary

router = APIRouter(prefix="/integrations", tags=["Integrations"])

_soc_roles = require_roles("Admin", "Analyst")


@router.get("", response_model=IntegrationStatusResponse, dependencies=[Depends(_soc_roles)])
def integrations():
    # Status only: reports which external sources are actually configured. Adapters that
    # are not configured are marked 'not_configured' and never return simulated telemetry.
    return status_summary()
