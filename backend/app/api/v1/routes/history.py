from fastapi import APIRouter, Query

from backend.app.services.history_service import get_history

router = APIRouter(prefix="/history", tags=["Analysis History"])


@router.get("")
def history(limit: int = Query(default=50, ge=1, le=100)):
    return {"items": get_history(limit)}
