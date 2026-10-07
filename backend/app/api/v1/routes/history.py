from fastapi import APIRouter, Depends, Query, status

from backend.app.core.auth import get_current_user
from backend.app.services.history_service import get_history, reset_history

router = APIRouter(prefix="/history", tags=["Analysis History"])


@router.get("")
def history(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    user: dict = Depends(get_current_user),
):
    user_id = None if user["role"] in {"Admin", "Analyst"} else user["id"]
    return {"items": get_history(limit, user_id=user_id, offset=offset)}


@router.delete("/clear", status_code=status.HTTP_204_NO_CONTENT)
def clear_history(user: dict = Depends(get_current_user)) -> None:
    user_id = None if user["role"] in {"Admin", "Analyst"} else user["id"]
    reset_history(user_id=user_id)
    return None
