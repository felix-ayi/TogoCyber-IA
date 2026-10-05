from fastapi import APIRouter, HTTPException

from backend.app.schemas.assistant import AssistantRequest, AssistantResponse
from backend.app.services.assistant_service import AssistantUnavailable, ask_assistant as assistant_service

router = APIRouter(prefix="/assistant", tags=["AI Assistant"])


@router.post("/ask", response_model=AssistantResponse)
def ask_assistant(request: AssistantRequest):
    if not request.message.strip():
        raise HTTPException(status_code=422, detail="Saisissez une question non vide.")
    try:
        return assistant_service(request.message)
    except AssistantUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
