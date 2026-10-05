from pydantic import BaseModel, Field

from backend.app.core.security import MAX_MESSAGE_LENGTH


class AssistantRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)

    model_config = {"extra": "forbid"}


class AssistantResponse(BaseModel):
    response: str
    disclaimer: str