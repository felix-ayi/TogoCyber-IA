from typing import Literal

from pydantic import BaseModel


class NotificationResponse(BaseModel):
    id: int
    event_type: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    subject: str
    body: str
    channel: Literal["email", "slack", "webhook"]
    delivery_status: Literal["not_configured", "sent", "failed"]
    created_at: str


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]


class NotificationCountsResponse(BaseModel):
    counts: dict[str, int]


class NotificationDispatchResponse(BaseModel):
    configured_channel: str | None
    considered: int
    sent: int
    failed: int
    remaining_not_configured: int
    detail: str
