import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

EventSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_RAW_EVENT_BYTES = 64 * 1024


class NormalizedEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=64)
    timestamp: datetime
    source: str = Field(min_length=1, max_length=128)
    source_type: str = Field(min_length=1, max_length=64)
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    event_type: str = Field(min_length=1, max_length=128)
    severity: EventSeverity = "INFO"
    message: str | None = Field(default=None, max_length=4096)
    raw_event: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def raw_event_must_be_bounded_json(self):
        try:
            encoded = json.dumps(
                self.raw_event, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("raw_event must be finite JSON data") from exc
        if len(encoded) > MAX_RAW_EVENT_BYTES:
            raise ValueError(f"raw_event must not exceed {MAX_RAW_EVENT_BYTES} bytes")
        return self


class EventIngestResponse(BaseModel):
    event: NormalizedEvent
    inserted: bool


class SuricataEveIngestRequest(BaseModel):
    event: dict[str, Any]

    model_config = ConfigDict(extra="forbid")


class EventListResponse(BaseModel):
    items: list[NormalizedEvent]