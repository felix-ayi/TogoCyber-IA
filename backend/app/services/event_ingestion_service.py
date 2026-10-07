"""Normalize supported source events into the shared event contract."""

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from backend.app.schemas.events import NormalizedEvent

_SURICATA_SEVERITIES = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


def normalize_suricata_event(raw_event: dict[str, Any]) -> NormalizedEvent:
    if not isinstance(raw_event, dict):
        raise ValueError("Suricata EVE event must be a JSON object")
    try:
        canonical = json.dumps(
            raw_event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Suricata EVE event must contain finite JSON data") from exc

    alert = raw_event.get("alert")
    if not isinstance(alert, dict):
        alert = {}
    source_severity = alert.get("severity")
    severity = (
        _SURICATA_SEVERITIES.get(source_severity, "INFO")
        if isinstance(source_severity, int) and not isinstance(source_severity, bool)
        else "INFO"
    )
    event_type = raw_event.get("event_type")
    metadata = {
        key: value
        for key, value in {
            "flow_id": raw_event.get("flow_id"),
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
        }.items()
        if value is not None
    }
    try:
        return NormalizedEvent(
            event_id=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            timestamp=raw_event.get("timestamp"),
            source="suricata",
            source_type="ids",
            host=raw_event.get("host") or raw_event.get("hostname"),
            user=raw_event.get("user"),
            src_ip=raw_event.get("src_ip"),
            dst_ip=raw_event.get("dest_ip"),
            src_port=raw_event.get("src_port"),
            dst_port=raw_event.get("dest_port"),
            protocol=raw_event.get("proto"),
            event_type=event_type,
            severity=severity,
            message=alert.get("signature") or raw_event.get("msg") or event_type,
            raw_event=raw_event,
            metadata=metadata,
        )
    except ValidationError as exc:
        raise ValueError("Suricata EVE event does not match the normalized event contract") from exc