"""Small shared safeguards for request handling."""

import math

MAX_MESSAGE_LENGTH = 20_000


def validate_message_text(message: object, *, allow_empty: bool = False) -> str:
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    cleaned = message.strip()
    if not cleaned and not allow_empty:
        raise ValueError("message must not be empty")
    if len(cleaned) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"message exceeds the {MAX_MESSAGE_LENGTH}-character analysis limit")
    return cleaned


def confidence_level(confidence: float) -> str:
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("confidence must be a finite number between zero and one")
    numeric_confidence = float(confidence)
    if not math.isfinite(numeric_confidence) or not 0 <= numeric_confidence <= 1:
        raise ValueError("confidence must be between zero and one")
    if numeric_confidence < 0.6:
        return "low"
    if numeric_confidence < 0.8:
        return "medium"
    return "high"