"""Build the narrow, defensive assistant prompt context."""

from backend.app.core.security import validate_message_text
from ml.assistant.prompts import SYSTEM_PROMPT


def build_messages(user_message: str) -> list[dict[str, str]]:
    message = validate_message_text(user_message)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": message},
    ]