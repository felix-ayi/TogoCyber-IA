"""Contextual OpenAI assistant; no local or success-shaped fallback."""

from backend.app.core.config import settings
from backend.app.core.security import validate_message_text
from ml.assistant.context import build_messages
from ml.assistant.llm_client import LLMServiceError, generate_completion


class AssistantUnavailable(RuntimeError):
    """The configured external assistant cannot safely serve the request."""


def ask_assistant(message: str) -> dict:
    if not settings.openai_api_key:
        raise AssistantUnavailable("L’assistant externe n’est pas configuré. Les analyses ML restent disponibles.")
    normalized_message = validate_message_text(message)
    try:
        answer = generate_completion(build_messages(normalized_message), settings.openai_api_key, settings.openai_model)
    except (LLMServiceError, ValueError) as exc:
        raise AssistantUnavailable(str(exc)) from exc
    return {
        "response": answer,
        "disclaimer": "Prototype de recherche : vérifiez les conseils importants auprès d’une source de confiance.",
    }