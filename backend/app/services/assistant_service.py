"""Contextual assistant with a safe local guidance fallback for demo deployments."""

from backend.app.core.config import settings
from backend.app.core.security import validate_message_text
from ml.assistant.context import build_messages
from ml.assistant.llm_client import LLMServiceError, generate_completion


class AssistantUnavailable(RuntimeError):
    """The configured external assistant cannot safely serve the request."""


def _build_demo_guidance(message: str) -> str:
    normalized = validate_message_text(message)
    lowered = normalized.lower()
    if any(token in lowered for token in ("sms", "email", "message", "phishing", "lien", "url")):
        return (
            "Mode démonstration — conseils de prudence.\n\n"
            "Pour un SMS suspect, vérifiez d’abord l’expéditeur, le contexte et toute demande d’action urgente. "
            "N’ouvrez pas de liens ni de pièces jointes inconnus, et ne partagez jamais un code OTP, un mot de passe ou un identifiant. "
            "Pour vérifier le risque, confirmez via le canal officiel de l’organisation avant de réagir."
        )
    if any(token in lowered for token in ("incident", "alerte", "risque", "réponse", "priorité")):
        return (
            "Mode démonstration — conseils de prudence.\n\n"
            "Commencez par confirmer la source de l’alerte et la portée probable de l’impact. "
            "Isolez les actifs concernés, collectez les éléments probants, puis validez l’échelle de priorité avant toute action de blocage ou de suppression."
        )
    return (
        "Mode démonstration — conseils de prudence.\n\n"
        "Concentrez-vous sur la source, le contexte et le besoin réel d’action. "
        "Vérifiez les informations via un canal fiable, évitez les liens non vérifiés et ne divulguez pas d’identifiants ou de secrets."
    )


def ask_assistant(message: str) -> dict:
    normalized_message = validate_message_text(message)
    if not settings.openai_api_key:
        return {
            "response": _build_demo_guidance(normalized_message),
            "disclaimer": "Prototype de recherche : le conseil ci-dessus est une aide locale de démonstration. Vérifiez les décisions critiques auprès d’une source fiable.",
        }
    try:
        answer = generate_completion(build_messages(normalized_message), settings.openai_api_key, settings.openai_model)
    except (LLMServiceError, ValueError) as exc:
        return {
            "response": _build_demo_guidance(normalized_message),
            "disclaimer": f"L’assistant externe n’a pu être utilisé : {exc}. Ce retour est une aide locale de démonstration, à vérifier avec une source fiable.",
        }
    return {
        "response": answer,
        "disclaimer": "Prototype de recherche : vérifiez les conseils importants auprès d’une source de confiance.",
    }