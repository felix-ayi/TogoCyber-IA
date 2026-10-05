"""Minimal OpenAI Chat Completions client with explicit provider errors."""

import requests


class LLMServiceError(RuntimeError):
    pass


def generate_completion(messages: list[dict[str, str]], api_key: str, model: str) -> str:
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "temperature": 0.2, "max_tokens": 500, "messages": messages},
            timeout=(5, 30),
        )
    except requests.RequestException as exc:
        raise LLMServiceError("Le service d’assistance est momentanément inaccessible.") from exc
    if response.status_code >= 400:
        raise LLMServiceError(f"Le service d’assistance a répondu avec le statut {response.status_code}.")
    try:
        answer = response.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMServiceError("La réponse du service d’assistance est invalide.") from exc
    if not isinstance(answer, str) or not answer.strip():
        raise LLMServiceError("Le service d’assistance a renvoyé une réponse vide.")
    return answer.strip()