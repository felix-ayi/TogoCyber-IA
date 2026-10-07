import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from backend.app.api.v1.routes.assistant import ask_assistant as assistant_endpoint
from backend.app.schemas.assistant import AssistantRequest
from backend.app.services.assistant_service import AssistantUnavailable, ask_assistant
from ml.assistant.context import build_messages


class AssistantTests(unittest.TestCase):
    def test_prompt_is_contextual_and_defensive(self):
        messages = build_messages("Comment vérifier un SMS suspect ?")
        self.assertEqual([item["role"] for item in messages], ["system", "user"])
        self.assertIn("code OTP", messages[0]["content"])
        self.assertIn("SMS suspect", messages[1]["content"])

    def test_missing_key_returns_demo_guidance_instead_of_error(self):
        with patch("backend.app.services.assistant_service.settings", SimpleNamespace(openai_api_key="", openai_model="test")):
            result = ask_assistant("Comment vérifier un SMS suspect ?")
        self.assertIn("SMS suspect", result["response"])
        self.assertIn("vérifier", result["response"].lower())
        self.assertIn("Prototype de recherche", result["disclaimer"])

    def test_blank_assistant_request_is_rejected_as_input_error(self):
        with self.assertRaises(HTTPException) as error:
            assistant_endpoint(AssistantRequest(message="   "))
        self.assertEqual(error.exception.status_code, 422)

    def test_overlong_assistant_request_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "20000-character"):
            build_messages("x" * 20_001)

    def test_non_string_assistant_request_is_rejected(self):
        with self.assertRaises(TypeError):
            build_messages(None)


if __name__ == "__main__":
    unittest.main()