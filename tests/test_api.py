import unittest
import uuid

from backend.app.main import app


class APIDocumentationTests(unittest.TestCase):
    def test_openapi_exposes_all_product_endpoints(self):
        paths = app.openapi()["paths"]
        expected = {
            "/api/v1/health",
            "/api/v1/health/live",
            "/api/v1/health/ready",
            "/api/v1/events",
            "/api/v1/events/ingest/suricata",
            "/api/v1/network/analyze",
            "/api/v1/phishing/analyze",
            "/api/v1/assistant/ask",
            "/api/v1/history",
            "/api/v1/history/clear",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/auth/me",
            "/api/v1/incidents",
            "/api/v1/incidents/{incident_id}",
            "/api/v1/incidents/{incident_id}/events",
            "/api/v1/url/analyze",
            "/api/v1/audit-events",
            "/api/v1/demo/scenario",
            "/api/v1/security/posture",
        }
        self.assertTrue(expected.issubset(paths))

    def test_demo_scenario_is_marked_as_synthetic(self):
        client = __import__("fastapi.testclient").testclient.TestClient(app)
        response = client.get("/api/v1/demo/scenario")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scenario"], "AI4YOUTH DEMO")
        self.assertEqual(payload["mode"], "demo")
        self.assertIn("SCÉNARIO DE DÉMONSTRATION — DONNÉES SYNTHÉTIQUES", payload["notice"])
        self.assertEqual(payload["risk_score"], 92)
        self.assertGreater(len(payload["steps"]), 0)

    def test_security_posture_uses_local_data_only(self):
        client = __import__("fastapi.testclient").testclient.TestClient(app)
        response = client.get("/api/v1/security/posture")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("overall_score", payload)
        self.assertIn("categories", payload)
        self.assertEqual(payload["basis"], "Calculé uniquement à partir des données locales disponibles.")
        self.assertTrue(0 <= payload["overall_score"] <= 100)

    def test_history_clear_resets_user_scope(self):
        from backend.app.repositories import auth_repository, history_repository
        from backend.app.services import auth_service

        email = f"clear-history-{uuid.uuid4().hex[:8]}@example.org"
        user = auth_repository.create_user(email, "hash", "User")
        history_repository.record_event(
            "phishing",
            "suspicious_email",
            0.93,
            "high",
            user_id=user["id"],
            risk_score=86,
            severity="HIGH",
        )

        token = auth_service._issue_token(user)["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        clear_response = __import__("fastapi.testclient").testclient.TestClient(app).delete(
            "/api/v1/history/clear",
            headers=headers,
        )
        self.assertEqual(clear_response.status_code, 204)

        fetch_response = __import__("fastapi.testclient").testclient.TestClient(app).get(
            "/api/v1/history",
            headers=headers,
        )
        self.assertEqual(fetch_response.status_code, 200)
        self.assertEqual(fetch_response.json()["items"], [])


if __name__ == "__main__":
    unittest.main()
