import unittest

from backend.app.main import app


class APIDocumentationTests(unittest.TestCase):
    def test_openapi_exposes_all_product_endpoints(self):
        paths = app.openapi()["paths"]
        expected = {
            "/api/v1/health",
            "/api/v1/network/analyze",
            "/api/v1/phishing/analyze",
            "/api/v1/assistant/ask",
            "/api/v1/history",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/auth/me",
            "/api/v1/incidents",
            "/api/v1/incidents/{incident_id}",
            "/api/v1/incidents/{incident_id}/events",
            "/api/v1/url/analyze",
            "/api/v1/audit-events",
        }
        self.assertTrue(expected.issubset(paths))


if __name__ == "__main__":
    unittest.main()
