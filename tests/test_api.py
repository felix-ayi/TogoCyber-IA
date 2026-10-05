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
        }
        self.assertTrue(expected.issubset(paths))


if __name__ == "__main__":
    unittest.main()
