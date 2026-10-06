import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.core.auth import get_current_user
from backend.app.main import app
from backend.app.schemas.url_analysis import URLAnalysisRequest, URLAnalysisResponse
from backend.app.services.url_analysis_service import MAX_URL_LENGTH, analyze_url


class URLAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_safe_https_domain_has_no_structural_indicators(self):
        result = analyze_url("https://example.org/documentation")
        self.assertEqual(result["module"], "url")
        self.assertEqual(result["suspicion_score"], 0)
        self.assertEqual(result["indicators"], [])
        URLAnalysisResponse.model_validate(result)

    def test_suspicious_url_exposes_individual_structural_reasons(self):
        result = analyze_url("http://user:password@bit.ly:8080/verify?next=%25encoded")
        names = {indicator["name"] for indicator in result["indicators"]}
        self.assertGreaterEqual(result["suspicion_score"], 80)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertIn("Informations d’identification intégrées avant le domaine", names)
        self.assertIn("Domaine de raccourcissement de liens", names)
        self.assertIn("Port non standard explicite", names)
        self.assertLessEqual(result["suspicion_score"], 100)

    def test_unicode_domains_are_normalized_before_punycode_detection(self):
        result = analyze_url("https://xn--e1afmkfd.example/path")
        self.assertIn(
            "Nom de domaine international encodé en punycode",
            {indicator["name"] for indicator in result["indicators"]},
        )

    def test_invalid_scheme_authority_ports_and_hostnames_are_rejected(self):
        for url in (
            "javascript:alert(1)",
            "https:///missing-host",
            "https://example.org:99999/path",
            "https://bad..example/path",
            "https://bad host.example/path",
            "https://example.org\\@evil.example/path",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                analyze_url(url)

    def test_length_boundaries_are_enforced(self):
        base = "https://example.org/"
        candidate = base + "a" * (MAX_URL_LENGTH - len(base))
        self.assertEqual(len(URLAnalysisRequest(url=candidate).url), MAX_URL_LENGTH)
        self.assertEqual(analyze_url(candidate)["suspicion_score"], 8)
        with self.assertRaises(ValidationError):
            URLAnalysisRequest(url="x" * (MAX_URL_LENGTH + 1))
        with self.assertRaises(ValueError):
            analyze_url("x" * (MAX_URL_LENGTH + 1))

    def test_url_analysis_does_not_perform_dns_or_http_requests(self):
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not be used")),
            patch("requests.get", side_effect=AssertionError("URL must not be fetched")),
        ):
            url = "https://example.org/login"
            result = analyze_url(url)
        self.assertGreater(result["suspicion_score"], 0)
        self.assertNotIn(url, str(result))

    def test_endpoint_requires_auth_and_rejects_invalid_url(self):
        response = self.client.post("/api/v1/url/analyze", json={"url": "https://example.org"})
        self.assertEqual(response.status_code, 401)

        app.dependency_overrides[get_current_user] = lambda: {"id": 1}
        try:
            invalid_response = self.client.post(
                "/api/v1/url/analyze",
                headers={"Authorization": "Bearer test-token"},
                json={"url": "ftp://example.org"},
            )
            valid_response = self.client.post(
                "/api/v1/url/analyze",
                headers={"Authorization": "Bearer test-token"},
                json={"url": "https://example.org/login"},
            )
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(invalid_response.status_code, 422)
        self.assertEqual(valid_response.status_code, 200)
        self.assertNotIn("https://example.org/login", valid_response.text)
        URLAnalysisResponse.model_validate(valid_response.json())


if __name__ == "__main__":
    unittest.main()
