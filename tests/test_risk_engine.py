import unittest

from backend.app.services.risk_engine import assess_risk, severity_for_score


class RiskEngineTests(unittest.TestCase):
    def test_severity_thresholds_match_documented_ranges(self):
        cases = {
            0: "VERY_LOW",
            20: "VERY_LOW",
            21: "LOW",
            40: "LOW",
            41: "MEDIUM",
            60: "MEDIUM",
            61: "HIGH",
            80: "HIGH",
            81: "CRITICAL",
            100: "CRITICAL",
        }
        for score, severity in cases.items():
            with self.subTest(score=score):
                self.assertEqual(severity_for_score(score), severity)

    def test_assessment_preserves_uncertainty_and_explanation_direction(self):
        result = assess_risk(
            "network",
            "malicious",
            threat_probability=0.81,
            confidence=0.81,
            explanation=[
                {"feature": "dst_port", "contribution": 0.3},
                {"feature": "duration", "contribution": -0.2},
            ],
        )
        self.assertEqual(result["risk_score"], 81)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["classification"], "malicious")
        self.assertEqual(
            [indicator["direction"] for indicator in result["indicators"]],
            ["raises_risk", "lowers_risk"],
        )
        self.assertTrue(result["recommendations"])

    def test_invalid_probabilities_and_classifications_are_rejected(self):
        for probability in (float("nan"), float("inf"), -0.1, 1.1):
            with self.subTest(probability=probability):
                with self.assertRaisesRegex(ValueError, "threat_probability"):
                    assess_risk("phishing", "phishing", probability, 0.9)
        with self.assertRaisesRegex(ValueError, "unsupported classification"):
            assess_risk("network", "phishing", 0.9, 0.9)


if __name__ == "__main__":
    unittest.main()
