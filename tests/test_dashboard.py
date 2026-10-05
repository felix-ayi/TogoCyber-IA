import unittest
import json
from datetime import datetime, timezone

from frontend.services.analysis_report import build_analysis_report
from frontend.services.response_guidance import get_action_guidance
from frontend.views.home import _comparison_rows


class DashboardTests(unittest.TestCase):
    def test_guidance_is_cautious_and_contextual_for_each_prediction(self):
        phishing_guidance = get_action_guidance("phishing", "phishing")
        safe_text_guidance = get_action_guidance("phishing", "legitimate")
        network_alert_guidance = get_action_guidance("network", "malicious")
        network_benign_guidance = get_action_guidance("network", "benign")

        self.assertTrue(any("OTP" in action for action in phishing_guidance["actions"]))
        self.assertIn("ne garantit pas", safe_text_guidance["caution"])
        self.assertTrue(any("administrateur" in action for action in network_alert_guidance["actions"]))
        self.assertIn("ne prouve pas", network_benign_guidance["actions"][0])
        for guidance in (
            phishing_guidance,
            safe_text_guidance,
            network_alert_guidance,
            network_benign_guidance,
        ):
            self.assertTrue(guidance["actions"])
            self.assertTrue(guidance["caution"])

    def test_guidance_rejects_unknown_model_results(self):
        with self.assertRaisesRegex(ValueError, "unsupported analysis result"):
            get_action_guidance("phishing", "unknown")

    def test_exported_analysis_report_contains_result_and_excludes_raw_input(self):
        result = {
            "module": "phishing",
            "prediction": "phishing",
            "phishing_probability": 0.91,
            "confidence": 0.91,
            "confidence_level": "high",
            "explanation": [{"term": "verify", "contribution": 0.5}],
            "explanation_truncated": True,
            "history_id": 4,
            "submitted_text": "private SMS body",
            "features": {"source_port": 1234},
        }
        timestamp = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)

        report = json.loads(build_analysis_report(result, timestamp))

        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["generated_at"], "2026-10-05T12:00:00+00:00")
        self.assertEqual(report["threat_probability"], 0.91)
        self.assertEqual(report["explanation"][0]["term"], "verify")
        self.assertTrue(report["explanation_truncated"])
        self.assertTrue(report["recommended_actions"]["actions"])
        self.assertFalse(report["privacy"]["submitted_content_included"])
        self.assertNotIn("private SMS body", json.dumps(report))
        self.assertNotIn("source_port", json.dumps(report))

    def test_exported_report_rejects_naive_timestamps(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            build_analysis_report(
                {
                    "module": "network",
                    "prediction": "benign",
                    "malicious_probability": 0.1,
                    "confidence": 0.9,
                    "confidence_level": "high",
                },
                datetime(2026, 10, 5, 12, 0),
            )

    def test_comparison_rows_show_validation_test_and_selected_model(self):
        rows = _comparison_rows({
            "algorithm": "xgboost",
            "comparison_metrics": {
                "random_forest": {
                    "validation_f1": 0.93,
                    "held_out_test": {
                        "f1": 0.92,
                        "precision": 0.97,
                        "recall": 0.88,
                        "roc_auc": 0.98,
                    },
                },
                "xgboost": {
                    "validation_f1": 0.94,
                    "held_out_test": {
                        "f1": 0.91,
                        "precision": 0.98,
                        "recall": 0.87,
                        "roc_auc": 0.99,
                    },
                },
            },
        })

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Algorithme"], "Random Forest")
        self.assertEqual(rows[1]["F1 validation"], "94.0%")
        self.assertEqual(rows[1]["ROC-AUC test"], "99.0%")
        self.assertEqual([row["Modèle retenu"] for row in rows], ["Non", "Oui"])

    def test_missing_comparison_metrics_are_shown_as_unavailable(self):
        rows = _comparison_rows({
            "algorithm": "multinomial_nb",
            "comparison_metrics": {
                "multinomial_nb": {"validation_f1": None, "held_out_test": None},
            },
        })

        self.assertEqual(rows[0]["F1 validation"], "—")
        self.assertEqual(rows[0]["F1 test"], "—")
        self.assertEqual(rows[0]["Modèle retenu"], "Oui")


if __name__ == "__main__":
    unittest.main()
