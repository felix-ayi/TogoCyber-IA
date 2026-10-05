import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from backend.app.api.v1.routes.health import health_check


class HealthTests(unittest.TestCase):
    def test_health_response_is_independent_of_model_artifacts(self):
        response = health_check()
        self.assertEqual(response["status"], "healthy")
        self.assertIn("version", response)
        self.assertEqual(set(response["models"]), {"network", "phishing"})
        self.assertIsInstance(response["assistant_configured"], bool)

    def test_health_includes_registered_demo_metrics_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            model_dir = Path(directory)
            (model_dir / "network.joblib").touch()
            (model_dir / "phishing.joblib").touch()
            metadata = {
                "network": {
                    "model": "xgboost",
                    "training_dataset": "unsw",
                    "test_dataset": "test.csv",
                    "test_rows": 175341,
                    "metrics": {"f1": 0.92, "roc_auc": 0.98},
                    "comparison_metrics": {"xgboost": {"validation_f1": 0.94}},
                },
                "phishing": {
                    "model": "logistic_regression",
                    "training_corpus": "public English emails",
                    "test_rows": 3727,
                    "metrics": {"f1": 0.96, "roc_auc": 0.99},
                    "comparison_metrics": {},
                },
            }
            with (
                patch("backend.app.api.v1.routes.health.MODELS_DIR", model_dir),
                patch(
                    "backend.app.api.v1.routes.health.registered_model_metadata",
                    side_effect=lambda name: metadata[name],
                ),
            ):
                response = health_check()

        self.assertEqual(response["model_details"]["network"]["algorithm"], "xgboost")
        self.assertEqual(response["model_details"]["network"]["test_rows"], 175341)
        self.assertEqual(response["model_details"]["phishing"]["metrics"]["f1"], 0.96)


if __name__ == "__main__":
    unittest.main()