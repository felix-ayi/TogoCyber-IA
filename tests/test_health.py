import unittest
import json
from unittest.mock import patch

from backend.app.api.v1.routes import health as health_routes
from backend.app.api.v1.routes.health import health_check


class HealthTests(unittest.TestCase):
    def test_health_response_is_independent_of_model_artifacts(self):
        response = health_check()
        self.assertEqual(response["status"], "healthy")
        self.assertIn("version", response)
        self.assertEqual(set(response["models"]), {"network", "phishing"})
        self.assertIsInstance(response["assistant_configured"], bool)

    def test_liveness_is_independent_of_database_readiness(self):
        with patch.object(health_routes.history_repository, "database_ok", return_value=False):
            self.assertEqual(health_routes.liveness_check(), {"status": "alive"})

    def test_readiness_requires_database_and_reports_optional_models(self):
        with (
            patch.object(
                health_routes, "_dependency_checks", return_value={"database": "unavailable"}
            ),
            patch.object(
                health_routes, "_model_status", side_effect=[(False, {}), (True, {})]
            ),
        ):
            response = health_routes.readiness_check()

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["models"], {"network": False, "phishing": True})

    def test_health_marks_unloadable_model_artifact_unavailable(self):
        with patch.object(
            health_routes,
            "load_model",
            side_effect=EOFError("invalid model artifact"),
        ):
            response = health_check()

        self.assertEqual(response["status"], "healthy")
        self.assertFalse(response["models"]["network"])

    def test_health_does_not_log_error_for_model_not_yet_trained(self):
        with (
            patch.object(health_routes, "load_model", side_effect=FileNotFoundError),
            patch.object(health_routes.logger, "exception") as log_exception,
        ):
            health_check()

        log_exception.assert_not_called()

    def test_health_includes_registered_demo_metrics_and_provenance(self):
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
            patch.object(health_routes, "load_model", return_value=object()),
            patch.object(
                health_routes,
                "registered_model_metadata",
                side_effect=lambda name: metadata[name],
            ),
        ):
            response = health_check()

        self.assertEqual(response["model_details"]["network"]["algorithm"], "xgboost")
        self.assertEqual(response["model_details"]["network"]["test_rows"], 175341)
        self.assertEqual(response["model_details"]["phishing"]["metrics"]["f1"], 0.96)


if __name__ == "__main__":
    unittest.main()