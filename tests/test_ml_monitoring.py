import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.repositories import (
    alert_repository,
    audit_repository,
    auth_repository,
    history_repository,
    ml_monitoring_repository,
)
from backend.app.services import auth_service


class MlMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "ml.sqlite3"
        self.test_settings = replace(
            settings,
            database_path=self.database_path,
            auth_secret_key="test-auth-secret-key-with-32-bytes-minimum",
            bootstrap_admin_email="",
            bootstrap_admin_password="",
        )
        self.patches = [
            patch.object(history_repository, "settings", self.test_settings),
            patch.object(auth_repository, "settings", self.test_settings),
            patch.object(audit_repository, "settings", self.test_settings),
            patch.object(alert_repository, "settings", self.test_settings),
            patch.object(ml_monitoring_repository, "settings", self.test_settings),
            patch.object(auth_service, "settings", self.test_settings),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()
        history_repository.initialize_database()

        self.analyst = auth_repository.create_user(
            "analyst@example.org", auth_service._password_hash("a-long-analyst-passphrase"), "Analyst"
        )
        self.plain_user = auth_repository.create_user("user@example.org", "hash", "User")
        self.analyst_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(self.analyst)['access_token']}"
        }
        self.user_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(self.plain_user)['access_token']}"
        }

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def _raise(self, module="network", prediction="malicious", severity="HIGH"):
        return history_repository.record_event(
            module,
            prediction,
            0.9,
            "high",
            risk_score=80,
            severity=severity,
            model_name="demo-model",
            model_version="1.0.0",
        )

    def test_routes_are_restricted_to_soc_roles(self):
        self.assertEqual(
            self.client.get("/api/v1/ml/monitoring", headers=self.user_headers).status_code, 403
        )
        self.assertEqual(self.client.get("/api/v1/ml/monitoring").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/ml/monitoring", headers=self.analyst_headers).status_code, 200
        )

    def test_monitoring_reflects_real_detections(self):
        empty = self.client.get("/api/v1/ml/monitoring", headers=self.analyst_headers).json()
        self.assertEqual(empty["total_analyses"], 0)
        self.assertEqual(empty["modules"], {})

        # Two malicious network detections and one benign network detection.
        self._raise(module="network", prediction="malicious")
        self._raise(module="network", prediction="benign", severity="LOW")
        self._raise(module="phishing", prediction="phishing")

        data = self.client.get("/api/v1/ml/monitoring", headers=self.analyst_headers).json()
        self.assertEqual(data["total_analyses"], 3)
        network = data["modules"]["network"]
        self.assertEqual(network["total"], 2)
        self.assertEqual(network["malicious"], 1)
        self.assertEqual(network["malicious_rate"], 0.5)
        self.assertEqual(network["models"], {"demo-model@1.0.0": 2})
        self.assertEqual(network["by_prediction"], {"malicious": 1, "benign": 1})

        phishing = data["modules"]["phishing"]
        self.assertEqual(phishing["total"], 1)
        self.assertEqual(phishing["malicious_rate"], 1.0)

        # The window parameter is validated.
        self.assertEqual(
            self.client.get(
                "/api/v1/ml/monitoring", headers=self.analyst_headers, params={"days": 90}
            ).status_code,
            422,
        )

    def test_feedback_from_analyst_verdicts(self):
        # A false positive: raise an alert then close it as FALSE_POSITIVE.
        self._raise(module="network", prediction="malicious")
        fp_alert = alert_repository.list_alerts()[0]["id"]
        alert_repository.update_status(fp_alert, "FALSE_POSITIVE", self.analyst["id"])

        # A confirmed true positive: raise, investigate, then confirm.
        self._raise(module="phishing", prediction="phishing")
        confirmed_alert = [a for a in alert_repository.list_alerts() if a["id"] != fp_alert][0]["id"]
        alert_repository.update_status(confirmed_alert, "INVESTIGATING", self.analyst["id"])
        alert_repository.update_status(confirmed_alert, "CONFIRMED", self.analyst["id"])

        data = self.client.get("/api/v1/ml/monitoring", headers=self.analyst_headers).json()
        feedback = data["feedback"]
        self.assertEqual(feedback["false_positive"], 1)
        self.assertEqual(feedback["confirmed"], 1)
        self.assertEqual(feedback["total"], 2)
        self.assertEqual(feedback["false_positive_rate"], 0.5)

        items = self.client.get("/api/v1/ml/feedback", headers=self.analyst_headers).json()["items"]
        self.assertEqual(len(items), 2)
        self.assertEqual(
            sorted(item["verdict"] for item in items), ["confirmed", "false_positive"]
        )
        # Each verdict carries the model that produced the underlying detection.
        self.assertTrue(all(item["model_name"] == "demo-model" for item in items))


if __name__ == "__main__":
    unittest.main()
