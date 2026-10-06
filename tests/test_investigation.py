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
    investigation_repository,
)
from backend.app.services import auth_service


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "investigation.sqlite3"
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
            patch.object(investigation_repository, "settings", self.test_settings),
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

    def _raise(self, severity="HIGH", risk_score=88, module="phishing", user_id=None):
        return history_repository.record_event(
            module,
            "phishing" if module == "phishing" else "malicious",
            0.9,
            "high",
            user_id=user_id,
            risk_score=risk_score,
            severity=severity,
        )

    def test_search_is_restricted_to_soc_roles(self):
        self._raise()
        self.assertEqual(
            self.client.get("/api/v1/search", headers=self.user_headers, params={"q": "phishing"}).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/v1/search", params={"q": "phishing"}).status_code, 401)
        ok = self.client.get("/api/v1/search", headers=self.analyst_headers, params={"q": "phishing"})
        self.assertEqual(ok.status_code, 200)

    def test_search_matches_each_entity_and_escapes_wildcards(self):
        self._raise(severity="HIGH", risk_score=88, user_id=self.plain_user["id"])
        alert_id = alert_repository.list_alerts()[0]["id"]
        alert_repository.add_tag(alert_id, "phishing")
        audit_repository.record_event("alert.status_changed", "success", self.analyst["id"], "alert", alert_id)

        results = self.client.get(
            "/api/v1/search", headers=self.analyst_headers, params={"q": "phishing"}
        ).json()
        self.assertEqual(results["term"], "phishing")
        self.assertTrue(any(a["id"] == alert_id for a in results["alerts"]))
        self.assertTrue(any(d["module"] == "phishing" for d in results["detections"]))
        self.assertEqual(len(results["incidents"]), 1)

        # Audit actions are searchable by their action name.
        audit_hits = self.client.get(
            "/api/v1/search", headers=self.analyst_headers, params={"q": "alert.status"}
        ).json()
        self.assertTrue(any(e["action"] == "alert.status_changed" for e in audit_hits["audit_events"]))

        # A wildcard-only term is escaped and matches nothing literally.
        wildcard = self.client.get(
            "/api/v1/search", headers=self.analyst_headers, params={"q": "%"}
        ).json()
        self.assertEqual(wildcard["alerts"], [])
        self.assertEqual(wildcard["detections"], [])

    def test_search_rejects_blank_term(self):
        # Whitespace-only terms are stripped to empty and rejected.
        blank = self.client.get("/api/v1/search", headers=self.analyst_headers, params={"q": "   "})
        self.assertEqual(blank.status_code, 422)

    def test_timeline_merges_all_sources_chronologically(self):
        history_id = self._raise(severity="HIGH", risk_score=88, user_id=self.plain_user["id"])
        alert_id = alert_repository.list_alerts()[0]["id"]
        alert_repository.update_status(alert_id, "INVESTIGATING", self.analyst["id"], "Triaging")
        alert_repository.add_comment(alert_id, self.analyst["id"], "Checked sender domain")

        response = self.client.get(
            f"/api/v1/alerts/{alert_id}/timeline", headers=self.analyst_headers
        )
        self.assertEqual(response.status_code, 200)
        items = response.json()["items"]
        kinds = [item["kind"] for item in items]
        self.assertIn("detection", kinds)
        self.assertIn("alert_status", kinds)
        self.assertIn("comment", kinds)
        self.assertIn("incident_status", kinds)
        # Timestamps must be non-decreasing (chronological order).
        timestamps = [item["timestamp"] for item in items]
        self.assertEqual(timestamps, sorted(timestamps))
        # The analyst email is resolved onto the events they caused.
        investigating = next(i for i in items if i.get("detail") == "Triaging")
        self.assertEqual(investigating["actor_email"], "analyst@example.org")
        self.assertIsNotNone(history_id)

    def test_timeline_missing_alert_returns_404(self):
        self.assertEqual(
            self.client.get("/api/v1/alerts/4242/timeline", headers=self.analyst_headers).status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main()
