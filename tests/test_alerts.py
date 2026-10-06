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
)
from backend.app.services import auth_service


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "alerts.sqlite3"
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

    def _raise_detection(self, severity="HIGH", risk_score=80, module="phishing", user_id=None):
        return history_repository.record_event(
            module,
            "phishing" if module == "phishing" else "malicious",
            0.9,
            "high",
            user_id=user_id,
            risk_score=risk_score,
            severity=severity,
        )

    def test_detections_raise_alerts_and_link_incidents(self):
        # HIGH detection with an owner creates both an incident and a linked alert.
        history_id = self._raise_detection(severity="HIGH", risk_score=88, user_id=self.plain_user["id"])
        incident_id = history_repository.get_incident_id_for_history(history_id)
        self.assertIsNotNone(incident_id)

        alerts = alert_repository.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["status"], "NEW")
        self.assertEqual(alerts[0]["incident_id"], incident_id)
        self.assertEqual(alerts[0]["history_id"], history_id)
        self.assertTrue(alerts[0]["title"])

        # MEDIUM detection creates an alert but no incident.
        self._raise_detection(severity="MEDIUM", risk_score=55)
        alerts = alert_repository.list_alerts()
        self.assertEqual(len(alerts), 2)
        medium = next(a for a in alerts if a["severity"] == "MEDIUM")
        self.assertIsNone(medium["incident_id"])

        # LOW detection creates no alert.
        self._raise_detection(severity="LOW", risk_score=10)
        self.assertEqual(len(alert_repository.list_alerts()), 2)

    def test_alert_routes_are_restricted_to_soc_roles(self):
        self._raise_detection()
        self.assertEqual(self.client.get("/api/v1/alerts", headers=self.user_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/alerts", headers=self.analyst_headers).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/alerts").status_code, 401)

    def test_status_transitions_timeline_and_audit(self):
        self._raise_detection()
        alert_id = alert_repository.list_alerts()[0]["id"]

        # Invalid: NEW -> RESOLVED is not allowed.
        invalid = self.client.patch(
            f"/api/v1/alerts/{alert_id}", headers=self.analyst_headers, json={"status": "RESOLVED"}
        )
        self.assertEqual(invalid.status_code, 409)

        investigating = self.client.patch(
            f"/api/v1/alerts/{alert_id}",
            headers=self.analyst_headers,
            json={"status": "INVESTIGATING", "note": "Triaging now"},
        )
        self.assertEqual(investigating.status_code, 200)
        self.assertEqual(investigating.json()["status"], "INVESTIGATING")

        confirmed = self.client.patch(
            f"/api/v1/alerts/{alert_id}", headers=self.analyst_headers, json={"status": "CONFIRMED"}
        )
        self.assertEqual(confirmed.status_code, 200)

        events = self.client.get(f"/api/v1/alerts/{alert_id}/events", headers=self.analyst_headers)
        self.assertEqual(events.status_code, 200)
        self.assertEqual(
            [e["new_status"] for e in events.json()["items"]],
            ["NEW", "INVESTIGATING", "CONFIRMED"],
        )
        self.assertEqual(events.json()["items"][1]["note"], "Triaging now")
        self.assertEqual(events.json()["items"][1]["actor_user_id"], self.analyst["id"])

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("alert.status_changed", actions)

    def test_assign_validates_target_and_records_audit(self):
        self._raise_detection()
        alert_id = alert_repository.list_alerts()[0]["id"]

        assigned = self.client.post(
            f"/api/v1/alerts/{alert_id}/assign",
            headers=self.analyst_headers,
            json={"assignee_user_id": self.analyst["id"]},
        )
        self.assertEqual(assigned.status_code, 200)
        self.assertEqual(assigned.json()["assignee_user_id"], self.analyst["id"])

        bad_target = self.client.post(
            f"/api/v1/alerts/{alert_id}/assign",
            headers=self.analyst_headers,
            json={"assignee_user_id": 9999},
        )
        self.assertEqual(bad_target.status_code, 422)

        unassigned = self.client.post(
            f"/api/v1/alerts/{alert_id}/assign",
            headers=self.analyst_headers,
            json={"assignee_user_id": None},
        )
        self.assertEqual(unassigned.status_code, 200)
        self.assertIsNone(unassigned.json()["assignee_user_id"])

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("alert.assigned", actions)

    def test_comments_and_tags_lifecycle(self):
        self._raise_detection()
        alert_id = alert_repository.list_alerts()[0]["id"]

        created = self.client.post(
            f"/api/v1/alerts/{alert_id}/comments",
            headers=self.analyst_headers,
            json={"body": "  Checked the sender domain  "},
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["body"], "Checked the sender domain")
        self.assertEqual(created.json()["author_user_id"], self.analyst["id"])

        empty = self.client.post(
            f"/api/v1/alerts/{alert_id}/comments", headers=self.analyst_headers, json={"body": "   "}
        )
        self.assertEqual(empty.status_code, 422)

        comments = self.client.get(f"/api/v1/alerts/{alert_id}/comments", headers=self.analyst_headers)
        self.assertEqual(len(comments.json()["items"]), 1)

        tagged = self.client.post(
            f"/api/v1/alerts/{alert_id}/tags", headers=self.analyst_headers, json={"tag": "  Phishing "}
        )
        self.assertEqual(tagged.status_code, 200)
        self.assertEqual(tagged.json()["tags"], ["phishing"])

        # Duplicate tag is idempotent.
        self.client.post(
            f"/api/v1/alerts/{alert_id}/tags", headers=self.analyst_headers, json={"tag": "phishing"}
        )
        detail = self.client.get(f"/api/v1/alerts/{alert_id}", headers=self.analyst_headers)
        self.assertEqual(detail.json()["tags"], ["phishing"])

        removed = self.client.delete(
            f"/api/v1/alerts/{alert_id}/tags/phishing", headers=self.analyst_headers
        )
        self.assertEqual(removed.status_code, 200)
        self.assertEqual(removed.json()["tags"], [])

    def test_list_filters_and_counts(self):
        self._raise_detection(severity="HIGH", risk_score=88, user_id=self.plain_user["id"])
        self._raise_detection(severity="MEDIUM", risk_score=55, module="network")
        alert_id = alert_repository.list_alerts(severity="MEDIUM")[0]["id"]
        alert_repository.update_status(alert_id, "INVESTIGATING", self.analyst["id"])

        high_only = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"severity": "HIGH"}
        )
        self.assertEqual(len(high_only.json()["items"]), 1)

        investigating = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"status": "INVESTIGATING"}
        )
        self.assertEqual(len(investigating.json()["items"]), 1)

        counts = self.client.get("/api/v1/alerts/counts", headers=self.analyst_headers)
        self.assertEqual(counts.status_code, 200)
        self.assertEqual(counts.json()["counts"]["NEW"], 1)
        self.assertEqual(counts.json()["counts"]["INVESTIGATING"], 1)

        bad_status = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"status": "NOPE"}
        )
        self.assertEqual(bad_status.status_code, 422)

    def test_missing_alert_returns_404(self):
        self.assertEqual(
            self.client.get("/api/v1/alerts/4242", headers=self.analyst_headers).status_code, 404
        )
        self.assertEqual(
            self.client.patch(
                "/api/v1/alerts/4242", headers=self.analyst_headers, json={"status": "CLOSED"}
            ).status_code,
            404,
        )

    def test_soc_overview_reflects_real_alerts_and_incidents(self):
        # Empty state: every aggregate is zero, and the endpoint is SOC-gated.
        self.assertEqual(
            self.client.get("/api/v1/alerts/overview", headers=self.user_headers).status_code, 403
        )
        empty = self.client.get("/api/v1/alerts/overview", headers=self.analyst_headers)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json()["alerts"]["total"], 0)
        self.assertEqual(empty.json()["incidents"]["active"], 0)

        # A HIGH detection owned by a user creates one incident and one linked alert.
        self._raise_detection(severity="HIGH", risk_score=88, user_id=self.plain_user["id"])
        # A CRITICAL detection with no owner creates an alert but no incident.
        self._raise_detection(severity="CRITICAL", risk_score=97, module="network")
        # A MEDIUM detection adds a third alert.
        self._raise_detection(severity="MEDIUM", risk_score=55)

        overview = self.client.get("/api/v1/alerts/overview", headers=self.analyst_headers).json()
        alerts = overview["alerts"]
        self.assertEqual(alerts["total"], 3)
        self.assertEqual(alerts["open"], 3)
        self.assertEqual(alerts["unassigned_open"], 3)
        self.assertEqual(alerts["critical_open"], 1)
        self.assertEqual(alerts["by_severity"], {"MEDIUM": 1, "HIGH": 1, "CRITICAL": 1})
        self.assertEqual(alerts["by_status"]["NEW"], 3)

        incidents = overview["incidents"]
        self.assertEqual(incidents["total"], 1)
        self.assertEqual(incidents["active"], 1)
        self.assertEqual(incidents["by_status"]["OPEN"], 1)

        # Assigning one alert drops the unassigned count but leaves totals intact.
        alert_id = alert_repository.list_alerts(severity="CRITICAL")[0]["id"]
        alert_repository.assign(alert_id, self.analyst["id"], self.analyst["id"])
        after = self.client.get("/api/v1/alerts/overview", headers=self.analyst_headers).json()
        self.assertEqual(after["alerts"]["unassigned_open"], 2)
        self.assertEqual(after["alerts"]["open"], 3)


if __name__ == "__main__":
    unittest.main()
