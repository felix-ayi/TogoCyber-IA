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
    correlation_repository,
    history_repository,
)
from backend.app.services import auth_service


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "correlation.sqlite3"
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
            patch.object(correlation_repository, "settings", self.test_settings),
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

    def _raise_alert(self, severity="HIGH", module="network"):
        return history_repository.record_event(
            module,
            "phishing" if module == "phishing" else "malicious",
            0.9,
            "high",
            risk_score=80,
            severity=severity,
        )

    def _create_rule(self, **overrides):
        body = {
            "name": "Rafale réseau",
            "module": "any",
            "min_severity": "MEDIUM",
            "threshold": 2,
            "window_minutes": 60,
        }
        body.update(overrides)
        return self.client.post("/api/v1/correlation/rules", headers=self.analyst_headers, json=body)

    def test_routes_are_restricted_to_soc_roles(self):
        self.assertEqual(
            self.client.get("/api/v1/correlation/rules", headers=self.user_headers).status_code, 403
        )
        self.assertEqual(self.client.get("/api/v1/correlation/rules").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/correlation/rules", headers=self.analyst_headers).status_code, 200
        )

    def test_create_rule_validates_and_records_audit(self):
        created = self._create_rule()
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["name"], "Rafale réseau")
        self.assertEqual(created.json()["created_by"], self.analyst["id"])
        self.assertTrue(created.json()["is_active"])

        # Schema rejects an unknown module and an out-of-range threshold.
        self.assertEqual(self._create_rule(module="satellite").status_code, 422)
        self.assertEqual(self._create_rule(threshold=1).status_code, 422)
        self.assertEqual(self._create_rule(window_minutes=0).status_code, 422)

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("rule.created", actions)

    def test_update_and_delete_rule_record_audit(self):
        rule_id = self._create_rule().json()["id"]
        updated = self.client.patch(
            f"/api/v1/correlation/rules/{rule_id}",
            headers=self.analyst_headers,
            json={"threshold": 5, "is_active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["threshold"], 5)
        self.assertFalse(updated.json()["is_active"])

        # Deactivating the rule keeps it out of a correlation run.
        self.assertEqual(self.client.post(
            "/api/v1/correlation/run", headers=self.analyst_headers
        ).json()["rules_evaluated"], 0)

        deleted = self.client.delete(
            f"/api/v1/correlation/rules/{rule_id}", headers=self.analyst_headers
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.get(
                f"/api/v1/correlation/rules/{rule_id}", headers=self.analyst_headers
            ).status_code,
            404,
        )
        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("rule.updated", actions)
        self.assertIn("rule.deleted", actions)

    def test_correlation_creates_finding_from_real_alerts_only(self):
        rule_id = self._create_rule(threshold=2, module="network", min_severity="HIGH").json()["id"]

        # With no alerts yet, nothing is produced.
        first = self.client.post("/api/v1/correlation/run", headers=self.analyst_headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["rules_evaluated"], 1)
        self.assertEqual(first.json()["findings_created"], [])

        # One matching alert is below the threshold; a non-matching module is ignored.
        self._raise_alert(severity="HIGH", module="network")
        self._raise_alert(severity="HIGH", module="phishing")
        still_below = self.client.post("/api/v1/correlation/run", headers=self.analyst_headers).json()
        self.assertEqual(still_below["findings_created"], [])

        # A second network HIGH alert crosses the threshold.
        self._raise_alert(severity="CRITICAL", module="network")
        created = self.client.post("/api/v1/correlation/run", headers=self.analyst_headers).json()
        self.assertEqual(len(created["findings_created"]), 1)

        finding_id = created["findings_created"][0]
        finding = self.client.get(
            f"/api/v1/correlation/findings/{finding_id}", headers=self.analyst_headers
        ).json()
        self.assertEqual(finding["rule_id"], rule_id)
        self.assertEqual(finding["alert_count"], 2)
        self.assertEqual(len(finding["alert_ids"]), 2)
        self.assertEqual(finding["status"], "OPEN")

        # Re-running is idempotent while the same OPEN finding covers the same alerts.
        again = self.client.post("/api/v1/correlation/run", headers=self.analyst_headers).json()
        self.assertEqual(again["findings_created"], [])

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("correlation.run", actions)

    def test_finding_status_transitions_and_listing(self):
        self._create_rule(threshold=2, module="network", min_severity="HIGH")
        self._raise_alert(severity="HIGH", module="network")
        self._raise_alert(severity="HIGH", module="network")
        finding_id = self.client.post(
            "/api/v1/correlation/run", headers=self.analyst_headers
        ).json()["findings_created"][0]

        # OPEN -> ACKNOWLEDGED -> CLOSED are allowed; reopening a CLOSED finding is not.
        acknowledged = self.client.patch(
            f"/api/v1/correlation/findings/{finding_id}",
            headers=self.analyst_headers,
            json={"status": "ACKNOWLEDGED"},
        )
        self.assertEqual(acknowledged.status_code, 200)
        self.assertEqual(acknowledged.json()["status"], "ACKNOWLEDGED")

        closed = self.client.patch(
            f"/api/v1/correlation/findings/{finding_id}",
            headers=self.analyst_headers,
            json={"status": "CLOSED"},
        )
        self.assertEqual(closed.status_code, 200)

        invalid = self.client.patch(
            f"/api/v1/correlation/findings/{finding_id}",
            headers=self.analyst_headers,
            json={"status": "OPEN"},
        )
        self.assertEqual(invalid.status_code, 409)

        listing = self.client.get(
            "/api/v1/correlation/findings",
            headers=self.analyst_headers,
            params={"status": "CLOSED"},
        )
        self.assertEqual(len(listing.json()["items"]), 1)
        empty = self.client.get(
            "/api/v1/correlation/findings", headers=self.analyst_headers, params={"status": "OPEN"}
        )
        self.assertEqual(empty.json()["items"], [])

    def test_missing_finding_returns_404(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/correlation/findings/4242", headers=self.analyst_headers
            ).status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main()
