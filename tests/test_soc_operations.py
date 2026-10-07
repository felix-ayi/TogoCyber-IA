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
    notification_repository,
    playbook_repository,
)
from backend.app.services import auth_service, integrations_service


class SocOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "soc_ops.sqlite3"
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
            patch.object(notification_repository, "settings", self.test_settings),
            patch.object(playbook_repository, "settings", self.test_settings),
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

    # --- Playbooks ---

    def _create_playbook(self, **overrides):
        body = {
            "name": "Réponse phishing",
            "module": "phishing",
            "min_severity": "HIGH",
            "description": "Procédure de réponse à une campagne de hameçonnage.",
            "steps": ["Isoler la boîte", "Bloquer l’expéditeur", "Avertir les utilisateurs"],
        }
        body.update(overrides)
        return self.client.post("/api/v1/playbooks", headers=self.analyst_headers, json=body)

    def test_playbook_routes_are_restricted_to_soc_roles(self):
        self.assertEqual(
            self.client.get("/api/v1/playbooks", headers=self.user_headers).status_code, 403
        )
        self.assertEqual(self.client.get("/api/v1/playbooks").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/playbooks", headers=self.analyst_headers).status_code, 200
        )

    def test_playbook_crud_and_audit(self):
        created = self._create_playbook()
        self.assertEqual(created.status_code, 201)
        playbook_id = created.json()["id"]
        # Steps are stored in order with 1-based positions.
        self.assertEqual(
            [step["position"] for step in created.json()["steps"]], [1, 2, 3]
        )
        self.assertEqual(created.json()["created_by"], self.analyst["id"])

        # Schema rejects an unknown module and blank/whitespace-only steps are dropped.
        self.assertEqual(self._create_playbook(module="radio").status_code, 422)
        trimmed = self._create_playbook(
            name="Nettoyage", module="network", steps=["  ", "Vérifier", ""]
        ).json()
        self.assertEqual([s["instruction"] for s in trimmed["steps"]], ["Vérifier"])

        updated = self.client.patch(
            f"/api/v1/playbooks/{playbook_id}",
            headers=self.analyst_headers,
            json={"min_severity": "CRITICAL", "steps": ["Étape unique"]},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["min_severity"], "CRITICAL")
        self.assertEqual(len(updated.json()["steps"]), 1)

        listing = self.client.get(
            "/api/v1/playbooks", headers=self.analyst_headers, params={"module": "phishing"}
        )
        self.assertEqual(len(listing.json()["items"]), 1)

        deleted = self.client.delete(
            f"/api/v1/playbooks/{playbook_id}", headers=self.analyst_headers
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.get(
                f"/api/v1/playbooks/{playbook_id}", headers=self.analyst_headers
            ).status_code,
            404,
        )
        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("playbook.created", actions)
        self.assertIn("playbook.updated", actions)
        self.assertIn("playbook.deleted", actions)

    # --- Notifications ---

    def test_notifications_are_queued_from_real_high_alerts_only(self):
        # A LOW detection raises no alert and no notification.
        history_repository.record_event(
            "network", "benign", 0.9, "low", risk_score=5, severity="LOW"
        )
        # A MEDIUM alert is queued for triage but not for notification.
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=55, severity="MEDIUM"
        )
        empty = self.client.get("/api/v1/notifications", headers=self.analyst_headers).json()
        self.assertEqual(empty["items"], [])

        # A HIGH alert enqueues one notification, marked not_configured (no channel set).
        history_repository.record_event(
            "phishing", "phishing", 0.9, "high", risk_score=88, severity="HIGH"
        )
        items = self.client.get("/api/v1/notifications", headers=self.analyst_headers).json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "HIGH")
        self.assertEqual(items[0]["delivery_status"], "not_configured")

        counts = self.client.get("/api/v1/notifications/counts", headers=self.analyst_headers).json()
        self.assertEqual(counts["counts"]["total"], 1)
        self.assertEqual(counts["counts"]["not_configured"], 1)
        self.assertEqual(counts["counts"]["sent"], 0)

        self.assertEqual(
            self.client.get("/api/v1/notifications", headers=self.user_headers).status_code, 403
        )

    # --- Integrations ---

    def test_integrations_report_not_configured_honestly(self):
        self.assertEqual(
            self.client.get("/api/v1/integrations", headers=self.user_headers).status_code, 403
        )
        data = self.client.get("/api/v1/integrations", headers=self.analyst_headers).json()
        self.assertEqual(data["total"], len(data["adapters"]))
        # With no integration env vars set in tests, nothing is configured.
        self.assertEqual(data["configured"], 0)
        self.assertEqual(data["not_configured"], data["total"])
        keys = {adapter["key"] for adapter in data["adapters"]}
        self.assertTrue({"zeek", "suricata", "virustotal", "abuseipdb", "siem"} <= keys)
        self.assertTrue(
            all(adapter["status"] == "not_configured" for adapter in data["adapters"])
        )

    def test_integration_marks_configured_when_env_present(self):
        with patch.dict(
            "os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}, clear=False
        ):
            data = self.client.get("/api/v1/integrations", headers=self.analyst_headers).json()
        virustotal = next(a for a in data["adapters"] if a["key"] == "virustotal")
        self.assertEqual(virustotal["status"], "configured")
        self.assertEqual(data["configured"], 1)

    def test_smtp_integration_requires_a_complete_delivery_configuration(self):
        with patch.dict(
            "os.environ", {"NOTIFICATION_SMTP_HOST": "mail.example.org"}, clear=True
        ):
            smtp = next(
                item
                for item in integrations_service.integration_status()
                if item["key"] == "smtp"
            )
        self.assertEqual(smtp["status"], "not_configured")

        with patch.dict(
            "os.environ",
            {
                "NOTIFICATION_SMTP_HOST": "mail.example.org",
                "NOTIFICATION_SMTP_FROM": "alerts@example.org",
                "NOTIFICATION_SMTP_TO": "soc@example.org",
            },
            clear=True,
        ):
            smtp = next(
                item
                for item in integrations_service.integration_status()
                if item["key"] == "smtp"
            )
        self.assertEqual(smtp["status"], "configured")


if __name__ == "__main__":
    unittest.main()
