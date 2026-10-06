import csv
import io
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
    ioc_repository,
    notification_repository,
)
from backend.app.services import auth_service


def _parse_csv(content: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(content.decode("utf-8"))))


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "exports.sqlite3"
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
            patch.object(ioc_repository, "settings", self.test_settings),
            patch.object(notification_repository, "settings", self.test_settings),
            patch.object(auth_service, "settings", self.test_settings),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()
        history_repository.initialize_database()

        self.admin = auth_repository.create_user(
            "admin@example.org", auth_service._password_hash("a-long-admin-passphrase"), "Admin"
        )
        self.analyst = auth_repository.create_user(
            "analyst@example.org", auth_service._password_hash("a-long-analyst-passphrase"), "Analyst"
        )
        self.plain_user = auth_repository.create_user("user@example.org", "hash", "User")
        self.admin_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(self.admin)['access_token']}"
        }
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

    def test_soc_exports_require_authentication_and_soc_role(self):
        for resource in ("alerts", "incidents", "iocs"):
            self.assertEqual(self.client.get(f"/api/v1/exports/{resource}").status_code, 401)
            self.assertEqual(
                self.client.get(f"/api/v1/exports/{resource}", headers=self.user_headers).status_code,
                403,
            )
            self.assertEqual(
                self.client.get(
                    f"/api/v1/exports/{resource}", headers=self.analyst_headers
                ).status_code,
                200,
            )

    def test_audit_export_is_admin_only(self):
        self.assertEqual(self.client.get("/api/v1/exports/audit").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/exports/audit", headers=self.analyst_headers).status_code, 403
        )
        response = self.client.get("/api/v1/exports/audit", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/csv"))
        self.assertIn("attachment", response.headers["content-disposition"])

    def test_alerts_export_has_header_and_real_row(self):
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=72, severity="HIGH"
        )
        response = self.client.get("/api/v1/exports/alerts", headers=self.analyst_headers)
        rows = _parse_csv(response.content)
        self.assertEqual(
            rows[0],
            [
                "id", "history_id", "incident_id", "module", "title", "severity",
                "risk_score", "status", "assignee_user_id", "created_at", "updated_at",
            ],
        )
        self.assertEqual(len(rows), 2)
        data = dict(zip(rows[0], rows[1]))
        self.assertEqual(data["module"], "network")
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["risk_score"], "72")

    def test_export_neutralises_formula_injection(self):
        ioc_repository.create_ioc(
            ioc_type="domain",
            value="evil.example.org",
            severity="HIGH",
            confidence=80,
            source="=cmd|'/c calc'!A1",
            description="+1234",
        )
        response = self.client.get("/api/v1/exports/iocs", headers=self.analyst_headers)
        rows = _parse_csv(response.content)
        header = rows[0]
        data = dict(zip(header, rows[1]))
        # A leading formula character is prefixed with a single quote so the cell is inert.
        self.assertTrue(data["source"].startswith("'="))
        self.assertTrue(data["description"].startswith("'+"))

    def test_export_limit_bounds_are_enforced(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/exports/alerts", headers=self.analyst_headers, params={"limit": 0}
            ).status_code,
            422,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/exports/alerts", headers=self.analyst_headers, params={"limit": 101}
            ).status_code,
            422,
        )


if __name__ == "__main__":
    unittest.main()
