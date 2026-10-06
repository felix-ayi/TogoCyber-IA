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


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "hardening.sqlite3"
        self.test_settings = replace(
            settings,
            database_path=self.database_path,
            auth_secret_key="test-auth-secret-key-with-32-bytes-minimum",
            bootstrap_admin_email="",
            bootstrap_admin_password="",
            rate_limit_per_minute=0,
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

        self.analyst = auth_repository.create_user(
            "analyst@example.org", auth_service._password_hash("a-long-analyst-passphrase"), "Analyst"
        )
        self.analyst_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(self.analyst)['access_token']}"
        }

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def test_health_reports_real_dependency_state(self):
        # A HIGH detection enqueues one not_configured notification.
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=90, severity="HIGH"
        )
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        checks = response.json()["checks"]
        self.assertEqual(checks["database"], "ok")
        self.assertEqual(checks["pending_notifications"], 1)
        self.assertEqual(checks["rate_limit_per_minute"], 0)
        # With no integration env vars set in tests, nothing is configured — reported honestly.
        self.assertEqual(checks["integrations_configured"], 0)
        self.assertEqual(checks["integrations_total"], response.json()["checks"]["integrations_total"])
        self.assertGreater(checks["integrations_total"], 0)

    def test_alerts_offset_pagination_is_consistent_and_disjoint(self):
        for score in (60, 65, 70, 75, 80):
            history_repository.record_event(
                "network", "malicious", 0.9, "high", risk_score=score, severity="MEDIUM"
            )
        first = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"limit": 2, "offset": 0}
        ).json()["items"]
        second = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"limit": 2, "offset": 2}
        ).json()["items"]
        tail = self.client.get(
            "/api/v1/alerts", headers=self.analyst_headers, params={"limit": 2, "offset": 4}
        ).json()["items"]
        self.assertEqual([a["id"] for a in first], [5, 4])
        self.assertEqual([a["id"] for a in second], [3, 2])
        self.assertEqual([a["id"] for a in tail], [1])
        ids = [a["id"] for a in (*first, *second, *tail)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_offset_bounds_are_validated(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/alerts", headers=self.analyst_headers, params={"offset": -1}
            ).status_code,
            422,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/alerts", headers=self.analyst_headers, params={"offset": 10001}
            ).status_code,
            422,
        )


if __name__ == "__main__":
    unittest.main()
