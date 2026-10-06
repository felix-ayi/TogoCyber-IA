import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import requests
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.repositories import (
    alert_repository,
    audit_repository,
    auth_repository,
    history_repository,
    notification_repository,
)
from backend.app.services import auth_service, notification_service


class _FakeResponse:
    def __init__(self, ok=True):
        self._ok = ok

    def raise_for_status(self):
        if not self._ok:
            raise requests.HTTPError("boom")


class NotificationDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "notif.sqlite3"
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
        # One HIGH alert -> one queued notification.
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=88, severity="HIGH"
        )

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def test_dispatch_is_soc_gated(self):
        self.assertEqual(
            self.client.post("/api/v1/notifications/dispatch", headers=self.user_headers).status_code,
            403,
        )

    def test_no_channel_configured_sends_nothing(self):
        # Ensure no channel env is present.
        env = {
            "NOTIFICATION_WEBHOOK_URL": "",
            "NOTIFICATION_SLACK_WEBHOOK": "",
            "NOTIFICATION_SMTP_HOST": "",
        }
        with patch.dict("os.environ", env, clear=False):
            result = self.client.post(
                "/api/v1/notifications/dispatch", headers=self.analyst_headers
            ).json()
        self.assertIsNone(result["configured_channel"])
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["failed"], 0)
        # The row is untouched and still awaiting a channel.
        counts = notification_repository.counts()
        self.assertEqual(counts["not_configured"], 1)
        self.assertEqual(counts["sent"], 0)

    def test_webhook_delivery_marks_sent(self):
        with (
            patch.dict("os.environ", {"NOTIFICATION_WEBHOOK_URL": "https://hooks.example/xyz"}, clear=False),
            patch.object(notification_service.requests, "post", return_value=_FakeResponse(ok=True)) as mock_post,
        ):
            result = self.client.post(
                "/api/v1/notifications/dispatch", headers=self.analyst_headers
            ).json()
        self.assertEqual(result["configured_channel"], "webhook")
        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["failed"], 0)
        mock_post.assert_called_once()
        counts = notification_repository.counts()
        self.assertEqual(counts["sent"], 1)
        self.assertEqual(counts["not_configured"], 0)

    def test_webhook_failure_marks_failed_not_sent(self):
        with (
            patch.dict("os.environ", {"NOTIFICATION_WEBHOOK_URL": "https://hooks.example/xyz"}, clear=False),
            patch.object(
                notification_service.requests, "post", return_value=_FakeResponse(ok=False)
            ),
        ):
            result = self.client.post(
                "/api/v1/notifications/dispatch", headers=self.analyst_headers
            ).json()
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["failed"], 1)
        counts = notification_repository.counts()
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["sent"], 0)

    def test_invalid_webhook_url_is_not_used(self):
        # A non-HTTP(S) URL must never be dialed; falls back to "no channel".
        with patch.dict("os.environ", {"NOTIFICATION_WEBHOOK_URL": "file:///etc/passwd"}, clear=False):
            channel, _ = notification_service.configured_channel()
        self.assertIsNone(channel)


if __name__ == "__main__":
    unittest.main()
