import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app.core.config import settings
from backend.app.repositories import (
    alert_repository,
    audit_repository,
    auth_repository,
    correlation_repository,
    history_repository,
    notification_repository,
)
from backend.app.services import auth_service


def _old_timestamp() -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=31)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "retention.sqlite3"
        self.test_settings = replace(
            settings,
            database_path=self.database_path,
            retention_days=30,
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
            patch.object(notification_repository, "settings", self.test_settings),
            patch.object(auth_service, "settings", self.test_settings),
        ]
        for patcher in self.patches:
            patcher.start()
        history_repository.initialize_database()
        self.analyst = auth_repository.create_user(
            "analyst@example.org", auth_service._password_hash("a-long-analyst-passphrase"), "Analyst"
        )

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def _count(self, table: str) -> int:
        connection = sqlite3.connect(self.database_path)
        try:
            return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        finally:
            connection.close()

    def _backdate(self, table: str) -> None:
        connection = sqlite3.connect(self.database_path)
        try:
            with connection:
                connection.execute(f"UPDATE {table} SET created_at = ?", (_old_timestamp(),))
        finally:
            connection.close()

    def test_purge_removes_ephemeral_but_keeps_operational_records(self):
        # A HIGH detection creates an alert, a notification and an audit trail.
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=88, severity="HIGH"
        )
        audit_repository.record_event("ioc.created", "success", self.analyst["id"], "ioc", 1)

        # A rule plus two matching alerts produce one correlation finding.
        correlation_repository.create_rule(
            name="Rafale", module="network", min_severity="HIGH", threshold=2,
            window_minutes=1440, created_by=self.analyst["id"],
        )
        history_repository.record_event(
            "network", "malicious", 0.9, "high", risk_score=90, severity="HIGH"
        )
        correlation_repository.run_correlation()

        self.assertEqual(self._count("notifications"), 2)
        self.assertEqual(self._count("correlation_findings"), 1)
        self.assertGreaterEqual(self._count("alerts"), 2)

        # Age every ephemeral row and the alerts beyond the retention window.
        for table in ("analysis_history", "notifications", "correlation_findings", "alerts"):
            self._backdate(table)

        history_repository.purge_expired()

        # Ephemeral data older than RETENTION_DAYS is gone.
        self.assertEqual(self._count("analysis_history"), 0)
        self.assertEqual(self._count("notifications"), 0)
        self.assertEqual(self._count("correlation_findings"), 0)
        # The finding/alert link table cascaded with the finding.
        self.assertEqual(self._count("correlation_finding_alerts"), 0)

        # Operational records survive regardless of age: alerts and the immutable audit log.
        self.assertGreaterEqual(self._count("alerts"), 2)
        self.assertGreaterEqual(self._count("audit_events"), 1)


if __name__ == "__main__":
    unittest.main()
