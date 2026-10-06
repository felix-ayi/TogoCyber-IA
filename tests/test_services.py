import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app.core.config import settings
from backend.app.repositories import auth_repository, history_repository


class HistoryRepositoryTests(unittest.TestCase):
    def test_existing_history_database_migrates_without_losing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "history.sqlite3"
            connection = sqlite3.connect(database_path)
            try:
                connection.executescript(
                    """
                    CREATE TABLE analysis_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        module TEXT NOT NULL,
                        prediction TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        confidence_level TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    );
                    INSERT INTO analysis_history (module, prediction, confidence, confidence_level)
                    VALUES ('network', 'benign', 0.9, 'high');
                    """
                )
                connection.commit()
            finally:
                connection.close()

            test_settings = replace(settings, database_path=database_path)
            with patch.object(history_repository, "settings", test_settings):
                history_repository.initialize_database()
                rows = history_repository.list_events()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["prediction"], "benign")
                migrated = sqlite3.connect(database_path)
                try:
                    columns = {
                        row[1]
                        for row in migrated.execute("PRAGMA table_info(analysis_history)")
                    }
                finally:
                    migrated.close()
                self.assertIn("user_id", columns)
                self.assertIn("risk_score", columns)
                self.assertIn("severity", columns)
                self.assertIn("model_version", columns)

    def test_only_result_metadata_is_persisted_and_expired_rows_are_purged(self):
        with tempfile.TemporaryDirectory() as directory:
            test_settings = replace(settings, database_path=Path(directory) / "history.sqlite3")
            with (
                patch.object(history_repository, "settings", test_settings),
                patch.object(auth_repository, "settings", test_settings),
            ):
                history_repository.initialize_database()
                event_id = history_repository.record_event(
                    "phishing",
                    "phishing",
                    0.91,
                    "high",
                    risk_score=91,
                    severity="CRITICAL",
                    model_name="logistic_regression",
                    model_version="unversioned",
                )
                self.assertGreater(event_id, 0)
                rows = history_repository.list_events(10)
                self.assertEqual(rows[0]["prediction"], "phishing")
                self.assertEqual(rows[0]["risk_score"], 91)
                self.assertEqual(rows[0]["severity"], "CRITICAL")
                self.assertEqual(rows[0]["model_name"], "logistic_regression")
                connection = sqlite3.connect(test_settings.database_path)
                try:
                    with connection:
                        columns = {row[1] for row in connection.execute("PRAGMA table_info(analysis_history)")}
                        self.assertNotIn("text", columns)
                        self.assertNotIn("features", columns)
                        old_timestamp = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                        connection.execute(
                            "INSERT INTO analysis_history(module,prediction,confidence,confidence_level,created_at) VALUES(?,?,?,?,?)",
                            ("network", "benign", 0.7, "medium", old_timestamp),
                        )
                finally:
                    connection.close()
                history_repository.purge_expired()
                self.assertEqual(len(history_repository.list_events()), 1)

    def test_high_risk_events_create_incidents_without_storing_submitted_content(self):
        with tempfile.TemporaryDirectory() as directory:
            test_settings = replace(settings, database_path=Path(directory) / "history.sqlite3")
            with (
                patch.object(history_repository, "settings", test_settings),
                patch.object(auth_repository, "settings", test_settings),
            ):
                history_repository.initialize_database()
                owner = auth_repository.create_user("owner@example.org", "hash", "User")
                high_risk_history_id = history_repository.record_event(
                    "phishing",
                    "legitimate",
                    0.7,
                    "medium",
                    user_id=owner["id"],
                    risk_score=82,
                    severity="CRITICAL",
                )
                incident_id = history_repository.get_incident_id_for_history(high_risk_history_id)
                self.assertIsNotNone(incident_id)
                incidents = history_repository.list_incidents(user_id=owner["id"])
                self.assertEqual(len(incidents), 1)
                self.assertEqual(incidents[0]["status"], "OPEN")
                self.assertEqual(incidents[0]["risk_score"], 82)
                events = history_repository.get_incident_status_events(incident_id)
                self.assertEqual(events[0]["previous_status"], None)
                self.assertEqual(events[0]["new_status"], "OPEN")

                moderate_history_id = history_repository.record_event(
                    "network",
                    "benign",
                    0.6,
                    "medium",
                    user_id=owner["id"],
                    risk_score=60,
                    severity="MEDIUM",
                )
                self.assertIsNone(history_repository.get_incident_id_for_history(moderate_history_id))
                connection = sqlite3.connect(test_settings.database_path)
                try:
                    columns = {
                        row[1]
                        for row in connection.execute("PRAGMA table_info(incidents)")
                    }
                    self.assertNotIn("text", columns)
                    self.assertNotIn("features", columns)
                finally:
                    connection.close()


if __name__ == "__main__":
    unittest.main()