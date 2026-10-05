import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app.core.config import settings
from backend.app.repositories import history_repository


class HistoryRepositoryTests(unittest.TestCase):
    def test_only_result_metadata_is_persisted_and_expired_rows_are_purged(self):
        with tempfile.TemporaryDirectory() as directory:
            test_settings = replace(settings, database_path=Path(directory) / "history.sqlite3")
            with patch.object(history_repository, "settings", test_settings):
                history_repository.initialize_database()
                event_id = history_repository.record_event("phishing", "phishing", 0.91, "high")
                self.assertGreater(event_id, 0)
                rows = history_repository.list_events(10)
                self.assertEqual(rows[0]["prediction"], "phishing")
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


if __name__ == "__main__":
    unittest.main()