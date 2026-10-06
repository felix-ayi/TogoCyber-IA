import unittest

from backend.app.core.config import _resolve_database_path


class DatabaseUrlResolutionTests(unittest.TestCase):
    def test_empty_url_falls_back_to_path(self):
        resolved = _resolve_database_path("", "database/togocyber.sqlite3")
        self.assertEqual(str(resolved).replace("\\", "/"), "database/togocyber.sqlite3")

    def test_sqlite_url_is_used(self):
        resolved = _resolve_database_path("sqlite:///var/lib/togo.db", "ignored.db")
        self.assertEqual(str(resolved).replace("\\", "/"), "var/lib/togo.db")

    def test_postgres_url_is_rejected_loudly(self):
        with self.assertRaises(ValueError) as context:
            _resolve_database_path("postgresql://user:pw@host/db", "ignored.db")
        self.assertIn("PostgreSQL", str(context.exception))

    def test_unknown_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            _resolve_database_path("mysql://user@host/db", "ignored.db")


if __name__ == "__main__":
    unittest.main()
