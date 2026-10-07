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
    investigation_repository,
)
from backend.app.services import auth_service

_SHA256 = "a" * 64


class IocTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "iocs.sqlite3"
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
            patch.object(investigation_repository, "settings", self.test_settings),
            patch.object(ioc_repository, "settings", self.test_settings),
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

    def _create(self, **overrides):
        body = {
            "type": "ip",
            "value": "10.0.0.1",
            "severity": "HIGH",
            "confidence": 80,
        }
        body.update(overrides)
        return self.client.post("/api/v1/iocs", headers=self.analyst_headers, json=body)

    def test_routes_are_restricted_to_soc_roles(self):
        self.assertEqual(self.client.get("/api/v1/iocs", headers=self.user_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/iocs").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/iocs", headers=self.analyst_headers).status_code, 200)

    def test_create_validates_value_by_type_and_records_audit(self):
        created = self._create()
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["value"], "10.0.0.1")
        self.assertEqual(created.json()["created_by"], self.analyst["id"])

        # Invalid IP is rejected.
        bad_ip = self._create(value="999.1.1.1")
        self.assertEqual(bad_ip.status_code, 422)
        # Invalid hash length is rejected; a valid SHA-256 is accepted and lowercased.
        self.assertEqual(self._create(type="hash", value="deadbeef").status_code, 422)
        good_hash = self._create(type="hash", value=_SHA256.upper())
        self.assertEqual(good_hash.status_code, 201)
        self.assertEqual(good_hash.json()["value"], _SHA256)
        # URL must carry a scheme.
        self.assertEqual(self._create(type="url", value="example.com/x").status_code, 422)

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("ioc.created", actions)

    def test_duplicate_indicator_is_rejected(self):
        self.assertEqual(self._create().status_code, 201)
        duplicate = self._create()
        self.assertEqual(duplicate.status_code, 409)

    def test_list_filters_and_counts(self):
        self._create(type="ip", value="10.0.0.1", severity="HIGH")
        self._create(type="domain", value="Malware.Example.COM", severity="CRITICAL")
        self._create(type="email", value="phish@example.org", severity="LOW")

        domains = self.client.get(
            "/api/v1/iocs", headers=self.analyst_headers, params={"type": "domain"}
        )
        self.assertEqual(len(domains.json()["items"]), 1)
        # Domain values are normalised to lowercase.
        self.assertEqual(domains.json()["items"][0]["value"], "malware.example.com")

        critical = self.client.get(
            "/api/v1/iocs", headers=self.analyst_headers, params={"severity": "CRITICAL"}
        )
        self.assertEqual(len(critical.json()["items"]), 1)

        counts = self.client.get("/api/v1/iocs/counts", headers=self.analyst_headers)
        self.assertEqual(counts.json()["counts"]["ACTIVE"], 3)

    def test_update_and_delete_record_audit(self):
        ioc_id = self._create().json()["id"]
        updated = self.client.patch(
            f"/api/v1/iocs/{ioc_id}",
            headers=self.analyst_headers,
            json={"status": "REVOKED", "confidence": 55},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "REVOKED")
        self.assertEqual(updated.json()["confidence"], 55)

        # type/value are immutable: sending them is rejected by the schema.
        immutable = self.client.patch(
            f"/api/v1/iocs/{ioc_id}", headers=self.analyst_headers, json={"value": "8.8.8.8"}
        )
        self.assertEqual(immutable.status_code, 422)

        deleted = self.client.delete(f"/api/v1/iocs/{ioc_id}", headers=self.analyst_headers)
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.get(f"/api/v1/iocs/{ioc_id}", headers=self.analyst_headers).status_code, 404
        )
        self.assertEqual(
            self.client.delete(f"/api/v1/iocs/{ioc_id}", headers=self.analyst_headers).status_code, 404
        )

        actions = {e["action"] for e in audit_repository.list_events(limit=100)}
        self.assertIn("ioc.updated", actions)
        self.assertIn("ioc.deleted", actions)

    def test_tags_lifecycle(self):
        ioc_id = self._create().json()["id"]
        added = self.client.post(
            f"/api/v1/iocs/{ioc_id}/tags", headers=self.analyst_headers, json={"tag": " Botnet "}
        )
        self.assertEqual(added.status_code, 200)
        self.assertEqual(added.json()["tags"], ["botnet"])
        removed = self.client.delete(
            f"/api/v1/iocs/{ioc_id}/tags/botnet", headers=self.analyst_headers
        )
        self.assertEqual(removed.json()["tags"], [])
        actions = {event["action"] for event in audit_repository.list_events(limit=100)}
        self.assertTrue({"ioc.tag_added", "ioc.tag_removed"} <= actions)

    def test_lookup_returns_active_matches_only_and_reports_no_external_sources(self):
        self._create(type="ip", value="10.0.0.1", severity="HIGH")
        revoked = self._create(type="ip", value="10.0.0.2", severity="MEDIUM")
        self.client.patch(
            f"/api/v1/iocs/{revoked.json()['id']}",
            headers=self.analyst_headers,
            json={"status": "REVOKED"},
        )

        hit = self.client.get(
            "/api/v1/iocs/lookup", headers=self.analyst_headers, params={"value": "10.0.0.1"}
        )
        self.assertEqual(hit.status_code, 200)
        self.assertEqual(len(hit.json()["matches"]), 1)
        self.assertEqual(hit.json()["external_sources"], [])

        miss = self.client.get(
            "/api/v1/iocs/lookup", headers=self.analyst_headers, params={"value": "10.0.0.2"}
        )
        self.assertEqual(miss.json()["matches"], [])


if __name__ == "__main__":
    unittest.main()
