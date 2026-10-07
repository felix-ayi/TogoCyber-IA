import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.core.auth import get_current_user
from backend.app.core.config import settings
from backend.app.main import app
from backend.app.repositories import event_repository, history_repository
from backend.app.services.event_ingestion_service import normalize_suricata_event


class SuricataNormalizationTests(unittest.TestCase):
    def test_suricata_alert_maps_to_normalized_event(self):
        raw_event = {
            "timestamp": "2026-10-06T09:00:00+00:00",
            "event_type": "alert",
            "src_ip": "198.51.100.12",
            "src_port": 49152,
            "dest_ip": "203.0.113.8",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 8123,
            "alert": {
                "signature_id": 2100498,
                "signature": "ET MALWARE Suspicious TLS Certificate",
                "category": "Potentially Bad Traffic",
                "severity": 1,
            },
        }

        event = normalize_suricata_event(raw_event)

        self.assertEqual(event.source, "suricata")
        self.assertEqual(event.source_type, "ids")
        self.assertEqual(event.event_type, "alert")
        self.assertEqual(str(event.src_ip), "198.51.100.12")
        self.assertEqual(str(event.dst_ip), "203.0.113.8")
        self.assertEqual(event.src_port, 49152)
        self.assertEqual(event.dst_port, 443)
        self.assertEqual(event.protocol, "TCP")
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.message, "ET MALWARE Suspicious TLS Certificate")
        self.assertEqual(event.metadata["signature_id"], 2100498)
        self.assertEqual(event.raw_event, raw_event)

    def test_identical_source_event_has_a_stable_event_id(self):
        raw_event = {
            "timestamp": "2026-10-06T09:00:00+00:00",
            "event_type": "flow",
            "proto": "UDP",
        }

        first = normalize_suricata_event(raw_event)
        second = normalize_suricata_event(raw_event)

        self.assertEqual(first.event_id, second.event_id)

    def test_event_timestamp_is_normalized_to_utc(self):
        event = normalize_suricata_event(
            {"timestamp": "2026-10-06T09:00:00+02:00", "event_type": "flow"}
        )

        self.assertEqual(event.timestamp.isoformat(), "2026-10-06T07:00:00+00:00")

    def test_unknown_suricata_severity_is_not_promoted_to_low(self):
        event = normalize_suricata_event(
            {
                "timestamp": "2026-10-06T09:00:00+00:00",
                "event_type": "alert",
                "alert": {"severity": 99},
            }
        )

        self.assertEqual(event.severity, "INFO")

    def test_invalid_event_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_suricata_event({"event_type": "alert", "src_ip": "not-an-ip"})

    def test_raw_event_larger_than_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "normalized event contract"):
            normalize_suricata_event(
                {
                    "timestamp": "2026-10-06T09:00:00+00:00",
                    "event_type": "alert",
                    "unmapped_source_data": "x" * (64 * 1024),
                }
            )


class SuricataIngestionApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "events.sqlite3"
        self.test_settings = replace(
            settings,
            database_path=self.database_path,
            auth_secret_key="test-auth-secret-key-with-32-bytes-minimum",
            bootstrap_admin_email="",
            bootstrap_admin_password="",
        )
        self.patches = [
            patch.object(history_repository, "settings", self.test_settings),
            patch.object(event_repository, "settings", self.test_settings),
        ]
        for patcher in self.patches:
            patcher.start()
        app.dependency_overrides[get_current_user] = lambda: {"id": 7, "role": "Analyst"}
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        app.dependency_overrides.pop(get_current_user, None)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    @staticmethod
    def _raw_event():
        return {
            "timestamp": "2026-10-06T09:00:00+00:00",
            "event_type": "alert",
            "src_ip": "198.51.100.12",
            "dest_ip": "203.0.113.8",
            "proto": "TCP",
            "alert": {"signature": "Suspicious TLS", "severity": 1},
        }

    def test_ingest_is_deduplicated_and_queryable_by_soc(self):
        payload = {"event": self._raw_event()}
        first = self.client.post("/api/v1/events/ingest/suricata", json=payload)
        duplicate = self.client.post("/api/v1/events/ingest/suricata", json=payload)

        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["inserted"])
        self.assertFalse(duplicate.json()["inserted"])
        self.assertEqual(first.json()["event"]["severity"], "CRITICAL")

        listed = self.client.get(
            "/api/v1/events", params={"source_type": "ids", "severity": "CRITICAL"}
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["items"]), 1)
        self.assertEqual(listed.json()["items"][0]["raw_event"], payload["event"])

    def test_invalid_event_and_non_soc_role_are_rejected(self):
        invalid = self.client.post(
            "/api/v1/events/ingest/suricata", json={"event": {"event_type": "alert"}}
        )
        self.assertEqual(invalid.status_code, 422)

        app.dependency_overrides[get_current_user] = lambda: {"id": 8, "role": "User"}
        forbidden = self.client.get("/api/v1/events")
        self.assertEqual(forbidden.status_code, 403)

    def test_ingestion_purges_expired_events_using_ingestion_time(self):
        old_event = normalize_suricata_event(self._raw_event())
        event_repository.ingest_event(old_event)
        with event_repository._connection() as connection:
            connection.execute(
                "UPDATE events SET ingested_at = '2000-01-01T00:00:00.000Z' WHERE event_id = ?",
                (old_event.event_id,),
            )

        new_raw_event = self._raw_event() | {"flow_id": 42}
        new_event = normalize_suricata_event(new_raw_event)
        event_repository.ingest_event(new_event)

        self.assertEqual(
            [event.event_id for event in event_repository.list_events()],
            [new_event.event_id],
        )


if __name__ == "__main__":
    unittest.main()