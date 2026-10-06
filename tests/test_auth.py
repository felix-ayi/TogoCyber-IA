import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.repositories import audit_repository, auth_repository, history_repository
from backend.app.services import auth_service


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "auth.sqlite3"
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
            patch.object(auth_service, "settings", self.test_settings),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def test_registration_login_me_logout_and_revoked_token(self):
        registration = self.client.post(
            "/api/v1/auth/register",
            json={"email": "Analyst@example.org", "password": "correct-horse-battery"},
        )
        self.assertEqual(registration.status_code, 201)
        self.assertEqual(registration.json()["role"], "User")
        self.assertNotIn("password", registration.json())

        duplicate = self.client.post(
            "/api/v1/auth/register",
            json={"email": "analyst@example.org", "password": "another-secure-passphrase"},
        )
        self.assertEqual(duplicate.status_code, 409)

        login = self.client.post(
            "/api/v1/auth/login",
            json={"email": "ANALYST@example.org", "password": "correct-horse-battery"},
        )
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=headers).json()["role"], "User")

        self.assertEqual(self.client.post("/api/v1/auth/logout", headers=headers).status_code, 204)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=headers).status_code, 401)

    def test_analysis_and_history_require_login(self):
        self.assertEqual(self.client.get("/api/v1/history").status_code, 401)
        self.assertEqual(
            self.client.post("/api/v1/assistant/ask", json={"message": "Hello"}).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/phishing/analyze",
                json={"text": "Review this invoice"},
            ).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/v1/health").status_code, 200)

    def test_history_is_scoped_to_user_and_admin_endpoint_is_role_guarded(self):
        first = auth_repository.create_user("first@example.org", "hash", "User")
        second = auth_repository.create_user("second@example.org", "hash", "User")
        history_repository.record_event("phishing", "phishing", 0.9, "high", user_id=second["id"])

        token_response = auth_service._issue_token(first)
        headers = {"Authorization": f"Bearer {token_response['access_token']}"}
        response = self.client.get("/api/v1/history", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], [])
        self.assertEqual(self.client.get("/api/v1/auth/users", headers=headers).status_code, 403)

    def test_incidents_are_scoped_and_analysts_can_transition_with_audit_events(self):
        owner = auth_repository.create_user("owner@example.org", "hash", "User")
        other_user = auth_repository.create_user("other@example.org", "hash", "User")
        analyst = auth_repository.create_user("analyst@example.org", "hash", "Analyst")
        history_repository.record_event(
            "phishing",
            "phishing",
            0.92,
            "high",
            user_id=owner["id"],
            risk_score=92,
            severity="CRITICAL",
        )

        owner_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(owner)['access_token']}"
        }
        other_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(other_user)['access_token']}"
        }
        analyst_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(analyst)['access_token']}"
        }

        owner_incidents = self.client.get("/api/v1/incidents", headers=owner_headers)
        self.assertEqual(owner_incidents.status_code, 200)
        self.assertEqual(len(owner_incidents.json()["items"]), 1)
        incident_id = owner_incidents.json()["items"][0]["id"]
        self.assertEqual(self.client.get("/api/v1/incidents", headers=other_headers).json()["items"], [])
        self.assertEqual(
            self.client.patch(
                f"/api/v1/incidents/{incident_id}",
                headers=owner_headers,
                json={"status": "ACKNOWLEDGED"},
            ).status_code,
            403,
        )

        invalid_transition = self.client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=analyst_headers,
            json={"status": "RESOLVED"},
        )
        self.assertEqual(invalid_transition.status_code, 409)
        acknowledged = self.client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=analyst_headers,
            json={"status": "ACKNOWLEDGED"},
        )
        self.assertEqual(acknowledged.status_code, 200)
        self.assertEqual(acknowledged.json()["status"], "ACKNOWLEDGED")
        repeated_transition = self.client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=analyst_headers,
            json={"status": "ACKNOWLEDGED"},
        )
        self.assertEqual(repeated_transition.status_code, 409)
        resolved = self.client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=analyst_headers,
            json={"status": "RESOLVED"},
        )
        self.assertEqual(resolved.status_code, 200)

        events = self.client.get(
            f"/api/v1/incidents/{incident_id}/events",
            headers=owner_headers,
        )
        self.assertEqual(events.status_code, 200)
        self.assertEqual(
            [event["new_status"] for event in events.json()["items"]],
            ["OPEN", "ACKNOWLEDGED", "RESOLVED"],
        )
        self.assertEqual(events.json()["items"][1]["actor_user_id"], analyst["id"])

    def test_admin_can_provision_analyst_but_public_user_cannot(self):
        admin = auth_repository.create_user(
            "admin@example.org",
            auth_service._password_hash("a-long-admin-passphrase"),
            "Admin",
        )
        admin_token = auth_service._issue_token(admin)["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        response = self.client.post(
            "/api/v1/auth/users",
            headers=admin_headers,
            json={
                "email": "analyst@example.org",
                "password": "a-long-analyst-passphrase",
                "role": "Analyst",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["role"], "Analyst")

        users = self.client.get("/api/v1/auth/users", headers=admin_headers)
        self.assertEqual(users.status_code, 200)
        self.assertEqual([item["role"] for item in users.json()["items"]], ["Admin", "Analyst"])

    def test_authenticated_analysis_routes_return_risk_contract(self):
        self.client.post(
            "/api/v1/auth/register",
            json={"email": "analyst@example.org", "password": "correct-horse-battery"},
        )
        token = self.client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.org", "password": "correct-horse-battery"},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        phishing_result = {
            "status": "success",
            "module": "phishing",
            "prediction": "phishing",
            "phishing_probability": 0.92,
            "confidence": 0.92,
            "confidence_level": "high",
            "risk_score": 92,
            "severity": "CRITICAL",
            "classification": "phishing",
            "indicators": [{"name": "urgent", "contribution": 0.4, "direction": "raises_risk"}],
            "recommendations": ["Ne répondez pas."],
            "explanation": [{"term": "urgent", "contribution": 0.4}],
            "explanation_truncated": False,
            "model": "logistic_regression",
            "model_version": "unversioned",
            "history_id": 1,
        }
        network_result = {
            "status": "success",
            "module": "network",
            "prediction": "malicious",
            "malicious_probability": 0.92,
            "confidence": 0.92,
            "confidence_level": "high",
            "risk_score": 92,
            "severity": "CRITICAL",
            "classification": "malicious",
            "indicators": [{"name": "dst_port", "contribution": 0.4, "direction": "raises_risk"}],
            "recommendations": ["Faites vérifier ce flux."],
            "features": {name: 0.0 for name in (
                "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets",
                "src_port", "dst_port", "protocol_number", "flow_rate",
            )},
            "explanation": [{"feature": "dst_port", "contribution": 0.4}],
            "model": "xgboost",
            "model_version": "unversioned",
            "history_id": 2,
        }
        with (
            patch("backend.app.api.v1.routes.phishing.phishing_analysis", return_value=phishing_result),
            patch("backend.app.api.v1.routes.network.network_analysis", return_value=network_result),
        ):
            phishing = self.client.post(
                "/api/v1/phishing/analyze",
                headers=headers,
                json={"text": "Check this message"},
            )
            network = self.client.post(
                "/api/v1/network/analyze",
                headers=headers,
                json={"features": network_result["features"]},
            )

        self.assertEqual(phishing.status_code, 200)
        self.assertEqual(phishing.json()["risk_score"], 92)
        self.assertEqual(network.status_code, 200)
        self.assertEqual(network.json()["severity"], "CRITICAL")

    def test_failed_login_is_rate_limited(self):
        for _ in range(auth_service.MAX_LOGIN_FAILURES):
            response = self.client.post(
                "/api/v1/auth/login",
                json={"email": "nobody@example.org", "password": "incorrect-password"},
            )
            self.assertEqual(response.status_code, 401)

        limited = self.client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.org", "password": "incorrect-password"},
        )
        self.assertEqual(limited.status_code, 429)

    def test_public_registration_cannot_assign_privileged_role(self):
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "email": "admin@example.org",
                "password": "correct-horse-battery",
                "role": "Admin",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_expired_and_tampered_tokens_are_rejected(self):
        user = auth_repository.create_user(
            "token@example.org",
            auth_service._password_hash("a-long-secure-passphrase"),
            "User",
        )
        expired_token = auth_service._issue_token(user, now=100)["access_token"]
        with self.assertRaises(auth_service.AuthenticationError):
            auth_service.authenticate_token(expired_token, now=2_000)

        current_token = auth_service._issue_token(user)["access_token"]
        header_part, payload_part, signature_part = current_token.split(".")
        first = signature_part[0]
        tampered_signature = ("A" if first != "A" else "B") + signature_part[1:]
        tampered_token = f"{header_part}.{payload_part}.{tampered_signature}"
        with self.assertRaises(auth_service.AuthenticationError):
            auth_service.authenticate_token(tampered_token)

    def test_bootstrap_admin_is_created_once_without_password_reset(self):
        bootstrap_settings = replace(
            self.test_settings,
            bootstrap_admin_email="root@example.org",
            bootstrap_admin_password="first-bootstrap-passphrase",
        )
        with (
            patch.object(auth_service, "settings", bootstrap_settings),
            patch.object(auth_repository, "settings", bootstrap_settings),
        ):
            auth_service.initialize_bootstrap_admin()
            original = auth_repository.find_user_by_email("root@example.org")
            auth_service.settings = replace(
                bootstrap_settings,
                bootstrap_admin_password="different-bootstrap-passphrase",
            )
            auth_service.initialize_bootstrap_admin()
            after_restart = auth_repository.find_user_by_email("root@example.org")

        self.assertEqual(original["role"], "Admin")
        self.assertEqual(after_restart["password_hash"], original["password_hash"])

    def test_passwords_are_hashed_and_minimum_length_is_enforced(self):
        too_short = self.client.post(
            "/api/v1/auth/register",
            json={"email": "short@example.org", "password": "short"},
        )
        self.assertEqual(too_short.status_code, 422)
        created = self.client.post(
            "/api/v1/auth/register",
            json={"email": "private@example.org", "password": "correct-horse-battery"},
        )
        stored = auth_repository.find_user_by_email("private@example.org")
        self.assertEqual(created.status_code, 201)
        self.assertNotEqual(stored["password_hash"], "correct-horse-battery")
        self.assertTrue(stored["password_hash"].startswith("pbkdf2_sha256$"))

    def test_bootstrap_admin_with_eleven_char_password_can_login_and_reach_admin_routes(self):
        bootstrap_settings = replace(
            self.test_settings,
            bootstrap_admin_email="felix@cybertogo.ai.com",
            bootstrap_admin_password="@Azerty1234",
        )
        with (
            patch.object(auth_service, "settings", bootstrap_settings),
            patch.object(auth_repository, "settings", bootstrap_settings),
        ):
            auth_service.initialize_bootstrap_admin()

        login = self.client.post(
            "/api/v1/auth/login",
            json={"email": "felix@cybertogo.ai.com", "password": "@Azerty1234"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["user"]["role"], "Admin")
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/v1/auth/users", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/audit-events", headers=headers).status_code, 200)

        stored = auth_repository.find_user_by_email("felix@cybertogo.ai.com")
        self.assertNotEqual(stored["password_hash"], "@Azerty1234")
        self.assertTrue(stored["password_hash"].startswith("pbkdf2_sha256$"))

    def test_admin_can_manage_users_and_lockout_guards_are_enforced(self):
        admin = auth_repository.create_user(
            "admin@example.org",
            auth_service._password_hash("a-long-admin-passphrase"),
            "Admin",
        )
        admin_headers = {
            "Authorization": f"Bearer {auth_service._issue_token(admin)['access_token']}"
        }
        target = auth_repository.create_user("target@example.org", "hash", "User")

        listed = self.client.get("/api/v1/auth/users", headers=admin_headers)
        self.assertEqual(listed.status_code, 200)
        self.assertIn("last_login", listed.json()["items"][0])

        fetched = self.client.get(f"/api/v1/auth/users/{target['id']}", headers=admin_headers)
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["email"], "target@example.org")
        self.assertEqual(
            self.client.get("/api/v1/auth/users/9999", headers=admin_headers).status_code, 404
        )

        promoted = self.client.patch(
            f"/api/v1/auth/users/{target['id']}",
            headers=admin_headers,
            json={"role": "Analyst"},
        )
        self.assertEqual(promoted.status_code, 200)
        self.assertEqual(promoted.json()["role"], "Analyst")

        deactivated = self.client.patch(
            f"/api/v1/auth/users/{target['id']}",
            headers=admin_headers,
            json={"is_active": False},
        )
        self.assertEqual(deactivated.status_code, 200)
        self.assertFalse(deactivated.json()["is_active"])
        self.assertTrue(
            self.client.patch(
                f"/api/v1/auth/users/{target['id']}",
                headers=admin_headers,
                json={"is_active": True},
            ).json()["is_active"]
        )

        reset = self.client.post(
            f"/api/v1/auth/users/{target['id']}/password",
            headers=admin_headers,
            json={"password": "a-brand-new-passphrase"},
        )
        self.assertEqual(reset.status_code, 204)
        weak_reset = self.client.post(
            f"/api/v1/auth/users/{target['id']}/password",
            headers=admin_headers,
            json={"password": "short"},
        )
        self.assertEqual(weak_reset.status_code, 422)

        self.assertEqual(
            self.client.delete(f"/api/v1/auth/users/{admin['id']}", headers=admin_headers).status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/v1/auth/users/{admin['id']}",
                headers=admin_headers,
                json={"role": "User"},
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/v1/auth/users/{admin['id']}",
                headers=admin_headers,
                json={"is_active": False},
            ).status_code,
            409,
        )

        deleted = self.client.delete(
            f"/api/v1/auth/users/{target['id']}", headers=admin_headers
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertIsNone(auth_repository.get_user_by_id(target["id"]))

        actions = {event["action"] for event in audit_repository.list_events(limit=100)}
        self.assertIn("user.role_changed", actions)
        self.assertIn("user.deactivated", actions)
        self.assertIn("user.activated", actions)
        self.assertIn("user.password_reset", actions)
        self.assertIn("user.deleted", actions)

    def test_non_admin_cannot_access_user_management_routes(self):
        user = auth_repository.create_user("plain@example.org", "hash", "User")
        headers = {"Authorization": f"Bearer {auth_service._issue_token(user)['access_token']}"}
        self.assertEqual(self.client.get("/api/v1/auth/users", headers=headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/auth/users/{user['id']}", headers=headers).status_code, 403)
        self.assertEqual(
            self.client.patch(f"/api/v1/auth/users/{user['id']}", headers=headers, json={"role": "Admin"}).status_code,
            403,
        )
        self.assertEqual(self.client.delete(f"/api/v1/auth/users/{user['id']}", headers=headers).status_code, 403)


if __name__ == "__main__":
    unittest.main()
