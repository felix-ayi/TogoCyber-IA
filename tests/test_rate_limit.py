import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core import rate_limit
from backend.app.core.rate_limit import RateLimitMiddleware, SlidingWindowRateLimiter


class SlidingWindowRateLimiterTests(unittest.TestCase):
    @staticmethod
    def _request(peer: str, forwarded: str | None = None):
        headers = {} if forwarded is None else {"x-forwarded-for": forwarded}
        return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))

    def test_disabled_limiter_always_allows(self):
        limiter = SlidingWindowRateLimiter(0)
        for _ in range(100):
            allowed, retry_after = limiter.allow("client", now=0.0)
            self.assertTrue(allowed)
            self.assertEqual(retry_after, 0)

    def test_blocks_once_window_is_exhausted_and_recovers(self):
        limiter = SlidingWindowRateLimiter(3, window_seconds=60)
        base = 1_000.0
        self.assertTrue(limiter.allow("client", now=base)[0])
        self.assertTrue(limiter.allow("client", now=base + 1)[0])
        self.assertTrue(limiter.allow("client", now=base + 2)[0])
        allowed, retry_after = limiter.allow("client", now=base + 3)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)
        # A different client has its own independent budget.
        self.assertTrue(limiter.allow("other", now=base + 3)[0])
        # Once the oldest hit falls out of the 60s window the client is allowed again.
        self.assertTrue(limiter.allow("client", now=base + 61)[0])

    def test_sweep_drops_expired_buckets(self):
        limiter = SlidingWindowRateLimiter(2, window_seconds=10)
        limiter.allow("gone", now=0.0)
        # Force a sweep well past the window so the stale bucket is pruned.
        limiter.allow("kept", now=100.0)
        self.assertNotIn("gone", limiter._hits)

    def test_untrusted_forwarded_header_cannot_change_client_key(self):
        test_settings = replace(rate_limit.settings, trusted_proxy_cidrs=())
        with patch.object(rate_limit, "settings", test_settings):
            direct = rate_limit.client_key(self._request("198.51.100.10"))
            spoofed = rate_limit.client_key(
                self._request("198.51.100.10", "203.0.113.99")
            )
        self.assertEqual(spoofed, direct)

    def test_trusted_proxy_chain_resolves_first_untrusted_address(self):
        test_settings = replace(rate_limit.settings, trusted_proxy_cidrs=("10.0.0.0/8",))
        with patch.object(rate_limit, "settings", test_settings):
            forwarded = rate_limit.client_key(
                self._request("10.0.0.2", "203.0.113.99, 198.51.100.20, 10.0.0.3")
            )
            direct = rate_limit.client_key(self._request("198.51.100.20"))
        self.assertEqual(forwarded, direct)

    def test_trusted_proxy_accepts_x_real_ip_when_forwarded_for_is_absent(self):
        test_settings = replace(rate_limit.settings, trusted_proxy_cidrs=("10.0.0.0/8",))
        request = SimpleNamespace(
            headers={"x-real-ip": "203.0.113.77"},
            client=SimpleNamespace(host="10.0.0.2"),
        )
        with patch.object(rate_limit, "settings", test_settings):
            forwarded = rate_limit.client_key(request)
            direct = rate_limit.client_key(self._request("203.0.113.77"))
        self.assertEqual(forwarded, direct)


class RateLimitMiddlewareTests(unittest.TestCase):
    def _build_app(self, max_requests: int) -> FastAPI:
        app = FastAPI()
        app.add_middleware(
            RateLimitMiddleware,
            limiter=SlidingWindowRateLimiter(max_requests, window_seconds=60),
        )

        @app.get("/api/v1/thing")
        def thing():
            return {"ok": True}

        @app.get("/api/v1/health")
        def health():
            return {"status": "healthy"}

        return app

    def test_returns_429_with_retry_after_when_enabled(self):
        client = TestClient(self._build_app(2))
        self.assertEqual(client.get("/api/v1/thing").status_code, 200)
        self.assertEqual(client.get("/api/v1/thing").status_code, 200)
        limited = client.get("/api/v1/thing")
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Retry-After", limited.headers)

    def test_health_is_exempt_from_throttling(self):
        client = TestClient(self._build_app(1))
        for _ in range(5):
            self.assertEqual(client.get("/api/v1/health").status_code, 200)

    def test_health_probe_routes_are_exempt_from_throttling(self):
        client = TestClient(self._build_app(1))
        for path in (
            "/api/v1/health",
            "/api/v1/health/",
            "/api/v1/health/live",
            "/api/v1/health/ready",
            "/api/v1/health/live/",
        ):
            for _ in range(5):
                self.assertEqual(client.get(path).status_code, 200)

    def test_disabled_limiter_never_throttles(self):
        client = TestClient(self._build_app(0))
        for _ in range(10):
            self.assertEqual(client.get("/api/v1/thing").status_code, 200)


if __name__ == "__main__":
    unittest.main()
