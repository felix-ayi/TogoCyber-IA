import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core.rate_limit import RateLimitMiddleware, SlidingWindowRateLimiter


class SlidingWindowRateLimiterTests(unittest.TestCase):
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

    def test_disabled_limiter_never_throttles(self):
        client = TestClient(self._build_app(0))
        for _ in range(10):
            self.assertEqual(client.get("/api/v1/thing").status_code, 200)


if __name__ == "__main__":
    unittest.main()
