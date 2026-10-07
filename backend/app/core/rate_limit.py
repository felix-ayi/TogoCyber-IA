"""In-process sliding-window rate limiting.

This is a deliberately small, dependency-free limiter meant for a single-process
deployment. It keeps a bounded in-memory window per client key. When the app runs
behind several workers or instances the window is NOT shared, so the effective
limit multiplies by the number of processes; a shared store (e.g. Redis) is required
for a true global limit. The limiter is disabled unless RATE_LIMIT_PER_MINUTE > 0.
"""

from collections import deque
from functools import lru_cache
import hashlib
import hmac
import ipaddress
import threading
import time

from backend.app.core.config import settings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_sweep: float | None = None

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Record a hit for ``key``; return ``(allowed, retry_after_seconds)``."""
        if self.max_requests <= 0:
            return True, 0
        current = time.monotonic() if now is None else now
        window_start = current - self.window_seconds
        with self._lock:
            self._sweep(window_start, current)
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= window_start:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = int(bucket[0] + self.window_seconds - current) + 1
                return False, max(retry_after, 1)
            bucket.append(current)
            return True, 0

    def _sweep(self, window_start: float, current: float) -> None:
        # Drop expired buckets at most once per window so the mapping cannot grow
        # without bound as distinct client keys come and go.
        if self._last_sweep is None:
            self._last_sweep = current
            return
        if current - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = current
        for key in list(self._hits):
            bucket = self._hits[key]
            while bucket and bucket[0] <= window_start:
                bucket.popleft()
            if not bucket:
                del self._hits[key]


@lru_cache(maxsize=8)
def _trusted_proxy_networks(cidrs: tuple[str, ...]) -> tuple:
    return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def client_key(request) -> str:
    """Stable, non-reversible per-client key.

    The raw address is never retained — only an HMAC of it under the auth secret — so
    the limiter's memory cannot leak client IPs. Forwarded addresses are considered
    only when the direct peer belongs to a configured trusted proxy network.
    """
    host = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    networks = _trusted_proxy_networks(settings.trusted_proxy_cidrs)
    try:
        peer = ipaddress.ip_address(host)
    except ValueError:
        peer = None
    if forwarded and peer is not None and any(peer in network for network in networks):
        forwarded_hosts = [item.strip() for item in forwarded.split(",")]
        for forwarded_host in reversed(forwarded_hosts):
            try:
                address = ipaddress.ip_address(forwarded_host)
            except ValueError:
                break
            if not any(address in network for network in networks):
                host = address.compressed
                break
    return hmac.new(
        settings.auth_secret_key.encode("utf-8"), host.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# Liveness/readiness probes must never be throttled, otherwise an orchestrator would
# restart a healthy instance that happens to sit behind a busy client.
_EXEMPT_PATHS = frozenset({"/", "/api/v1/health"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: SlidingWindowRateLimiter) -> None:
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        if self.limiter.max_requests <= 0 or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)
        allowed, retry_after = self.limiter.allow(client_key(request))
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Trop de requêtes. Réessayez dans quelques instants."},
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
