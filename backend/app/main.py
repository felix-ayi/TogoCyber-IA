from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.logging import configure_logging
from backend.app.core.rate_limit import RateLimitMiddleware, SlidingWindowRateLimiter
from backend.app.repositories.history_repository import initialize_database
from backend.app.api.v1.router import router as api_router
from backend.app.services.auth_service import initialize_bootstrap_admin

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    initialize_database()
    initialize_bootstrap_admin()
    yield


app = FastAPI(
    title=settings.api_title,
    description="API intelligente de detection, prevention et assistance face aux cybermenaces.",
    version=settings.api_version,
    lifespan=lifespan,
)

# Order matters: Starlette treats the last-added middleware as the outermost layer, so
# CORS is added after the limiter to guarantee that even a 429 carries CORS headers.
app.add_middleware(
    RateLimitMiddleware,
    limiter=SlidingWindowRateLimiter(settings.rate_limit_per_minute, window_seconds=60),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "PATCH", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "project": "TogoCyber AI",
        "status": "online",
        "message": "API TogoCyber AI operationnelle"
    }
