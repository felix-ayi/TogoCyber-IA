from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.logging import configure_logging
from backend.app.repositories.history_repository import initialize_database
from backend.app.api.v1.router import router as api_router

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    initialize_database()
    yield


app = FastAPI(
    title=settings.api_title,
    description="API intelligente de detection, prevention et assistance face aux cybermenaces.",
    version=settings.api_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "project": "TogoCyber AI",
        "status": "online",
        "message": "API TogoCyber AI operationnelle"
    }
