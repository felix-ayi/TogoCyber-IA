"""Environment-backed configuration without requiring secrets in source control."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    api_title: str = "TogoCyber AI API"
    api_version: str = "1.0.0"
    database_path: Path = Path(os.getenv("TOGOCYBER_DB_PATH", str(ROOT / "database" / "togocyber.sqlite3")))
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip() for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8501").split(",") if origin.strip()
    )

    def __post_init__(self) -> None:
        if not 1 <= self.retention_days <= 30:
            raise ValueError("RETENTION_DAYS must be between 1 and 30")


settings = Settings()