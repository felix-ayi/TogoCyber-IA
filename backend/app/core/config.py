"""Environment-backed configuration without requiring secrets in source control."""

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import secrets

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

_DEFAULT_SQLITE_PATH = ROOT / "database" / "togocyber.sqlite3"


def _resolve_database_path(database_url: str, fallback_path: str) -> Path:
    """Resolve the SQLite file path from DATABASE_URL or TOGOCYBER_DB_PATH.

    DATABASE_URL is the forward-compatible connection string. Only the sqlite scheme is
    wired today; a PostgreSQL URL is rejected loudly rather than silently ignored, so no
    one is misled into believing Postgres is functional before the adapter layer lands.
    """
    if not database_url:
        return Path(fallback_path)
    if database_url.startswith("sqlite:///"):
        return Path(database_url[len("sqlite:///"):])
    if database_url.startswith("sqlite://"):
        return Path(database_url[len("sqlite://"):])
    if database_url.startswith(("postgres://", "postgresql://")):
        raise ValueError(
            "DATABASE_URL utilise PostgreSQL, mais la couche de persistance est actuelle"
            "ment spécifique à SQLite (sqlite3, executescript, triggers). Le support "
            "PostgreSQL nécessite un adaptateur dédié qui n’est pas encore implémenté."
        )
    raise ValueError(f"DATABASE_URL non pris en charge : schéma inconnu dans {database_url!r}")


@dataclass(frozen=True)
class Settings:
    api_title: str = "TogoCyber AI API"
    api_version: str = "1.0.0"
    database_url: str = os.getenv("DATABASE_URL", "").strip()
    database_path: Path = _resolve_database_path(
        os.getenv("DATABASE_URL", "").strip(),
        os.getenv("TOGOCYBER_DB_PATH", str(_DEFAULT_SQLITE_PATH)),
    )
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "0"))
    trusted_proxy_cidrs: tuple[str, ...] = tuple(
        cidr.strip()
        for cidr in os.getenv("TRUSTED_PROXY_CIDRS", "").split(",")
        if cidr.strip()
    )
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    auth_secret_key: str = os.getenv("AUTH_SECRET_KEY") or secrets.token_urlsafe(48)
    bootstrap_admin_email: str = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    bootstrap_admin_password: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    password_reset_email_enabled: bool = str(os.getenv("SMTP_ENABLED", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    password_reset_sender_email: str = os.getenv(
        "SMTP_FROM", os.getenv("NOTIFICATION_SMTP_FROM", "")
    ).strip()
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip() for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8501").split(",") if origin.strip()
    )

    def __post_init__(self) -> None:
        if not 1 <= self.retention_days <= 30:
            raise ValueError("RETENTION_DAYS must be between 1 and 30")
        if self.rate_limit_per_minute < 0:
            raise ValueError("RATE_LIMIT_PER_MINUTE must be 0 (disabled) or a positive integer")
        for cidr in self.trusted_proxy_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid TRUSTED_PROXY_CIDRS entry: {cidr!r}") from exc
        if os.getenv("AUTH_SECRET_KEY") and len(self.auth_secret_key) < 32:
            raise ValueError("AUTH_SECRET_KEY must contain at least 32 characters")
        if bool(self.bootstrap_admin_email) != bool(self.bootstrap_admin_password):
            raise ValueError("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together")
        if self.bootstrap_admin_password and len(self.bootstrap_admin_password) < 11:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 11 characters")


settings = Settings()