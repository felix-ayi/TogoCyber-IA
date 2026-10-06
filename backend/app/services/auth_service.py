"""Password verification and short-lived, revocable bearer-token sessions."""

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time

from backend.app.core.config import settings
from backend.app.repositories import auth_repository

TOKEN_LIFETIME_SECONDS = 30 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_FAILURES = 5
PBKDF2_ITERATIONS = 600_000
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthenticationError(ValueError):
    """Credentials or bearer token are invalid."""


class LoginRateLimited(RuntimeError):
    """The client has exceeded the failed-login budget."""


class UserNotFoundError(LookupError):
    """The requested account does not exist."""


class LastAdminError(RuntimeError):
    """The operation would leave the platform without an active administrator."""


class SelfActionError(RuntimeError):
    """An administrator cannot perform this destructive action on their own account."""


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 254 or not _EMAIL_PATTERN.fullmatch(normalized):
        raise ValueError("Saisissez une adresse e-mail valide.")
    return normalized


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _password_hash(password: str, salt: bytes | None = None) -> str:
    password_salt = secrets.token_bytes(16) if salt is None else salt
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), password_salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_encode(password_salt)}${_encode(derived)}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, expected_text = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        expected = _decode(expected_text)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _decode(salt_text), iterations
        )
    except (ValueError, TypeError, binascii.Error):
        return False
    return hmac.compare_digest(actual, expected)


def register_user(email: str, password: str) -> dict:
    return _create_user(email, password, "User")


def create_managed_user(email: str, password: str, role: str) -> dict:
    if role not in {"Analyst", "User"}:
        raise ValueError("Les comptes créés par un administrateur doivent avoir le rôle Analyst ou User.")
    return _create_user(email, password, role)


def _create_user(email: str, password: str, role: str) -> dict:
    normalized = normalize_email(email)
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Le mot de passe doit contenir entre 12 et 128 caractères.")
    return auth_repository.create_user(normalized, _password_hash(password), role)


def list_managed_users() -> list[dict]:
    return auth_repository.list_users_detailed()


def get_managed_user(user_id: int) -> dict:
    user = auth_repository.get_user_by_id(user_id)
    if user is None:
        raise UserNotFoundError("Utilisateur introuvable.")
    return user


def update_managed_user(
    user_id: int,
    actor_id: int,
    role: str | None = None,
    is_active: bool | None = None,
) -> tuple[dict, list[str]]:
    """Apply role and/or activation changes, returning the user and audit actions taken."""
    target = get_managed_user(user_id)
    if role is not None and role not in {"Admin", "Analyst", "User"}:
        raise ValueError("Rôle invalide.")
    actions: list[str] = []

    if role is not None and role != target["role"]:
        if target["role"] == "Admin" and target["is_active"] and role != "Admin":
            if auth_repository.count_active_admins(exclude_user_id=user_id) < 1:
                raise LastAdminError("Impossible de retirer le dernier administrateur actif.")
        auth_repository.update_user_role(user_id, role)
        actions.append("user.role_changed")

    current = auth_repository.get_user_by_id(user_id) or target
    if is_active is not None and bool(is_active) != bool(current["is_active"]):
        if not is_active:
            if user_id == actor_id:
                raise SelfActionError("Vous ne pouvez pas désactiver votre propre compte.")
            if current["role"] == "Admin" and current["is_active"]:
                if auth_repository.count_active_admins(exclude_user_id=user_id) < 1:
                    raise LastAdminError("Impossible de désactiver le dernier administrateur actif.")
        auth_repository.set_user_active(user_id, bool(is_active))
        actions.append("user.activated" if is_active else "user.deactivated")

    updated = get_managed_user(user_id)
    return updated, actions


def reset_managed_password(user_id: int, new_password: str) -> dict:
    get_managed_user(user_id)
    if len(new_password) < 12 or len(new_password) > 128:
        raise ValueError("Le mot de passe doit contenir entre 12 et 128 caractères.")
    auth_repository.replace_password_hash(user_id, _password_hash(new_password))
    return get_managed_user(user_id)


def delete_managed_user(user_id: int, actor_id: int) -> None:
    target = get_managed_user(user_id)
    if user_id == actor_id:
        raise SelfActionError("Vous ne pouvez pas supprimer votre propre compte.")
    if target["role"] == "Admin" and target["is_active"]:
        if auth_repository.count_active_admins(exclude_user_id=user_id) < 1:
            raise LastAdminError("Impossible de supprimer le dernier administrateur actif.")
    auth_repository.delete_user(user_id)


def _issue_token(user: dict, now: int | None = None) -> dict:
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + TOKEN_LIFETIME_SECONDS
    token_id = secrets.token_urlsafe(24)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": issued_at,
        "exp": expires_at,
        "jti": token_id,
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_encode(json.dumps(header, separators=(',', ':')).encode())}.{_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(
        settings.auth_secret_key.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    token = f"{signing_input}.{_encode(signature)}"
    auth_repository.create_session(
        int(user["id"]),
        hashlib.sha256(token_id.encode("utf-8")).hexdigest(),
        expires_at,
    )
    # "bearer" is the OAuth2 token-type label, not a credential.
    token_type = "bearer"  # nosec B105
    return {
        "access_token": token,
        "token_type": token_type,
        "expires_in": TOKEN_LIFETIME_SECONDS,
        "user": {
            "id": int(user["id"]),
            "email": user["email"],
            "role": user["role"],
        },
    }


def login(email: str, password: str, client_identifier: str, now: int | None = None) -> dict:
    current_time = int(time.time()) if now is None else now
    client_hash = auth_repository.client_identifier_hash(client_identifier)
    window_start = current_time - LOGIN_WINDOW_SECONDS
    if not auth_repository.begin_login_attempt(
        client_hash, current_time, window_start, MAX_LOGIN_FAILURES
    ):
        raise LoginRateLimited("Trop de tentatives. Réessayez dans 15 minutes.")

    try:
        normalized = normalize_email(email)
    except ValueError:
        normalized = ""
    user = auth_repository.find_user_by_email(normalized) if normalized else None
    encoded_password = user["password_hash"] if user else _password_hash(
        "constant-time-invalid-password", b"\x00" * 16
    )
    password_valid = _verify_password(password, encoded_password)
    if user is None or not user["is_active"] or not password_valid:
        raise AuthenticationError("Adresse e-mail ou mot de passe incorrect.")

    auth_repository.clear_login_attempts(client_hash)
    return _issue_token(user, current_time)


def authenticate_token(token: str, now: int | None = None) -> dict:
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}"
        expected_signature = hmac.new(
            settings.auth_secret_key.encode("utf-8"),
            signing_input.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected_signature, _decode(signature_part)):
            raise AuthenticationError("Jeton invalide ou expiré.")
        header = json.loads(_decode(header_part))
        payload = json.loads(_decode(payload_part))
        if header != {"alg": "HS256", "typ": "JWT"}:
            raise AuthenticationError("Jeton invalide ou expiré.")
        user_id = int(payload["sub"])
        expires_at = int(payload["exp"])
        token_id = str(payload["jti"])
    except AuthenticationError:
        raise
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise AuthenticationError("Jeton invalide ou expiré.") from exc

    current_time = int(time.time()) if now is None else now
    token_id_hash = hashlib.sha256(token_id.encode("utf-8")).hexdigest()
    if expires_at <= current_time or not auth_repository.session_is_active(
        user_id, token_id_hash, current_time
    ):
        raise AuthenticationError("Jeton invalide ou expiré.")
    user = auth_repository.find_active_user(user_id)
    if user is None:
        raise AuthenticationError("Jeton invalide ou expiré.")
    return user


def logout(token: str) -> None:
    try:
        payload = json.loads(_decode(token.split(".")[1]))
        token_id = str(payload["jti"])
    except (IndexError, ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise AuthenticationError("Jeton invalide ou expiré.") from exc
    auth_repository.revoke_session(hashlib.sha256(token_id.encode("utf-8")).hexdigest())


def initialize_bootstrap_admin() -> None:
    if settings.bootstrap_admin_email:
        email = normalize_email(settings.bootstrap_admin_email)
        auth_repository.initialize_bootstrap_admin(email, _password_hash(settings.bootstrap_admin_password))
