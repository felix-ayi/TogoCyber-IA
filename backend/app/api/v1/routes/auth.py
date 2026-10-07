from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.core.auth import get_current_user, require_roles
from backend.app.core.rate_limit import client_key
from backend.app.repositories.audit_repository import record_event as record_audit_event
from backend.app.repositories.auth_repository import DuplicateUserError
from backend.app.schemas.auth import (
    AuthResponse,
    CredentialsRequest,
    ManagedUserRequest,
    ManagedUserResponse,
    PasswordResetRequest,
    RegistrationRequest,
    UserDetailListResponse,
    UserDetailResponse,
    UserResponse,
    UserUpdateRequest,
)
from backend.app.services.auth_service import (
    AuthenticationError,
    LastAdminError,
    LoginRateLimited,
    SelfActionError,
    UserNotFoundError,
    create_managed_user as provision_user,
    delete_managed_user,
    get_managed_user,
    list_managed_users,
    login as authenticate,
    logout as revoke,
    register_user,
    reset_managed_password,
    update_managed_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
_bearer_scheme = HTTPBearer(auto_error=False)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegistrationRequest):
    try:
        user = register_user(request.email, request.password)
        record_audit_event("auth.registered", "success", user["id"], "user", user["id"])
        return user
    except DuplicateUserError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/login", response_model=AuthResponse)
def login(request: CredentialsRequest, client_request: Request):
    client_identifier = client_key(client_request)
    try:
        response = authenticate(request.email, request.password, client_identifier)
        record_audit_event(
            "auth.login.succeeded",
            "success",
            response["user"]["id"],
            "user",
            response["user"]["id"],
        )
        return response
    except LoginRateLimited as exc:
        record_audit_event("auth.login.rate_limited", "failure", target_type="auth")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except AuthenticationError as exc:
        record_audit_event("auth.login.failed", "failure", target_type="auth")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(get_current_user)],
)
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    user: dict = Depends(get_current_user),
):
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentification requise.")
    revoke(credentials.credentials)
    record_audit_event("auth.logout", "success", user["id"], "user", user["id"])
    return None


@router.get("/me", response_model=UserResponse)
def me(user: dict = Depends(get_current_user)):
    return user


@router.post(
    "/users",
    response_model=ManagedUserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles("Admin"))],
)
def create_managed_user(
    request: ManagedUserRequest,
    admin: dict = Depends(require_roles("Admin")),
):
    try:
        user = provision_user(request.email, request.password, request.role)
        record_audit_event("user.provisioned", "success", admin["id"], "user", user["id"])
        return user
    except DuplicateUserError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get(
    "/users",
    response_model=UserDetailListResponse,
    dependencies=[Depends(require_roles("Admin"))],
)
def users():
    return {"items": list_managed_users()}


@router.get(
    "/users/{user_id}",
    response_model=UserDetailResponse,
    dependencies=[Depends(require_roles("Admin"))],
)
def get_user(user_id: int):
    try:
        return get_managed_user(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch(
    "/users/{user_id}",
    response_model=UserDetailResponse,
    dependencies=[Depends(require_roles("Admin"))],
)
def update_user(
    user_id: int,
    request: UserUpdateRequest,
    admin: dict = Depends(require_roles("Admin")),
):
    try:
        user, actions = update_managed_user(
            user_id, admin["id"], role=request.role, is_active=request.is_active
        )
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (LastAdminError, SelfActionError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    for action in actions:
        record_audit_event(action, "success", admin["id"], "user", user["id"])
    return user


@router.post(
    "/users/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_roles("Admin"))],
)
def reset_user_password(
    user_id: int,
    request: PasswordResetRequest,
    admin: dict = Depends(require_roles("Admin")),
):
    try:
        reset_managed_password(user_id, request.password)
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    record_audit_event("user.password_reset", "success", admin["id"], "user", user_id)
    return None


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_roles("Admin"))],
)
def delete_user(
    user_id: int,
    admin: dict = Depends(require_roles("Admin")),
):
    try:
        delete_managed_user(user_id, admin["id"])
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (LastAdminError, SelfActionError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    record_audit_event("user.deleted", "success", admin["id"], "user", user_id)
    return None
