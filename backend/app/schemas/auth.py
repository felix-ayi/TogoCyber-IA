from typing import Literal

from pydantic import BaseModel, Field


class CredentialsRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class RegistrationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

    model_config = {"extra": "forbid"}


class UserResponse(BaseModel):
    id: int
    email: str
    role: Literal["Admin", "Analyst", "User"]
    is_active: bool = True
    created_at: str | None = None


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"]
    expires_in: int
    user: UserResponse


class ManagedUserRequest(RegistrationRequest):
    role: Literal["Analyst", "User"]


class ManagedUserResponse(UserResponse):
    is_active: bool = True


class UserDetailResponse(BaseModel):
    id: int
    email: str
    role: Literal["Admin", "Analyst", "User"]
    is_active: bool
    created_at: str
    last_login: str | None = None


class UserDetailListResponse(BaseModel):
    items: list[UserDetailResponse]


class UserUpdateRequest(BaseModel):
    role: Literal["Admin", "Analyst", "User"] | None = None
    is_active: bool | None = None

    model_config = {"extra": "forbid"}


class PasswordResetRequest(BaseModel):
    password: str = Field(min_length=12, max_length=128)

    model_config = {"extra": "forbid"}


class PasswordResetEmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    model_config = {"extra": "forbid"}


class PasswordResetTokenRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    token: str = Field(min_length=20, max_length=512)
    password: str = Field(min_length=12, max_length=128)

    model_config = {"extra": "forbid"}


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

    model_config = {"extra": "forbid"}
