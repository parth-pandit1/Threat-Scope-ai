import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserTier


class UserRegister(BaseModel):
    """Payload to register a new user."""
    email: EmailStr
    password: str = Field(..., min_length=6, description="Minimum 6 characters")


class UserLogin(BaseModel):
    """Payload to login an existing user."""
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Response containing user profile details."""
    id: uuid.UUID
    email: str
    api_key: str
    tier: UserTier
    is_admin: bool
    is_banned: bool
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class TokenResponse(BaseModel):
    """Token payload returned to clients upon successful auth."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse
