from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth_deps import get_current_admin
from app.models.user import User

router = APIRouter(prefix="/api/admin", tags=["Admin Operations"])


class UserBanRequest(BaseModel):
    """Payload to ban or unban a user by email."""
    email: EmailStr
    is_banned: bool = True


@router.post(
    "/ban",
    summary="Ban or unban a user account",
)
async def ban_user(
    payload: UserBanRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(get_current_admin),
):
    """Bans or unbans a user account by email. Requires admin privileges."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email '{payload.email}' not found"
        )

    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot ban your own administrator account"
        )

    user.is_banned = payload.is_banned
    await db.flush()

    action = "banned" if payload.is_banned else "unbanned"
    return {"message": f"User '{payload.email}' has been successfully {action}."}
