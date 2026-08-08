import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import DateTime, String, Boolean, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class UserTier(str, enum.Enum):
    """Access tier level for users."""
    FREE = "free"
    PRO = "pro"


class User(Base):
    """
    SQLAlchemy User model tracking user details, access tiers, API keys,
    admin flags, and account status.
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    api_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        default=lambda: f"ts_{uuid.uuid4().hex}"
    )
    tier: Mapped[UserTier] = mapped_column(
        Enum(UserTier),
        default=UserTier.FREE,
        nullable=False,
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    is_banned: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        import uuid
        from datetime import datetime, timezone
        if not getattr(self, "id", None):
            self.id = uuid.uuid4()
        if not getattr(self, "api_key", None):
            self.api_key = f"ts_{uuid.uuid4().hex}"
        if getattr(self, "is_admin", None) is None:
            self.is_admin = False
        if getattr(self, "is_banned", None) is None:
            self.is_banned = False
        if not getattr(self, "created_at", None):
            self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<User email={self.email} tier={self.tier.value}>"
