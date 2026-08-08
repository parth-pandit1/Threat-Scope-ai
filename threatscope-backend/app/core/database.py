"""
Async SQLAlchemy 2.0 database engine and session management.

Provides:
- Async engine with connection pooling
- Async session factory for request-scoped sessions
- FastAPI dependency ``get_db`` that yields a session per request
- ``init_db`` helper to create all tables (dev / first-run convenience)
"""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Async Engine ─────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=10,
)

# ── Session Factory ──────────────────────────────────────────
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Declarative Base ─────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


# ── FastAPI Dependency ───────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async database session scoped to a single request.

    Commits on success, rolls back on exception, and always closes
    the session when the request is done.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Table Creation Helper ────────────────────────────────────
async def init_db() -> None:
    """
    No-op database init helper. Tables are managed via Alembic migrations.
    """
    logger.info("Database tables initialization bypassed (using Alembic migrations)")
