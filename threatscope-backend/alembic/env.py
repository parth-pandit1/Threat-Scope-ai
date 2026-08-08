"""
Alembic environment configuration for async SQLAlchemy migrations.

This file is executed by Alembic when running migration commands.
It configures the database URL from application settings (not from
alembic.ini) and uses an async engine for online migrations.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import settings
from app.core.database import Base

# Import all models so their tables are registered on Base.metadata
from app.models import Scan  # noqa: F401

# ── Alembic Config object ───────────────────────────────────
config = context.config

# Set up Python logging from the alembic.ini [loggers] section
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override the placeholder URL with the real async DATABASE_URL
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# MetaData object for autogenerate support
target_metadata = Base.metadata


# ─────────────────────────────────────────────────────────────
# Offline Migrations (SQL script generation)
# ─────────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """
    Generate migration SQL without connecting to the database.

    Produces a ``.sql`` script that can be applied manually.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ─────────────────────────────────────────────────────────────
# Online Migrations (async engine)
# ─────────────────────────────────────────────────────────────
def do_run_migrations(connection: Connection) -> None:
    """Run migrations within a synchronous connection callback."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine, connect, and run migrations."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online (connected) migrations via asyncio."""
    asyncio.run(run_async_migrations())


# ── Dispatch ─────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
