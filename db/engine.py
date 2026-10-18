"""
Database engine and session management.

Supports both PostgreSQL (production) and SQLite (local dev/testing)
via the DATABASE_URL environment variable.

  PostgreSQL: DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/cloud_guardian
  SQLite dev: DATABASE_URL=sqlite+aiosqlite:///./data/cloud_guardian.db  (default)

SQLite requires `pip install aiosqlite` — already in requirements.txt.
Switch to PostgreSQL for any multi-tenant deployment.
"""
import os
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/cloud_guardian.db"
)


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_async_engine(
    DATABASE_URL,
    echo=os.environ.get("DB_ECHO", "false").lower() == "true",
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a db session, always closes on exit."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables. Call on app startup for SQLite dev. Use Alembic for Postgres."""
    from db.models import organization, user, aws_account, incident, audit
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
