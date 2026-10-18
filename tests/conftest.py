"""
Shared test fixtures — provides a reusable async-safe in-memory SQLite DB
for API-level tests that need the FastAPI app with a real DB session.
"""
import asyncio
import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from db.engine import Base, get_db
from api.app import app


def _get_or_create_event_loop():
    """
    asyncio.get_event_loop() raises (rather than creating a loop) once
    something else on this thread has run an asyncio test and closed its
    loop — which happens as soon as any @pytest.mark.asyncio test runs
    earlier in the same session. Fixtures that need a loop synchronously
    (because TestClient itself is sync) should go through this instead of
    calling asyncio.get_event_loop() directly.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("loop closed")
        return loop
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


@pytest.fixture(scope="function")
def auth_client():
    """
    TestClient wired to a fresh in-memory SQLite DB per test function.
    Handles the async engine init synchronously so TestClient (sync) works.
    """
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )


    async def _setup():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _get_or_create_event_loop().run_until_complete(_setup())

    TestSessionLocal = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def override_get_db():
        async with TestSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=True)
    yield client

    app.dependency_overrides.clear()
    _get_or_create_event_loop().run_until_complete(test_engine.dispose())
