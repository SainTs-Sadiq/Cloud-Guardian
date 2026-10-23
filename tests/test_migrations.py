"""Prove a v15-shaped database upgrades to v17 cleanly."""
import os
import sqlite3

import pytest

alembic = pytest.importorskip("alembic.command")
pytest.importorskip("alembic.config")


def _v15_schema(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE aws_accounts (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            aws_account_id VARCHAR(12) NOT NULL,
            display_name VARCHAR(255) NOT NULL,
            role_arn VARCHAR(255) NOT NULL,
            external_id VARCHAR(100)
        );
        CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);
        INSERT INTO alembic_version VALUES ('0001_baseline');
    """)
    conn.commit()
    conn.close()


def test_v15_database_gains_remediation_role_columns(tmp_path):
    db_path = str(tmp_path / "v15.db")
    _v15_schema(db_path)

    from alembic.config import Config
    cfg = Config("alembic.ini")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    alembic.upgrade(cfg, "0002_remediation_roles")

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(aws_accounts)")}
    conn.close()
    assert "auto_remediation_role_arn" in cols
    assert "destructive_remediation_role_arn" in cols


def test_fresh_install_has_all_columns_via_metadata():
    """Fresh install path: Base.metadata.create_all must include the new cols."""
    from sqlalchemy.ext.asyncio import create_async_engine
    import asyncio
    from db.engine import Base
    import db.models  # noqa: F401

    async def _make():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            def _cols(sync_conn):
                from sqlalchemy import inspect
                insp = inspect(sync_conn)
                return {c["name"] for c in insp.get_columns("aws_accounts")}
            return await conn.run_sync(lambda c: _cols(c))
        await engine.dispose()

    cols = asyncio.get_event_loop().run_until_complete(_make())
    assert "auto_remediation_role_arn" in cols
    assert "destructive_remediation_role_arn" in cols


def test_v17_shaped_db_with_alembic_stamp_upgrades(tmp_path):
    """A v17 DB (has alembic_version=0002 already) re-upgrades to head as no-op."""
    db_path = str(tmp_path / "v17.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE aws_accounts (id VARCHAR(36) PRIMARY KEY, role_arn VARCHAR(255) NOT NULL);
        CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);
        INSERT INTO alembic_version VALUES ('0002_remediation_roles');
    """)
    conn.commit(); conn.close()

    from alembic.config import Config
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    alembic.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(aws_accounts)")}
    version = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    conn.close()
    assert version == "0002_remediation_roles"
    assert "role_arn" in cols
