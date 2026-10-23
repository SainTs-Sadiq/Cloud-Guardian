"""Alembic environment — reads DATABASE_URL, autogenerates from db.models."""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

database_url = os.environ.get("DATABASE_URL", "")
# Alembic runs synchronously: swap any async driver for its sync twin
for _async, _sync in (("postgresql+asyncpg", "postgresql+psycopg2"),
                      ("sqlite+aiosqlite", "sqlite")):
    if database_url.startswith(_async):
        database_url = database_url.replace(_async, _sync, 1)
config.set_main_option("sqlalchemy.url", database_url or "postgresql://localhost/cloud_guardian")

import db.models  # noqa: F401 — register all models on db.engine.Base
from db.engine import Base
target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"),
                      target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
