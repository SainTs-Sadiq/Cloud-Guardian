"""baseline schema (matches db/models at v15)

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline: create nothing. Databases initialized from db.Base.metadata
    # (fresh installs) already have every v15 table. Existing v15 databases
    # are stamped here: alembic stamp 0001_baseline
    pass


def downgrade() -> None:
    pass
