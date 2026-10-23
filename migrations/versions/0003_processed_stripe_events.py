"""add processed_stripe_events dedupe table

Revision ID: 0003_processed_stripe_events
Revises: 0002_remediation_roles
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_processed_stripe_events"
down_revision = "0002_remediation_roles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "processed_stripe_events",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("processed_stripe_events")
