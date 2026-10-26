"""add anomaly_models table (durable, signed model storage)

Revision ID: 0004_anomaly_models
Revises: 0003_processed_stripe_events
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_anomaly_models"
down_revision = "0003_processed_stripe_events"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "anomaly_models",
        sa.Column("scope", sa.String(64), primary_key=True),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("anomaly_models")
