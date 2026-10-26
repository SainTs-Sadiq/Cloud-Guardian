"""add remediation_attempts claim table (idempotent retries)

Revision ID: 0005_remediation_attempts
Revises: 0004_anomaly_models
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_remediation_attempts"
down_revision = "0004_anomaly_models"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("incident_id", sa.String(36), nullable=False, index=True),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("incident_id", "action_type", name="uq_remediation_attempt"),
    )


def downgrade():
    op.drop_table("remediation_attempts")
