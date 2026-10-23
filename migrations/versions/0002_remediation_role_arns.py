"""split remediation role ARNs on aws_accounts

Revision ID: 0002_remediation_roles
Revises: 0001_baseline
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_remediation_roles"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("aws_accounts",
        sa.Column("auto_remediation_role_arn", sa.String(255), nullable=True))
    op.add_column("aws_accounts",
        sa.Column("destructive_remediation_role_arn", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("aws_accounts", "destructive_remediation_role_arn")
    op.drop_column("aws_accounts", "auto_remediation_role_arn")
