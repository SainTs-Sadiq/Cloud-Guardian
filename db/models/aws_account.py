"""
AWSAccount model — connected AWS accounts per organization.

Each org can connect multiple AWS accounts (plan-limited).
Credentials are NEVER stored here — we store the IAM role ARN
that Cloud Guardian assumes via cross-account STS, following
AWS best practices for multi-account security tooling.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.engine import Base


class AccountStatus(str, PyEnum):
    active = "active"
    disconnected = "disconnected"
    error = "error"
    pending = "pending"


def _utcnow():
    return datetime.now(timezone.utc)


class AWSAccount(Base):
    """
    An AWS account connected to Cloud Guardian for monitoring.

    Cross-account access model:
    1. Customer creates an IAM role in their account with our detection
       policy attached and a trust policy allowing our account to assume it.
    2. They register the role ARN here.
    3. On each scan, we call sts:AssumeRole with this ARN to get temporary
       credentials — no long-lived keys stored anywhere.
    """
    __tablename__ = "aws_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )


    aws_account_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role_arn: Mapped[str] = mapped_column(String(255), nullable=False)
    # Separate remediation roles. auto_remediation_role_arn must NEVER grant
    # destructive permissions; destructive_remediation_role_arn is only used
    # after an explicit human approval (API route, never celery).
    auto_remediation_role_arn: Mapped[str | None] = mapped_column(String(255))
    destructive_remediation_role_arn: Mapped[str | None] = mapped_column(String(255))

    external_id: Mapped[str | None] = mapped_column(String(100))


    primary_region: Mapped[str] = mapped_column(String(30), default="us-east-1")
    additional_regions: Mapped[list | None] = mapped_column(JSON)

    status: Mapped[str] = mapped_column(
        Enum(AccountStatus), default=AccountStatus.pending, nullable=False
    )
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    guardduty_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    cloudtrail_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow,
                                                  onupdate=_utcnow)


    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="aws_accounts"
    )
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="aws_account", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<AWSAccount id={self.id} aws_id={self.aws_account_id} name={self.display_name}>"
