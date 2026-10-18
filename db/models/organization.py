"""
Organization model — the top-level multi-tenant unit.

Every other table references organization_id. A single deployment of
Cloud Guardian can serve multiple orgs (SaaS mode) with full data
isolation enforced at the repository layer.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.engine import Base


class PlanTier(str, PyEnum):
    free = "free"
    starter = "starter"
    pro = "pro"
    enterprise = "enterprise"


class ScanFrequency(str, PyEnum):
    manual = "manual"      # never auto-scan; only POST /scan or verify triggers one
    daily = "daily"
    hourly = "hourly"


def _utcnow():
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False,
                                      index=True)
    plan: Mapped[str] = mapped_column(
        Enum(PlanTier), default=PlanTier.free, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


    billing_email: Mapped[str | None] = mapped_column(String(255))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(100))


    max_aws_accounts: Mapped[int] = mapped_column(Integer, default=1)
    max_monthly_alerts: Mapped[int] = mapped_column(Integer, default=100)

    # Scheduler settings (see workers/tasks.py::run_all_accounts_scan and
    # api/routes/organizations.py)
    scan_frequency: Mapped[str] = mapped_column(
        Enum(ScanFrequency), default=ScanFrequency.daily, nullable=False
    )
    notification_webhook_url: Mapped[str | None] = mapped_column(String(500))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow,
                                                  onupdate=_utcnow)


    users: Mapped[list["User"]] = relationship(
        "User", back_populates="organization", cascade="all, delete-orphan"
    )
    aws_accounts: Mapped[list["AWSAccount"]] = relationship(
        "AWSAccount", back_populates="organization", cascade="all, delete-orphan"
    )
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="organization", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Organization id={self.id} slug={self.slug} plan={self.plan}>"
