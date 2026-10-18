"""
Asset model — lightweight resource inventory.

Populated as a side effect of config scanning: every resource a scanner
examines (not just ones with findings) gets an upserted Asset row, so
GET /dashboard/assets can show a real inventory ("47 S3 buckets, 12 IAM
users...") rather than only resources that happen to have an open finding.

Keyed on (organization_id, aws_account_id, service, resource_id) — a
re-scan updates last_seen_at rather than creating duplicates.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.engine import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Asset(Base):
    """A discovered AWS resource, tracked independent of whether it has findings."""
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "aws_account_id", "service", "resource_id",
                          name="uq_asset_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    aws_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("aws_accounts.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    service: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    region: Mapped[str] = mapped_column(String(30), nullable=False)
    resource_metadata: Mapped[dict | None] = mapped_column(JSON)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow,
                                                     onupdate=_utcnow, index=True)

    organization: Mapped["Organization"] = relationship("Organization")
    aws_account: Mapped["AWSAccount"] = relationship("AWSAccount")

    def __repr__(self):
        return f"<Asset service={self.service} resource_id={self.resource_id}>"
