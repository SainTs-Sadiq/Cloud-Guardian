"""
ScanRun model — durable scan lifecycle tracking.

Celery's AsyncResult (used by GET /scan/{job_id}) only works when Redis is
configured, and its results expire (result_expires=3600s) — it's not a
history. ScanRun is the durable record: every scan dispatch (manual,
scheduled, or triggered by account verification) gets a row here that
tracks status through its lifecycle, independent of Redis/Celery.

Lifecycle: running -> success | failed | partial
  - success: completed with no errors
  - partial: completed but one or more accounts/regions errored
  - failed: the scan never got off the ground (e.g. STS assume-role failed
    for every account)
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.engine import Base


class ScanRunStatus(str, PyEnum):
    running = "running"
    success = "success"
    partial = "partial"
    failed = "failed"


class ScanTrigger(str, PyEnum):
    manual = "manual"
    scheduled = "scheduled"
    verification = "verification"


def _utcnow():
    return datetime.now(timezone.utc)


class ScanRun(Base):
    """One org-wide scan dispatch (which may fan out across many accounts/regions)."""
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    status: Mapped[str] = mapped_column(
        Enum(ScanRunStatus), default=ScanRunStatus.running, nullable=False, index=True,
    )
    trigger: Mapped[str] = mapped_column(
        Enum(ScanTrigger), default=ScanTrigger.manual, nullable=False,
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(155), index=True)

    accounts_targeted: Mapped[int] = mapped_column(Integer, default=0)
    accounts_succeeded: Mapped[int] = mapped_column(Integer, default=0)
    accounts_failed: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped["Organization"] = relationship("Organization")

    def __repr__(self):
        return f"<ScanRun id={self.id} status={self.status} findings={self.findings_count}>"
