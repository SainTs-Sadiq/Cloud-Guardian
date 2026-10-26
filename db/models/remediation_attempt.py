"""
RemediationAttempt: claim record written BEFORE a remediation handler touches AWS.

A Celery retry (or a duplicate delivery) finds the existing claim and does not
run the AWS call again. Keyed on (incident_id, action_type) so one incident
can run one action at most.

status:
  running   claimed, handler in flight or the worker died mid-action
  succeeded handler returned success
  failed    handler returned failure (retry may re-run it)
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.engine import Base


def _utcnow():
    return datetime.now(timezone.utc)


class RemediationAttempt(Base):
    __tablename__ = "remediation_attempts"
    __table_args__ = (
        UniqueConstraint("incident_id", "action_type", name="uq_remediation_attempt"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
