"""
Incident model — the production-grade version of DetectedAlert.

An Incident is a detected security event stored in PostgreSQL with
full multi-tenant isolation, lifecycle tracking, and remediation history.

Relationship to the existing detection system:
  DetectedAlert (in-memory/JSONL) -> saved as Incident (PostgreSQL)
  This is the migration path — the rule engine stays the same,
  the storage backend upgrades to this model.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.engine import Base


class IncidentStatus(str, PyEnum):
    detected = "detected"
    pending_approval = "pending_approval"
    remediating = "remediating"
    remediated = "remediated"
    remediation_failed = "remediation_failed"
    false_positive = "false_positive"
    suppressed = "suppressed"


class IncidentSeverityLabel(str, PyEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _utcnow():
    return datetime.now(timezone.utc)


class Incident(Base):
    """
    A detected security incident with full lifecycle tracking.

    Stored in PostgreSQL with organization_id on every row for
    multi-tenant data isolation enforced at the DB layer.
    """
    __tablename__ = "incidents"

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


    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    event_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False, index=True)


    severity: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_tier: Mapped[str] = mapped_column(
        Enum(IncidentSeverityLabel), nullable=False, index=True
    )
    ml_anomaly_score: Mapped[float | None] = mapped_column()


    description: Mapped[str] = mapped_column(Text, nullable=False)
    actor_arn: Mapped[str] = mapped_column(String(255), nullable=False)
    aws_region: Mapped[str] = mapped_column(String(30), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    modifiers: Mapped[list | None] = mapped_column(JSON)

    # Standardized finding fields — same shape regardless of which
    # scanner produced the finding (config_scan, cloudtrail, guardduty).
    # Nullable for backward compatibility with incidents created before
    # these columns existed.
    service: Mapped[str | None] = mapped_column(String(50), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(500), index=True)
    title: Mapped[str | None] = mapped_column(String(255))
    recommendation: Mapped[str | None] = mapped_column(Text)
    compliance: Mapped[list | None] = mapped_column(JSON)


    status: Mapped[str] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.detected,
        nullable=False, index=True,
    )
    assigned_to_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    false_positive_reason: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow,
                                                  onupdate=_utcnow)


    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="incidents"
    )
    aws_account: Mapped["AWSAccount"] = relationship(
        "AWSAccount", back_populates="incidents"
    )
    assigned_to: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assigned_to_id]
    )
    remediations: Mapped[list["RemediationAction"]] = relationship(
        "RemediationAction", back_populates="incident", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Incident id={self.id} technique={self.technique_id} severity={self.severity} status={self.status}>"


class RemediationAction(Base):
    """
    Full audit trail for every remediation action taken on an incident.

    One incident can have multiple remediation attempts (e.g. auto-executed
    low-risk action, then human-approved high-risk follow-up).
    """
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    action_risk_tier: Mapped[str] = mapped_column(String(20), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)


    detail: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    success: Mapped[bool | None] = mapped_column()
    error_message: Mapped[str | None] = mapped_column(Text)

    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="remediations")
    approved_by: Mapped["User | None"] = relationship("User", foreign_keys=[approved_by_id])

    def __repr__(self):
        return f"<RemediationAction id={self.id} action={self.action_type} decision={self.decision}>"
