import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.engine import Base


class PlaybookStatus(str, PyEnum):
    observing           = "observing"
    learning            = "learning"
    candidate           = "candidate"
    pending_graduation  = "pending_graduation"
    autonomous          = "autonomous"
    continuous_validation = "continuous_validation"
    disabled            = "disabled"


LIFECYCLE_ORDER = [
    PlaybookStatus.observing,
    PlaybookStatus.learning,
    PlaybookStatus.candidate,
    PlaybookStatus.pending_graduation,
    PlaybookStatus.autonomous,
    PlaybookStatus.continuous_validation,
]

LIFECYCLE_DESCRIPTIONS = {
    PlaybookStatus.observing:            "Watching — 1-2 sightings, building context",
    PlaybookStatus.learning:             "Learning — collecting analyst-confirmed responses",
    PlaybookStatus.candidate:            "Candidate — threshold reached, building confidence",
    PlaybookStatus.pending_graduation:   "Awaiting final analyst approval for autonomous execution",
    PlaybookStatus.autonomous:           "Autonomous — self-executing with continuous validation",
    PlaybookStatus.continuous_validation:"Under review — outcomes being re-evaluated",
    PlaybookStatus.disabled:             "Disabled — autonomous execution suspended",
}


def _utcnow():
    return datetime.now(timezone.utc)


class PlaybookMemory(Base):
    __tablename__ = "playbook_memories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    attack_fingerprint:      Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    fingerprint_description: Mapped[str] = mapped_column(String(500), nullable=False)
    fingerprint_features:    Mapped[dict | None] = mapped_column(JSON)

    technique_id:   Mapped[str] = mapped_column(String(20),  nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic:         Mapped[str] = mapped_column(String(100), nullable=False)
    event_name:     Mapped[str] = mapped_column(String(255), nullable=False)
    risk_tier:      Mapped[str] = mapped_column(String(20),  nullable=False)

    learned_action:      Mapped[str]       = mapped_column(String(100), nullable=False)
    action_detail:       Mapped[str | None] = mapped_column(Text)

    instance_count:       Mapped[int]   = mapped_column(Integer, default=0,   nullable=False)
    successful_count:     Mapped[int]   = mapped_column(Integer, default=0,   nullable=False)
    false_positive_count: Mapped[int]   = mapped_column(Integer, default=0,   nullable=False)
    rollback_count:       Mapped[int]   = mapped_column(Integer, default=0,   nullable=False)
    analyst_agreement:    Mapped[int]   = mapped_column(Integer, default=0,   nullable=False)
    confidence_score:     Mapped[float] = mapped_column(Float,   default=0.0, nullable=False)
    trust_score:          Mapped[float] = mapped_column(Float,   default=0.0, nullable=False)

    learning_threshold: Mapped[int]  = mapped_column(Integer, default=5,    nullable=False)
    observe_threshold:  Mapped[int]  = mapped_column(Integer, default=2,    nullable=False)
    candidate_threshold:Mapped[int]  = mapped_column(Integer, default=3,    nullable=False)

    status:   Mapped[str] = mapped_column(
        Enum(PlaybookStatus), default=PlaybookStatus.observing,
        nullable=False, index=True,
    )
    version:  Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    graduated_at:               Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    graduation_approved_by_id:  Mapped[str | None]      = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    graduation_notes:           Mapped[str | None]      = mapped_column(Text)
    last_executed_at:           Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at:               Mapped[datetime]        = mapped_column(DateTime(timezone=True), default=_utcnow)
    validation_started_at:      Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow,
                                                  onupdate=_utcnow)

    graduation_approved_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[graduation_approved_by_id]
    )
    observations: Mapped[list["PlaybookObservation"]] = relationship(
        "PlaybookObservation", back_populates="memory",
        cascade="all, delete-orphan",
        order_by="PlaybookObservation.created_at",
    )
    versions: Mapped[list["PlaybookVersion"]] = relationship(
        "PlaybookVersion", back_populates="memory",
        cascade="all, delete-orphan",
        order_by="PlaybookVersion.version_number",
    )

    @property
    def status_description(self) -> str:
        return LIFECYCLE_DESCRIPTIONS.get(self.status, "")

    def __repr__(self):
        return (f"<PlaybookMemory fp={self.attack_fingerprint[:12]}… "
                f"action={self.learned_action} count={self.instance_count} "
                f"status={self.status} trust={self.trust_score:.2f}>")


class PlaybookObservation(Base):
    __tablename__ = "playbook_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    memory_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("playbook_memories.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )

    analyst_action:  Mapped[str]       = mapped_column(String(100), nullable=False)
    analyst_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    analyst_notes:   Mapped[str | None] = mapped_column(Text)

    outcome:         Mapped[str]  = mapped_column(String(20),  nullable=False)
    was_autonomous:  Mapped[bool] = mapped_column(Boolean,     default=False)
    was_rolled_back: Mapped[bool] = mapped_column(Boolean,     default=False)
    attack_severity: Mapped[int]  = mapped_column(Integer,     nullable=False)
    attack_context:  Mapped[dict | None] = mapped_column(JSON)

    investigation_steps: Mapped[list | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    memory: Mapped["PlaybookMemory"] = relationship("PlaybookMemory", back_populates="observations")

    def __repr__(self):
        return f"<PlaybookObservation action={self.analyst_action} outcome={self.outcome} auto={self.was_autonomous}>"


class PlaybookVersion(Base):
    """
    Immutable snapshot of a PlaybookMemory at each status transition.
    Provides full audit history of how the playbook evolved.
    """
    __tablename__ = "playbook_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    memory_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("playbook_memories.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    version_number:   Mapped[int] = mapped_column(Integer, nullable=False)
    status_at_version:Mapped[str] = mapped_column(String(50), nullable=False)
    learned_action:   Mapped[str] = mapped_column(String(100), nullable=False)
    instance_count:   Mapped[int] = mapped_column(Integer, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    trust_score:      Mapped[float] = mapped_column(Float, nullable=False)
    changed_by_id:    Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    change_reason:    Mapped[str | None] = mapped_column(Text)
    snapshot:         Mapped[dict | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    memory: Mapped["PlaybookMemory"] = relationship("PlaybookMemory", back_populates="versions")

    def __repr__(self):
        return f"<PlaybookVersion v{self.version_number} status={self.status_at_version}>"
