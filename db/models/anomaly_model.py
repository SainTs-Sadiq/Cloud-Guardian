"""
AnomalyModelRecord: durable store for trained anomaly models.

One row per organization (plus the global fallback row keyed "global").
The payload is the joblib-pickled model blob, plus an HMAC-SHA256 signature
over the blob keyed on SECRET_KEY. Loading verifies the signature before any
unpickling, so a tampered row is refused rather than executed (fail-closed).
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from db.engine import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AnomalyModelRecord(Base):
    __tablename__ = "anomaly_models"

    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False)
