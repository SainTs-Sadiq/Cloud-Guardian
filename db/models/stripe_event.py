"""
ProcessedStripeEvent — dedupe ledger for Stripe webhooks.

Stripe can redeliver the same event (retries, replays). Each event id is
recorded once; a replay of an already-processed id is acknowledged without
re-applying the plan change.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from db.engine import Base


class ProcessedStripeEvent(Base):
    __tablename__ = "processed_stripe_events"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128))
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
