"""
Usage tracking — counts alerts per org per billing period.

Used to:
  1. Enforce plan limits (reject scans/alerts above the monthly cap)
  2. Show usage in the billing dashboard
  3. Feed into Stripe metered billing if you add overage charges later

Storage: uses the same DB (incidents table count) so there's no separate
counter to keep in sync — the source of truth is always the incident rows.
"""
import logging
from datetime import datetime, timezone
from calendar import monthrange

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.incident import Incident

logger = logging.getLogger("cloud_guardian.billing.usage")


def _billing_period_start() -> datetime:
    """Returns the first day of the current UTC month at midnight."""
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _billing_period_end() -> datetime:
    """Returns the last moment of the current UTC month."""
    now = datetime.now(timezone.utc)
    last_day = monthrange(now.year, now.month)[1]
    return now.replace(day=last_day, hour=23, minute=59, second=59, microsecond=999999)


async def get_monthly_alert_count(db: AsyncSession, organization_id: str) -> int:
    """Count incidents created in the current billing period for an org."""
    period_start = _billing_period_start()
    result = await db.execute(
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.organization_id == organization_id,
            Incident.created_at >= period_start,
        )
    )
    return result.scalar_one() or 0


async def check_alert_limit(
    db: AsyncSession,
    organization_id: str,
    max_monthly_alerts: int,
) -> tuple[bool, int, int]:
    """
    Check whether the org has headroom to store more alerts.

    Returns (within_limit, current_count, max_allowed).
    """
    current = await get_monthly_alert_count(db, organization_id)
    return current < max_monthly_alerts, current, max_monthly_alerts


async def get_usage_summary(db: AsyncSession, organization_id: str) -> dict:
    """Return a full usage summary for the billing dashboard."""
    from db.models.aws_account import AWSAccount
    from sqlalchemy import select

    period_start = _billing_period_start()
    period_end   = _billing_period_end()


    alert_count = await get_monthly_alert_count(db, organization_id)


    acc_result = await db.execute(
        select(func.count())
        .select_from(AWSAccount)
        .where(AWSAccount.organization_id == organization_id)
    )
    account_count = acc_result.scalar_one() or 0


    for tier in ("critical", "high", "medium", "low"):
        pass

    return {
        "period_start": period_start.isoformat(),
        "period_end":   period_end.isoformat(),
        "alerts_this_month": alert_count,
        "aws_accounts_connected": account_count,
    }
