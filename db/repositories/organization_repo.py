"""
Organization repository — CRUD for orgs and plan management.
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.organization import Organization, PlanTier

PLAN_LIMITS = {
    PlanTier.free:       {"max_aws_accounts": 1,   "max_monthly_alerts": 100},
    PlanTier.starter:    {"max_aws_accounts": 3,   "max_monthly_alerts": 1_000},
    PlanTier.pro:        {"max_aws_accounts": 10,  "max_monthly_alerts": 10_000},
    PlanTier.enterprise: {"max_aws_accounts": 999, "max_monthly_alerts": 999_999},
}


class OrganizationRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, name: str, slug: str, billing_email: str,
                     plan: PlanTier = PlanTier.free) -> Organization:
        limits = PLAN_LIMITS[plan]
        org = Organization(
            name=name, slug=slug, billing_email=billing_email, plan=plan,
            **limits,
        )
        self.db.add(org)
        await self.db.flush()
        return org

    async def get_by_id(self, org_id: str) -> Organization | None:
        result = await self.db.execute(select(Organization).where(Organization.id == org_id))
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Organization | None:
        result = await self.db.execute(select(Organization).where(Organization.slug == slug))
        return result.scalar_one_or_none()

    async def update_plan(self, org_id: str, plan: PlanTier) -> Organization | None:
        org = await self.get_by_id(org_id)
        if org is None:
            return None
        limits = PLAN_LIMITS[plan]
        org.plan = plan
        org.max_aws_accounts = limits["max_aws_accounts"]
        org.max_monthly_alerts = limits["max_monthly_alerts"]
        await self.db.flush()
        return org

    async def list_all(self, limit: int = 100) -> list[Organization]:
        result = await self.db.execute(select(Organization).limit(limit))
        return list(result.scalars().all())
