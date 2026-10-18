"""
Asset repository — resource inventory, scoped to organization_id.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models.asset import Asset


def _utcnow():
    return datetime.now(timezone.utc)


class AssetRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert_many(self, organization_id: str, aws_account_db_id: str,
                           assets: list[dict]) -> int:
        """
        Upsert a batch of discovered assets. Existing (org, account,
        service, resource_id) rows get last_seen_at bumped; new ones are
        inserted. Uses each backend's native ON CONFLICT so a full scan's
        worth of assets can be written in one statement rather than N
        round trips.
        """
        if not assets:
            return 0

        now = _utcnow()
        rows = [{
            "id": uuid.uuid4().hex,
            "organization_id": organization_id,
            "aws_account_id": aws_account_db_id,
            "service": a["service"],
            "resource_type": a["resource_type"],
            "resource_id": a["resource_id"],
            "region": a["region"],
            "resource_metadata": a.get("metadata") or {},
            "first_seen_at": now,
            "last_seen_at": now,
        } for a in assets]

        dialect = self.db.bind.dialect.name if self.db.bind else "sqlite"
        insert_fn = pg_insert if dialect == "postgresql" else sqlite_insert
        stmt = insert_fn(Asset).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["organization_id", "aws_account_id", "service", "resource_id"],
            set_={
                "last_seen_at": stmt.excluded.last_seen_at,
                "resource_metadata": stmt.excluded.resource_metadata,
            },
        )
        await self.db.execute(stmt)
        await self.db.flush()
        return len(rows)

    async def list_for_org(self, organization_id: str, service: Optional[str] = None,
                            limit: int = 200, offset: int = 0) -> tuple[list[Asset], int]:
        where = [Asset.organization_id == organization_id]
        if service:
            where.append(Asset.service == service)

        count_result = await self.db.execute(
            select(func.count()).select_from(Asset).where(*where)
        )
        total = count_result.scalar_one()

        result = await self.db.execute(
            select(Asset).where(*where).order_by(Asset.service, Asset.resource_id)
            .offset(offset).limit(limit)
        )
        return list(result.scalars().all()), total

    async def count_by_service(self, organization_id: str) -> dict[str, int]:
        result = await self.db.execute(
            select(Asset.service, func.count())
            .where(Asset.organization_id == organization_id)
            .group_by(Asset.service)
        )
        return {service: count for service, count in result.all()}
