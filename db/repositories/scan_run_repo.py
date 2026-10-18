"""
ScanRun repository — durable scan lifecycle tracking, scoped to organization_id.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.scan_run import ScanRun, ScanRunStatus, ScanTrigger


def _utcnow():
    return datetime.now(timezone.utc)


class ScanRunRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def start(self, organization_id: str, trigger: str = ScanTrigger.manual,
                     accounts_targeted: int = 0, celery_task_id: Optional[str] = None) -> ScanRun:
        run = ScanRun(
            organization_id=organization_id,
            trigger=trigger,
            status=ScanRunStatus.running,
            accounts_targeted=accounts_targeted,
            celery_task_id=celery_task_id,
        )
        self.db.add(run)
        await self.db.flush()
        return run

    async def complete(self, run_id: str, *, accounts_succeeded: int, accounts_failed: int,
                        findings_count: int, error_message: Optional[str] = None) -> Optional[ScanRun]:
        run = await self.db.get(ScanRun, run_id)
        if run is None:
            return None
        run.accounts_succeeded = accounts_succeeded
        run.accounts_failed = accounts_failed
        run.findings_count = findings_count
        run.completed_at = _utcnow()
        if accounts_failed == 0:
            run.status = ScanRunStatus.success
        elif accounts_succeeded > 0:
            run.status = ScanRunStatus.partial
        else:
            run.status = ScanRunStatus.failed
        run.error_message = error_message
        await self.db.flush()
        return run

    async def fail(self, run_id: str, error_message: str) -> Optional[ScanRun]:
        run = await self.db.get(ScanRun, run_id)
        if run is None:
            return None
        run.status = ScanRunStatus.failed
        run.error_message = error_message
        run.completed_at = _utcnow()
        await self.db.flush()
        return run

    async def get(self, run_id: str, organization_id: str) -> Optional[ScanRun]:
        result = await self.db.execute(
            select(ScanRun).where(ScanRun.id == run_id, ScanRun.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def history(self, organization_id: str, limit: int = 20, offset: int = 0) -> tuple[list[ScanRun], int]:
        from sqlalchemy import func
        count_result = await self.db.execute(
            select(func.count()).select_from(ScanRun).where(ScanRun.organization_id == organization_id)
        )
        total = count_result.scalar_one()

        result = await self.db.execute(
            select(ScanRun)
            .where(ScanRun.organization_id == organization_id)
            .order_by(desc(ScanRun.started_at))
            .offset(offset).limit(limit)
        )
        return list(result.scalars().all()), total

    async def last_successful(self, organization_id: str) -> Optional[ScanRun]:
        result = await self.db.execute(
            select(ScanRun)
            .where(ScanRun.organization_id == organization_id,
                   ScanRun.status.in_([ScanRunStatus.success, ScanRunStatus.partial]))
            .order_by(desc(ScanRun.completed_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def last_run(self, organization_id: str) -> Optional[ScanRun]:
        result = await self.db.execute(
            select(ScanRun)
            .where(ScanRun.organization_id == organization_id)
            .order_by(desc(ScanRun.started_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def record_account_result(self, run_id: str, success: bool,
                                     findings_count: int = 0,
                                     error_message: Optional[str] = None) -> Optional[ScanRun]:
        """
        Atomically record one account's contribution to a fanned-out scan
        (the Celery path dispatches N run_account_scan tasks per ScanRun;
        each calls this on completion). Uses an atomic SQL increment
        rather than read-modify-write, since multiple workers can finish
        at nearly the same instant. Marks the run success/partial/failed
        once every targeted account has reported in.

        Returns the ScanRun if this call just finalized it (so the caller
        can react — e.g. send a notification), or None if the run is
        still in progress or was already finalized.
        """
        from sqlalchemy import update
        if success:
            await self.db.execute(
                update(ScanRun).where(ScanRun.id == run_id)
                .values(accounts_succeeded=ScanRun.accounts_succeeded + 1,
                        findings_count=ScanRun.findings_count + findings_count)
            )
        else:
            await self.db.execute(
                update(ScanRun).where(ScanRun.id == run_id)
                .values(accounts_failed=ScanRun.accounts_failed + 1,
                        error_message=error_message)
            )
        await self.db.commit()

        run = await self.db.get(ScanRun, run_id)
        if not run or run.status != ScanRunStatus.running:
            return None
        if (run.accounts_succeeded + run.accounts_failed) >= run.accounts_targeted:
            if run.accounts_failed == 0:
                run.status = ScanRunStatus.success
            elif run.accounts_succeeded > 0:
                run.status = ScanRunStatus.partial
            else:
                run.status = ScanRunStatus.failed
            run.completed_at = _utcnow()
            await self.db.commit()
            return run
        return None
