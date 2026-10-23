"""
Scan routes — trigger detection scans asynchronously via Celery.

POST /scan                  Dispatch a background scan, return job ID
GET  /scan/{job_id}         Poll job status
POST /scan/sync             Synchronous scan (dev/testing only, no Celery required)
"""
import os
import time
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from detection.cloudtrail_ingest import fetch_recent_events
from detection.guardduty_ingest import fetch_findings
from pydantic import BaseModel, Field
from sqlalchemy import select
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from api.models import ScanRequest, ScanResponse
from core.auth import CurrentUser, get_current_user
from db.engine import get_db
from db.models.aws_account import AWSAccount, AccountStatus
from db.models.organization import Organization
from config.settings import DETECTION

logger = logging.getLogger("cloud_guardian.api.scan")
router = APIRouter(prefix="/scan", tags=["Scan"])

REDIS_AVAILABLE = bool(os.environ.get("REDIS_URL"))


class ScanDispatchResponse(BaseModel):
    job_id: str
    scan_run_id: Optional[str] = None
    status: str = "queued"
    account_count: int
    message: str

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    result: Optional[dict] = None
    message: str

class ScanRunResponse(BaseModel):
    id: str
    status: str
    trigger: str
    accounts_targeted: int
    accounts_succeeded: int
    accounts_failed: int
    findings_count: int
    error_message: Optional[str] = None
    started_at: str
    completed_at: Optional[str] = None

class ScanRunListResponse(BaseModel):
    runs: list[ScanRunResponse]
    total: int


def _scan_run_to_response(run) -> ScanRunResponse:
    return ScanRunResponse(
        id=run.id, status=run.status, trigger=run.trigger,
        accounts_targeted=run.accounts_targeted, accounts_succeeded=run.accounts_succeeded,
        accounts_failed=run.accounts_failed, findings_count=run.findings_count,
        error_message=run.error_message,
        started_at=run.started_at.isoformat() if run.started_at else None,
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
    )


async def dispatch_scan_for_org(
    org_id: str,
    db: AsyncSession,
    minutes: int = 15,
    use_ml: bool = True,
    trigger: str = "manual",
) -> dict:
    """
    Dispatch (or synchronously run) a scan for all active AWS accounts in an org.

    Factored out so it can be called both from the POST /scan route and
    from the AWS-account verification flow (to kick off the "first scan"
    automatically the moment a role is verified — see
    api/routes/accounts.py::verify_account).

    Every dispatch gets a durable ScanRun row (db/models/scan_run.py) so
    scan history/last-successful/failed-scan queries work regardless of
    whether Redis is configured — Celery's AsyncResult alone isn't a
    history, it expires and requires Redis to poll at all.

    Returns a dict with one of:
      {"status": "skipped", "reason": "no_active_accounts", "account_count": 0}
      {"status": "queued", "job_id": ..., "scan_run_id": ..., "account_count": ...}
      {"status": "completed", "job_id": ..., "scan_run_id": ..., "account_count": ..., "alerts_found": ...}
    """
    from db.repositories.scan_run_repo import ScanRunRepository

    result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.organization_id == org_id,
            AWSAccount.status == AccountStatus.active,
        )
    )
    accounts = list(result.scalars().all())

    if not accounts:
        return {"status": "skipped", "reason": "no_active_accounts", "account_count": 0}

    scan_run_repo = ScanRunRepository(db)
    scan_run = await scan_run_repo.start(
        organization_id=org_id, trigger=trigger, accounts_targeted=len(accounts),
    )
    await db.commit()

    if REDIS_AVAILABLE:
        from workers.tasks import run_org_full_scan
        task = run_org_full_scan.apply_async(args=[org_id, minutes, scan_run.id])
        scan_run.celery_task_id = task.id
        await db.commit()
        return {
            "status": "queued", "job_id": task.id, "scan_run_id": scan_run.id,
            "account_count": len(accounts),
        }
    else:
        logger.warning("REDIS_URL not set — running scan synchronously. "
                       "Set REDIS_URL for production async execution.")
        try:
            job_id, alerts_found = await _run_sync_scan(
                accounts=accounts, org_id=org_id, db=db, lookback_minutes=minutes, use_ml=use_ml,
            )
            completed_run = await scan_run_repo.complete(
                scan_run.id, accounts_succeeded=len(accounts), accounts_failed=0,
                findings_count=alerts_found,
            )
        except Exception as e:
            logger.error(f"Sync scan failed for org {org_id}: {e}", exc_info=True)
            await scan_run_repo.fail(scan_run.id, str(e))
            await db.commit()
            raise
        await db.commit()

        if completed_run and alerts_found > 0:
            try:
                from core.notifications import send_scan_notification
                from db.repositories.incident_repo import IncidentRepository
                org = await db.get(Organization, org_id)
                severity_counts = await IncidentRepository(db).count_by_severity(org_id, open_only=True)
                await send_scan_notification(org, completed_run, severity_counts)
            except Exception as e:
                logger.warning(f"Scan notification failed for org {org_id}: {e}")

        return {
            "status": "completed", "job_id": job_id, "scan_run_id": scan_run.id,
            "account_count": len(accounts), "alerts_found": alerts_found,
        }


@router.post("", response_model=ScanDispatchResponse)
async def dispatch_scan(
    request: ScanRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Dispatch a background scan for all active AWS accounts in the org.

    Returns a job_id for polling via GET /scan/{job_id}.
    If Redis is not configured (REDIS_URL not set), falls back to
    synchronous execution automatically.
    """
    outcome = await dispatch_scan_for_org(
        org_id=current_user.organization_id, db=db,
        minutes=request.minutes, use_ml=request.use_ml,
    )

    if outcome["status"] == "skipped":
        raise HTTPException(
            status_code=422,
            detail="No active AWS accounts connected to your organization. "
                   "Add an account via the account onboarding flow first."
        )

    if outcome["status"] == "queued":
        return ScanDispatchResponse(
            job_id=outcome["job_id"],
            scan_run_id=outcome.get("scan_run_id"),
            status="queued",
            account_count=outcome["account_count"],
            message=f"Scan queued for {outcome['account_count']} account(s). "
                    f"Poll GET /scan/{outcome['job_id']} for status.",
        )
    else:
        return ScanDispatchResponse(
            job_id=outcome["job_id"],
            scan_run_id=outcome.get("scan_run_id"),
            status="completed",
            account_count=outcome["account_count"],
            message=f"Synchronous scan complete (no Redis configured). "
                    f"{outcome['alerts_found']} alert(s) found across "
                    f"{outcome['account_count']} account(s).",
        )


@router.get("/runs/last-successful", response_model=Optional[ScanRunResponse])
async def get_last_successful_scan(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Most recent scan that completed with no failed accounts (or partially), or null if none yet."""
    from db.repositories.scan_run_repo import ScanRunRepository
    run = await ScanRunRepository(db).last_successful(current_user.organization_id)
    return _scan_run_to_response(run) if run else None


@router.get("/runs", response_model=ScanRunListResponse)
async def get_scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated scan history for the org — durable regardless of Redis/Celery availability."""
    from db.repositories.scan_run_repo import ScanRunRepository
    runs, total = await ScanRunRepository(db).history(current_user.organization_id, limit, offset)
    return ScanRunListResponse(runs=[_scan_run_to_response(r) for r in runs], total=total)


@router.get("/runs/{run_id}", response_model=ScanRunResponse)
async def get_scan_run_detail(
    run_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Detail + live status for one scan run (works for both manual and scheduled runs)."""
    from db.repositories.scan_run_repo import ScanRunRepository
    run = await ScanRunRepository(db).get(run_id, current_user.organization_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return _scan_run_to_response(run)


@router.get("/{job_id}", response_model=JobStatusResponse)
async def get_scan_status(
    job_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Poll the status of a dispatched scan job.

    States: queued → started → success | failure
    Result is available when status == success.
    """
    if not REDIS_AVAILABLE:
        return JobStatusResponse(
            job_id=job_id, status="success",
            result={"note": "Sync mode — results already persisted"},
            message="Redis not configured. Scan ran synchronously at dispatch time.",
        )

    from celery.result import AsyncResult
    from workers.celery_app import app as celery_app

    result = AsyncResult(job_id, app=celery_app)
    status = result.status.lower()

    status_map = {
        "pending": "queued",
        "started": "started",
        "success": "success",
        "failure": "failure",
        "retry": "retrying",
    }
    mapped = status_map.get(status, status)

    task_result = None
    if result.ready():
        try:
            task_result = result.get(propagate=False)
            if isinstance(task_result, Exception):
                task_result = {"error": str(task_result)}
        except Exception as e:
            task_result = {"error": str(e)}

    return JobStatusResponse(
        job_id=job_id,
        status=mapped,
        result=task_result,
        message=f"Job {job_id} is {mapped}.",
    )


@router.post("/sync", response_model=ScanResponse)
async def sync_scan(
    request: ScanRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Synchronous scan — blocks until complete. For development/testing only.
    In production, use POST /scan (async) instead.
    """
    from detection.rule_engine import score_event
    from detection.storage import get_store

    store = get_store()
    start = time.time()
    alerts_found = 0

    try:
        ct_events = list(fetch_recent_events(lookback_minutes=request.minutes))
    except Exception as e:
        logger.error(f"CloudTrail fetch failed: {e}")
        ct_events = []

    for event in ct_events:
        alert = score_event(event)
        if alert and alert.severity >= DETECTION.alert_threshold:
            store.save(alert)
            alerts_found += 1

    try:
        gd_events = fetch_findings()
    except Exception as e:
        logger.error(f"GuardDuty fetch failed: {e}")
        gd_events = []

    for event in gd_events:
        alert = score_event(event)
        if alert and alert.severity >= DETECTION.alert_threshold:
            store.save(alert)
            alerts_found += 1

    elapsed = round(time.time() - start, 2)
    return ScanResponse(
        alerts_found=alerts_found,
        scan_duration_seconds=elapsed,
        lookback_minutes=request.minutes,
        message=f"Sync scan complete. {alerts_found} alert(s) in {elapsed}s.",
    )


_sync_scan_lock = asyncio.Lock()  # guards module-global client swaps in the sync path


async def _run_sync_scan(accounts, org_id, db, lookback_minutes, use_ml) -> tuple[str, int]:
    """Serialize sync scans: this path temporarily replaces module-global
    boto3 client factories, so concurrent scans could swap each other's
    customers' clients mid-flight (cross-tenant credential mixup)."""
    async with _sync_scan_lock:
        return await _run_sync_scan_locked(accounts, org_id, db, lookback_minutes, use_ml)


async def _run_sync_scan_locked(accounts, org_id, db, lookback_minutes, use_ml) -> tuple[str, int]:
    """
    Inline synchronous scan used when Redis isn't available (local/dev).

    Mirrors workers/tasks.py::run_account_scan for parity: assumes each
    account's IAM role via STS (no ambient/local credentials are used),
    scans CloudTrail + GuardDuty + configuration checks per region,
    persists incidents the same way the Celery path does, and updates
    each account's last_scan_at/status/last_error.

    This is async (awaits _persist_incidents directly) rather than
    spinning up a nested event loop, since it's already called from
    within the FastAPI request's running event loop.
    """
    import uuid
    from datetime import datetime, timezone
    from detection import cloudtrail_ingest, guardduty_ingest
    from detection.rule_engine import score_event
    from detection.config_scanner import run_config_scan, discover_assets
    from core.aws_session import get_session_for_account
    from workers.tasks import _persist_incidents, _persist_assets
    from db.models.aws_account import AccountStatus
    from config.settings import DETECTION

    job_id = str(uuid.uuid4())
    alerts_found = 0
    incidents_by_account: dict[str, list] = {}

    for account in accounts:
        try:
            session = get_session_for_account(
                role_arn=account.role_arn,
                external_id=account.external_id,
                region=account.primary_region,
                org_id=org_id,
                aws_account_id=account.aws_account_id,
            )
        except Exception as e:
            logger.error(f"Could not assume role for account {account.id}: {e}")
            account.status = AccountStatus.error
            account.last_error = str(e)
            continue

        acc_incidents = incidents_by_account.setdefault(account.id, [])
        regions = [account.primary_region] + (account.additional_regions or [])

        for region in regions:
            original_ct_client = cloudtrail_ingest.get_cloudtrail_client
            original_gd_client = guardduty_ingest._client
            cloudtrail_ingest.get_cloudtrail_client = lambda r=None: session.client("cloudtrail", region_name=region)
            guardduty_ingest._client = lambda r=None: session.client("guardduty", region_name=region)

            try:
                try:
                    for event in cloudtrail_ingest.fetch_recent_events(lookback_minutes=lookback_minutes):
                        alert = score_event(event)
                        if alert and alert.severity >= DETECTION.alert_threshold:
                            acc_incidents.append((alert, None))
                            alerts_found += 1
                except Exception as e:
                    logger.error(f"Sync scan CloudTrail error for {account.id}/{region}: {e}")

                try:
                    for event in guardduty_ingest.fetch_findings(region=region):
                        alert = score_event(event)
                        if alert and alert.severity >= DETECTION.alert_threshold:
                            acc_incidents.append((alert, None))
                            alerts_found += 1
                except Exception as e:
                    logger.error(f"Sync scan GuardDuty error for {account.id}/{region}: {e}")

                if DETECTION.config_scan_enabled:
                    try:
                        for alert in run_config_scan(session=session, region=region, account_id=account.aws_account_id):
                            if alert.severity >= DETECTION.alert_threshold:
                                acc_incidents.append((alert, None))
                                alerts_found += 1
                    except Exception as e:
                        logger.error(f"Sync config scan error for {account.id}/{region}: {e}")

                    try:
                        assets = discover_assets(session=session, region=region, account_id=account.aws_account_id)
                        if assets:
                            await _persist_assets(assets, account.id, org_id)
                    except Exception as e:
                        logger.error(f"Sync asset discovery error for {account.id}/{region}: {e}")
            finally:
                cloudtrail_ingest.get_cloudtrail_client = original_ct_client
                guardduty_ingest._client = original_gd_client

        account.last_scan_at = datetime.now(timezone.utc)
        account.last_error = None

    await db.commit()

    for acc_db_id, batch in incidents_by_account.items():
        if batch:
            await _persist_incidents(batch, acc_db_id, org_id)

    return job_id, alerts_found
