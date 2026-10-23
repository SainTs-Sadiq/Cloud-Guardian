"""
Celery tasks — all detection and remediation work runs here, off the HTTP thread.

Task structure:
    run_account_scan(aws_account_id, org_id, lookback_minutes)
        → fetches CloudTrail + GuardDuty for ONE AWS account
        → scores events, persists Incidents to DB
        → queues execute_remediation for LOW-risk auto-actions

    run_org_full_scan(org_id)
        → fans out run_account_scan for every active AWSAccount in the org

    run_all_accounts_scan()
        → fans out run_org_full_scan for every active org (beat-triggered)

    execute_remediation(incident_id, org_id, approved_by_id=None)
        → executes the playbook action for a resolved incident
        → writes RemediationAction audit record

    retrain_anomaly_model(org_id)
        → pulls 14 days of history, retrains Isolation Forest, saves model

    retrain_all_models()
        → fans out retrain_anomaly_model for every active org
"""
import asyncio
import os
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from celery.utils.log import get_task_logger

from workers.celery_app import app

logger = get_task_logger(__name__)

MODEL_DIR = os.environ.get("CG_MODEL_DIR", "./data/models")


def _run_async(coro):
    """Run a coroutine synchronously inside a Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_aws_account(aws_account_db_id: str, org_id: str):
    """Load an AWSAccount record from DB."""
    from sqlalchemy import select
    from db.engine import AsyncSessionLocal
    from db.models.aws_account import AWSAccount
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AWSAccount).where(
                AWSAccount.id == aws_account_db_id,
                AWSAccount.organization_id == org_id,
            )
        )
        return result.scalar_one_or_none()


async def _get_active_accounts_for_org(org_id: str) -> list:
    from sqlalchemy import select
    from db.engine import AsyncSessionLocal
    from db.models.aws_account import AWSAccount, AccountStatus
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AWSAccount).where(
                AWSAccount.organization_id == org_id,
                AWSAccount.status == AccountStatus.active,
            )
        )
        return list(result.scalars().all())


async def _get_active_orgs() -> list:
    from sqlalchemy import select
    from db.engine import AsyncSessionLocal
    from db.models.organization import Organization
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Organization).where(Organization.is_active == True)
        )
        return list(result.scalars().all())


_FREQUENCY_INTERVALS = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
}


async def _due_orgs_for_scheduled_scan() -> list[tuple]:
    """
    Returns [(org, accounts_targeted), ...] for every active org whose
    scan_frequency isn't "manual" and whose last scan (of any trigger) is
    older than its configured interval — or which has never been scanned.
    """
    from sqlalchemy import select
    from db.engine import AsyncSessionLocal
    from db.models.aws_account import AWSAccount, AccountStatus
    from db.repositories.scan_run_repo import ScanRunRepository

    due = []
    async with AsyncSessionLocal() as db:
        orgs = await _get_active_orgs()
        scan_run_repo = ScanRunRepository(db)

        for org in orgs:
            interval = _FREQUENCY_INTERVALS.get(org.scan_frequency)
            if interval is None:  # "manual" (or unrecognized) -> never auto-scan
                continue

            result = await db.execute(
                select(AWSAccount).where(
                    AWSAccount.organization_id == org.id,
                    AWSAccount.status == AccountStatus.active,
                )
            )
            accounts = list(result.scalars().all())
            if not accounts:
                continue

            last_run = await scan_run_repo.last_run(org.id)
            if last_run is None:
                is_due = True
            else:
                started_at = last_run.started_at
                if started_at.tzinfo is None:
                    # SQLite's driver can drop tzinfo even for timezone=True
                    # columns; everything we write is UTC (see _utcnow()).
                    started_at = started_at.replace(tzinfo=timezone.utc)
                is_due = (datetime.now(timezone.utc) - started_at) >= interval
            if is_due:
                due.append((org, len(accounts)))

    return due


@app.task(
    bind=True,
    name="workers.tasks.run_account_scan",
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def run_account_scan(
    self,
    aws_account_db_id: str,
    org_id: str,
    lookback_minutes: int = 15,
    use_ml: bool = True,
    scan_run_id: Optional[str] = None,
):
    """
    Scan a single AWS account for security events.

    Uses cross-account STS to assume the customer's IAM role.
    Persists discovered incidents to DB.
    Auto-queues low-risk remediations.
    """
    logger.info(f"Starting scan: account={aws_account_db_id} org={org_id} lookback={lookback_minutes}m")

    try:
        account = _run_async(_get_aws_account(aws_account_db_id, org_id))
        if not account:
            logger.error(f"Account {aws_account_db_id} not found for org {org_id}")
            if scan_run_id:
                _run_async(_record_scan_run_result(scan_run_id, False, 0, "Account not found"))
            return {"status": "error", "detail": "Account not found"}


        from core.aws_session import get_session_for_account
        session = get_session_for_account(
            role_arn=account.role_arn,
            external_id=account.external_id,
            region=account.primary_region,
            org_id=org_id,
            aws_account_id=account.aws_account_id,
        )

        regions = [account.primary_region] + (account.additional_regions or [])
        all_alerts_found = 0

        for region in regions:
            alerts_found = _scan_region(
                session=session,
                region=region,
                aws_account_db_id=aws_account_db_id,
                aws_account_id=account.aws_account_id,
                org_id=org_id,
                lookback_minutes=lookback_minutes,
                use_ml=use_ml,
            )
            all_alerts_found += alerts_found


        _run_async(_update_account_scan_time(aws_account_db_id, org_id))
        if scan_run_id:
            _run_async(_record_scan_run_result(scan_run_id, True, all_alerts_found))

        logger.info(f"Scan complete: account={aws_account_db_id} alerts={all_alerts_found}")
        return {"status": "ok", "alerts_found": all_alerts_found, "account_id": aws_account_db_id}

    except PermissionError as e:

        logger.error(f"Permission error scanning account {aws_account_db_id}: {e}")
        _run_async(_update_account_error(aws_account_db_id, org_id, str(e)))
        if scan_run_id:
            _run_async(_record_scan_run_result(scan_run_id, False, 0, str(e)))
        return {"status": "permission_error", "detail": str(e)}

    except Exception as exc:
        logger.error(f"Scan failed for account {aws_account_db_id}: {exc}", exc_info=True)
        if scan_run_id and self.request.retries >= self.max_retries:
            _run_async(_record_scan_run_result(scan_run_id, False, 0, str(exc)))
        raise self.retry(exc=exc)


async def _record_scan_run_result(scan_run_id, success, findings_count, error_message=None):
    from db.engine import AsyncSessionLocal
    from db.repositories.scan_run_repo import ScanRunRepository
    async with AsyncSessionLocal() as db:
        repo = ScanRunRepository(db)
        finalized_run = await repo.record_account_result(scan_run_id, success, findings_count, error_message)

        if finalized_run and finalized_run.findings_count > 0:
            try:
                from core.notifications import send_scan_notification
                from db.repositories.incident_repo import IncidentRepository
                from db.models.organization import Organization
                org = await db.get(Organization, finalized_run.organization_id)
                if org:
                    severity_counts = await IncidentRepository(db).count_by_severity(
                        finalized_run.organization_id, open_only=True,
                    )
                    await send_scan_notification(org, finalized_run, severity_counts)
            except Exception as e:
                logger.warning(f"Scan notification failed for run {scan_run_id}: {e}")


def _scan_region(session, region, aws_account_db_id, aws_account_id, org_id, lookback_minutes, use_ml):
    """Inner: scan one region, persist results. Returns alert count."""

    from detection import cloudtrail_ingest, guardduty_ingest
    from detection.rule_engine import score_event
    from config.settings import DETECTION


    original_ct_client = cloudtrail_ingest.get_cloudtrail_client
    original_gd_client = guardduty_ingest._client
    cloudtrail_ingest.get_cloudtrail_client = lambda r=None: session.client("cloudtrail", region_name=region)
    guardduty_ingest._client = lambda r=None: session.client("guardduty", region_name=region)

    try:

        ct_events = list(cloudtrail_ingest.fetch_recent_events(lookback_minutes=lookback_minutes))


        detector = None
        actor_histories = {}
        if use_ml:
            model_path = Path(MODEL_DIR) / f"{org_id}.joblib"
            if model_path.exists():
                from ml.anomaly_detector import AnomalyDetector, build_actor_history
                try:
                    detector = AnomalyDetector.load(str(model_path))
                    actor_histories = build_actor_history(ct_events)
                except Exception as e:
                    logger.warning(f"Could not load anomaly model for org {org_id}: {e}")

        alerts_found = 0
        incidents_to_save = []

        for event in ct_events:
            ml_score = None
            if detector:
                from ml.anomaly_detector import extract_features
                history = actor_histories.get(event["actor"].get("arn", "unknown"))
                ml_score = detector.score(extract_features(event, actor_history=history))

            alert = score_event(event, ml_anomaly_score=ml_score)
            if alert and alert.severity >= DETECTION.alert_threshold:
                incidents_to_save.append((alert, ml_score))
                alerts_found += 1


        gd_events = guardduty_ingest.fetch_findings(region=region)
        for event in gd_events:
            alert = score_event(event)
            if alert and alert.severity >= DETECTION.alert_threshold:
                incidents_to_save.append((alert, None))
                alerts_found += 1

        if DETECTION.config_scan_enabled:
            from detection.config_scanner import run_config_scan, discover_assets
            try:
                config_alerts = run_config_scan(session=session, region=region, account_id=aws_account_id)
                for alert in config_alerts:
                    if alert.severity >= DETECTION.alert_threshold:
                        incidents_to_save.append((alert, None))
                        alerts_found += 1
            except Exception as e:
                logger.error(f"Config scan failed for {aws_account_id}/{region}: {e}", exc_info=True)

            try:
                assets = discover_assets(session=session, region=region, account_id=aws_account_id)
                if assets:
                    _run_async(_persist_assets(assets, aws_account_db_id, org_id))
            except Exception as e:
                logger.error(f"Asset discovery failed for {aws_account_id}/{region}: {e}", exc_info=True)

        if incidents_to_save:
            _run_async(_persist_incidents(incidents_to_save, aws_account_db_id, org_id))

        return alerts_found

    finally:

        cloudtrail_ingest.get_cloudtrail_client = original_ct_client
        guardduty_ingest._client = original_gd_client


async def _persist_assets(assets, aws_account_db_id, org_id):
    """Upsert discovered assets for the resource inventory (GET /dashboard/assets)."""
    from db.engine import AsyncSessionLocal
    from db.repositories.asset_repo import AssetRepository

    async with AsyncSessionLocal() as db:
        repo = AssetRepository(db)
        await repo.upsert_many(org_id, aws_account_db_id, assets)
        await db.commit()


async def _persist_incidents(incidents, aws_account_db_id, org_id):
    """Persist a batch of incidents and queue auto-remediations for low-risk ones."""
    from db.engine import AsyncSessionLocal
    from db.repositories.incident_repo import IncidentRepository
    from detection.playbooks import get_playbook
    from config.settings import REMEDIATION

    async with AsyncSessionLocal() as db:
        repo = IncidentRepository(db)
        for alert, ml_score in incidents:

            existing = await repo.get_by_event_id(alert.event_id, org_id)
            if existing:
                continue

            try:
                incident = await repo.create(
                    organization_id=org_id,
                    aws_account_db_id=aws_account_db_id,
                    event_id=alert.event_id,
                    source=alert.source,
                    event_name=alert.event_name,
                    event_time=alert.event_time if isinstance(alert.event_time, datetime)
                               else datetime.now(timezone.utc),
                    technique_id=alert.technique_id,
                    technique_name=alert.technique_name,
                    tactic=alert.tactic,
                    severity=alert.severity,
                    risk_tier=alert.risk_tier,
                    description=alert.description,
                    actor_arn=alert.actor_arn,
                    aws_region=alert.region,
                    source_ip=alert.source_ip,
                    modifiers=alert.modifiers,
                    ml_anomaly_score=ml_score,
                    service=getattr(alert, "service", None),
                    resource_id=getattr(alert, "resource_id", None),
                    title=getattr(alert, "title", None),
                    recommendation=getattr(alert, "recommendation", None),
                    compliance=getattr(alert, "compliance", None),
                )
            except IntegrityError:
                # concurrent worker inserted the same (org, event) first — dedup constraint won
                await db.rollback()
                continue
            await db.commit()


            if REMEDIATION.enabled:
                playbook = get_playbook(alert)
                if playbook and playbook.action_risk_tier.value in REMEDIATION.auto_approve_tiers:
                    execute_remediation.apply_async(
                        args=[incident.id, org_id],
                        kwargs={"auto": True},
                    )
                elif playbook:

                    from db.models.incident import IncidentStatus
                    await repo.update_status(incident.id, org_id, IncidentStatus.pending_approval)
                    await db.commit()


async def _update_account_scan_time(aws_account_db_id, org_id):
    from db.engine import AsyncSessionLocal
    from db.models.aws_account import AWSAccount, AccountStatus
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            __import__("sqlalchemy", fromlist=["select"]).select(AWSAccount)
            .where(AWSAccount.id == aws_account_db_id)
        )
        account = result.scalar_one_or_none()
        if account:
            account.last_scan_at = datetime.now(timezone.utc)
            account.status = AccountStatus.active
            account.last_error = None
            await db.commit()


async def _update_account_error(aws_account_db_id, org_id, error_msg):
    from db.engine import AsyncSessionLocal
    from db.models.aws_account import AWSAccount, AccountStatus
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            __import__("sqlalchemy", fromlist=["select"]).select(AWSAccount)
            .where(AWSAccount.id == aws_account_db_id)
        )
        account = result.scalar_one_or_none()
        if account:
            account.status = AccountStatus.error
            account.last_error = error_msg
            await db.commit()


@app.task(name="workers.tasks.run_org_full_scan")
def run_org_full_scan(org_id: str, lookback_minutes: int = 15, scan_run_id: Optional[str] = None):
    """Fan out scan tasks for every active AWS account in an org."""
    accounts = _run_async(_get_active_accounts_for_org(org_id))
    logger.info(f"Fanning out scan for org {org_id}: {len(accounts)} account(s)")
    for account in accounts:
        run_account_scan.apply_async(
            args=[account.id, org_id, lookback_minutes, True, scan_run_id],
        )
    return {"status": "dispatched", "account_count": len(accounts)}


@app.task(name="workers.tasks.run_all_accounts_scan")
def run_all_accounts_scan():
    """
    Beat-triggered (every 15 min — see workers/celery_app.py). Only
    actually dispatches a scan for orgs that are "due" per their
    scan_frequency setting (hourly/daily; "manual" orgs are skipped
    entirely and only scan via POST /scan or account verification).

    This is the standard way to support per-tenant variable cadence on
    top of one fixed-interval Celery Beat entry: check frequently, only
    act when each org's own interval has actually elapsed.
    """
    from db.engine import AsyncSessionLocal
    from db.repositories.scan_run_repo import ScanRunRepository

    async def _dispatch_due():
        due = await _due_orgs_for_scheduled_scan()
        dispatched = []
        async with AsyncSessionLocal() as db:
            scan_run_repo = ScanRunRepository(db)
            for org, accounts_targeted in due:
                run = await scan_run_repo.start(
                    organization_id=org.id, trigger="scheduled",
                    accounts_targeted=accounts_targeted,
                )
                await db.commit()
                dispatched.append((org.id, run.id))
        return dispatched

    dispatched = _run_async(_dispatch_due())
    logger.info(f"Scheduled scan check: {len(dispatched)} org(s) due")
    for org_id, scan_run_id in dispatched:
        run_org_full_scan.apply_async(args=[org_id, 15, scan_run_id])
    return {"status": "dispatched", "org_count": len(dispatched)}


@app.task(
    bind=True,
    name="workers.tasks.execute_remediation",
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
)
def execute_remediation(
    self,
    incident_id: str,
    org_id: str,
    approved_by_id: Optional[str] = None,
    auto: bool = False,
):
    """
    Execute the playbook remediation action for an incident.

    Called:
      - Automatically by _persist_incidents for LOW risk tier actions
      - From the API POST /remediation/{id}/approve for human approvals
        (the API handles approval logging; this task does the actual action)
    """
    logger.info(f"Executing remediation: incident={incident_id} org={org_id} auto={auto}")

    try:
        result = _run_async(_do_remediation(incident_id, org_id, approved_by_id, auto))
        return result
    except Exception as exc:
        # Fail-closed guard refusals are final: never retry them and never
        # log the raw credential/ARN text back out.
        from detection.remediation_actions import RemediationGuardError
        if isinstance(exc, RemediationGuardError):
            logger.error(f"Remediation refused for {incident_id} by guard")
            return {"status": "blocked", "detail": "remediation refused by fail-closed guard"}
        logger.error(f"Remediation task failed for {incident_id}: {type(exc).__name__}", exc_info=True)
        raise self.retry(exc=exc)


async def _load_account_for_incident(db, incident, org_id):
    """Return the AWSAccount linked to this incident, scoped to its org.
    Incident.aws_account_id stores the 12-digit AWS account number, which
    matches AWSAccount.aws_account_id. None if missing (caller fails closed)."""
    from sqlalchemy import select
    from db.models.aws_account import AWSAccount
    if not getattr(incident, "aws_account_id", None):
        return None
    res = await db.execute(
        select(AWSAccount).where(
            AWSAccount.aws_account_id == incident.aws_account_id,
            AWSAccount.organization_id == org_id,
        )
    )
    return res.scalar_one_or_none()


async def _do_remediation(incident_id, org_id, approved_by_id, auto):
    from db.engine import AsyncSessionLocal
    from db.repositories.incident_repo import IncidentRepository
    from db.models.incident import IncidentStatus
    from detection.playbooks import get_playbook
    from detection.rule_engine import DetectedAlert
    from detection import remediation_actions as actions

    async with AsyncSessionLocal() as db:
        repo = IncidentRepository(db)
        incident = await repo.get_by_id(incident_id, org_id)
        if not incident:
            return {"status": "error", "detail": f"Incident {incident_id} not found"}
        # The incident is linked to its AWS account by FK (aws_account_id).
        # Load the real account record; never trust a missing or guessed one.
        aws_account = await _load_account_for_incident(db, incident, org_id)

        alert = DetectedAlert(
            event_id=incident.event_id, source=incident.source,
            event_name=incident.event_name, event_time=incident.event_time,
            technique_id=incident.technique_id, technique_name=incident.technique_name,
            tactic=incident.tactic, severity=incident.severity, risk_tier=incident.risk_tier,
            description=incident.description, actor_arn=incident.actor_arn,
            account_id=aws_account.aws_account_id if aws_account else "",
            region=incident.aws_region,
            source_ip=incident.source_ip, modifiers=incident.modifiers or [], raw_event={},
        )

        playbook = get_playbook(alert)
        if not playbook:
            return {"status": "no_playbook"}

        handler = getattr(actions, playbook.action.value, None)
        is_destructive = playbook.action.value in getattr(actions, "DESTRUCTIVE_ACTIONS", set())
        if not handler:
            success, detail = False, f"No handler for {playbook.action.value}"
        elif auto and is_destructive:
            # Server-side guard: a misconfigured playbook can never route a
            # destructive handler through the auto path.
            logger.warning(f"[{alert.event_id}] BLOCKED auto-remediation of destructive handler")
            return {"status": "blocked", "detail": (
                f"Handler '{playbook.action.value}' is destructive and cannot "
                "run via auto-remediation; requires explicit human approval.")}
        elif not aws_account or not aws_account.role_arn:
            # Fail closed: no account row means no customer credentials to use.
            logger.error(f"Remediation blocked for incident {incident_id}: AWS account missing or has no role ARN")
            return {"status": "blocked", "detail": (
                "No active AWS account with a role ARN for this incident; "
                "refusing platform-credential remediation (fail-closed).")}
        else:
            from core.aws_session import get_session_for_account
            # Both roles must be registered before anything runs (fail-closed).
            # Auto runs use only the low-risk auto role; approved destructive
            # runs must have the destructive role too.
            auto_arn = aws_account.auto_remediation_role_arn
            destr_arn = aws_account.destructive_remediation_role_arn
            if not auto_arn:
                # Fail closed and return BEFORE creating any session.
                logger.error(
                    f"Remediation blocked for incident {incident_id}: no "
                    "auto_remediation_role_arn registered (fail-closed).")
                return {"status": "blocked", "detail": (
                    "No auto_remediation_role_arn registered for this AWS "
                    "account; refusing to run remediation on the detection "
                    "role (fail-closed).")}
            if not destr_arn:
                logger.error(
                    f"Remediation blocked for incident {incident_id}: no "
                    "destructive_remediation_role_arn registered (fail-closed).")
                return {"status": "blocked", "detail": (
                    "No destructive_remediation_role_arn registered for this "
                    "AWS account; remediation is refused (fail-closed).")}
            customer_session = get_session_for_account(
                role_arn=auto_arn, external_id=aws_account.external_id,
                region=aws_account.primary_region, org_id=org_id,
                aws_account_id=aws_account.aws_account_id,
            )
            destr_session = get_session_for_account(
                role_arn=destr_arn, external_id=aws_account.external_id,
                region=aws_account.primary_region, org_id=org_id,
                aws_account_id=aws_account.aws_account_id,
            ) if not auto else None
            # Per-call binding: sessions exist only for this handler call and
            # are reset on exit, so nothing leaks to the next task.
            with actions.remediation_sessions(auto=customer_session, destructive=destr_session):
                try:
                    success, detail = handler(alert)
                except actions.RemediationGuardError as guard:
                    logger.error(f"[{incident_id}] guard refused action: {guard}")
                    return {"status": "blocked", "detail": str(guard)}

        new_status = IncidentStatus.remediated if success else IncidentStatus.remediation_failed
        resolved_at = datetime.now(timezone.utc) if success else None
        await repo.update_status(incident_id, org_id, new_status, resolved_at=resolved_at)
        await repo.add_remediation_record(
            incident_id=incident_id, organization_id=org_id,
            action_type=playbook.action.value,
            action_risk_tier=playbook.action_risk_tier.value,
            decision="auto_executed" if auto else "approved",
            detail=detail, approved_by_id=approved_by_id,
            success=success,
        )
        await db.commit()

        logger.info(f"Remediation {'succeeded' if success else 'failed'}: {incident_id} — {detail}")
        return {"status": "ok", "success": success, "detail": detail}


@app.task(name="workers.tasks.retrain_anomaly_model")
def retrain_anomaly_model(org_id: str, days: int = 14):
    """
    Retrain the Isolation Forest anomaly model for one org using
    recent CloudTrail history from all their active accounts.
    """
    logger.info(f"Retraining anomaly model for org {org_id} ({days} days of history)")

    accounts = _run_async(_get_active_accounts_for_org(org_id))
    if not accounts:
        logger.warning(f"No active accounts for org {org_id} — skipping retrain")
        return {"status": "skipped", "reason": "no active accounts"}

    all_events = []
    for account in accounts:
        try:
            from core.aws_session import get_session_for_account
            from detection import cloudtrail_ingest

            session = get_session_for_account(
                role_arn=account.role_arn, external_id=account.external_id,
                region=account.primary_region, org_id=org_id,
                aws_account_id=account.aws_account_id,
            )
            original = cloudtrail_ingest.get_cloudtrail_client
            cloudtrail_ingest.get_cloudtrail_client = lambda r=None: session.client(
                "cloudtrail", region_name=account.primary_region)
            try:
                events = list(cloudtrail_ingest.fetch_recent_events(
                    lookback_minutes=days * 24 * 60))
                all_events.extend(events)
            finally:
                cloudtrail_ingest.get_cloudtrail_client = original
        except Exception as e:
            logger.warning(f"Could not fetch history from account {account.id}: {e}")

    if len(all_events) < 20:
        logger.warning(f"Only {len(all_events)} events for org {org_id} — need 20+ to retrain")
        return {"status": "skipped", "reason": "insufficient data", "event_count": len(all_events)}

    from ml.anomaly_detector import AnomalyDetector, build_actor_history, extract_features
    actor_histories = build_actor_history(all_events)
    rows = [
        extract_features(e, actor_history=actor_histories.get(e["actor"].get("arn", "unknown")))
        for e in all_events
    ]

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(rows)

    model_dir = Path(MODEL_DIR)
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / f"{org_id}.joblib"
    detector.save(str(model_path))

    logger.info(f"Model retrained for org {org_id}: {len(rows)} samples → {model_path}")
    return {"status": "ok", "samples": len(rows), "model_path": str(model_path)}


@app.task(name="workers.tasks.retrain_all_models")
def retrain_all_models():
    """Beat-triggered: retrain models for every active org."""
    orgs = _run_async(_get_active_orgs())
    for org in orgs:
        retrain_anomaly_model.apply_async(args=[org.id])
    return {"status": "dispatched", "org_count": len(orgs)}
