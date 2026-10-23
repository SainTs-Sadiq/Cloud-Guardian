"""
Remediation routes — approval queue, action execution, and learning integration.
Every analyst action (approve/dismiss) is fed to the learning engine.
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models import AlertListResponse, AlertSummary, RemediationResponse
from core.audit import audit_log
from core.auth import CurrentUser, require_min_role, require_role
from config.settings import REMEDIATION
from db.engine import get_db
from db.models.aws_account import AWSAccount, AccountStatus
from db.models.incident import IncidentStatus
from db.repositories.incident_repo import IncidentRepository
from detection.playbooks import get_playbook
from detection.rule_engine import DetectedAlert
from detection import remediation_actions as actions
from learning.engine import record_analyst_action
import logging
logger = logging.getLogger("cloud_guardian.api.remediation")

router = APIRouter(prefix="/remediation", tags=["Remediation"])


class DismissRequest(BaseModel):
    reason: str
    analyst_notes: Optional[str] = None


class ApproveWithNotesRequest(BaseModel):
    confirmed: bool
    analyst_notes: Optional[str] = Field(default=None, max_length=2000)
    investigation_steps: Optional[list[str]] = Field(default=None, max_length=50)


def _rebuild_alert(incident) -> DetectedAlert:
    return DetectedAlert(
        event_id=incident.event_id, source=incident.source,
        event_name=incident.event_name, event_time=incident.event_time,
        technique_id=incident.technique_id, technique_name=incident.technique_name,
        tactic=incident.tactic, severity=incident.severity, risk_tier=incident.risk_tier,
        description=incident.description, actor_arn=incident.actor_arn,
        account_id=incident.aws_account_id or "", region=incident.aws_region,
        source_ip=incident.source_ip, modifiers=incident.modifiers or [], raw_event={},
    )


@router.get("/pending", response_model=AlertListResponse)
async def list_pending(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    repo = IncidentRepository(db)
    incidents, total = await repo.list_for_org(
        organization_id=current_user.organization_id,
        status="pending_approval", limit=limit, offset=offset,
    )
    alerts = [AlertSummary(
        event_id=i.event_id, source=i.source, event_name=i.event_name,
        event_time=i.event_time.isoformat(), technique_id=i.technique_id,
        technique_name=i.technique_name, tactic=i.tactic, severity=i.severity,
        risk_tier=i.risk_tier, actor_arn=i.actor_arn, region=i.aws_region,
        status=i.status,
        remediation_action=(i.remediations[-1].action_type if i.remediations else None),
    ) for i in incidents]
    return AlertListResponse(alerts=alerts, total=total,
                             filters_applied={"status": "pending_approval",
                                              "limit": limit, "offset": offset})


@router.post("/{incident_id}/approve", response_model=RemediationResponse)
async def approve_remediation(
    incident_id: str,
    request: Request,
    body: ApproveWithNotesRequest,
    current_user: CurrentUser = Depends(require_role("admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve and execute a pending remediation.

    Every approval is recorded by the adaptive learning engine —
    the system learns from each confirmed analyst decision.
    """
    if not body.confirmed:
        raise HTTPException(status_code=400,
            detail="Set confirmed=true to execute. This is a deliberate safety gate.")
    if not REMEDIATION.enabled:
        raise HTTPException(status_code=409,
            detail="Remediation is in dry-run mode. Set CG_REMEDIATION_ENABLED=true to enable.")

    repo     = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id, current_user.organization_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    if incident.status != IncidentStatus.pending_approval:
        raise HTTPException(status_code=409,
            detail=f"Incident is not pending approval (current status: {incident.status})")

    alert   = _rebuild_alert(incident)
    playbook = get_playbook(alert)
    if not playbook:
        raise HTTPException(status_code=422,
            detail=f"No playbook for technique {incident.technique_id}")

    handler = getattr(actions, playbook.action.value, None)
    if not handler:
        raise HTTPException(status_code=501,
            detail=f"Action '{playbook.action.value}' not implemented")

    # Fail-closed guards run OUTSIDE any broad except: a guard refusal is a
    # 409 the client can act on, never a swallowed 500.
    acct_result = await db.execute(
        select(AWSAccount).where(
            AWSAccount.organization_id == current_user.organization_id,
            AWSAccount.status == AccountStatus.active,
        ).limit(1)
    )
    aws_account = acct_result.scalar_one_or_none()
    if not aws_account or not aws_account.role_arn:
        raise HTTPException(status_code=409,
            detail="No active connected AWS account with a role ARN; refusing to run remediation on platform credentials.")
    # Both remediation roles must be registered before any session is built.
    if not aws_account.auto_remediation_role_arn:
        raise HTTPException(status_code=409,
            detail="No auto_remediation_role_arn registered for this AWS account; remediation is refused (fail-closed).")
    if not aws_account.destructive_remediation_role_arn:
        raise HTTPException(status_code=409,
            detail="No destructive_remediation_role_arn registered for this AWS account; remediation is refused (fail-closed).")

    from core.aws_session import get_session_for_account
    from detection import remediation_actions as _ra
    try:
        auto_session = get_session_for_account(
            role_arn=aws_account.auto_remediation_role_arn,
            external_id=aws_account.external_id,
            region=aws_account.primary_region, org_id=current_user.organization_id,
            aws_account_id=aws_account.aws_account_id,
        )
        destr_session = get_session_for_account(
            role_arn=aws_account.destructive_remediation_role_arn,
            external_id=aws_account.external_id,
            region=aws_account.primary_region, org_id=current_user.organization_id,
            aws_account_id=aws_account.aws_account_id,
        )
    except Exception as e:
        logger.error(f"Remediation session setup failed for {incident_id}: {type(e).__name__}", exc_info=True)
        raise HTTPException(status_code=500, detail="Remediation could not be started. See server logs.")

    # Per-call binding: the sessions exist only for this handler call.
    try:
        with _ra.remediation_sessions(auto=auto_session, destructive=destr_session):
            success, detail = handler(alert)
    except _ra.RemediationGuardError as guard:
        # Guard refused (e.g. destructive session missing): fail closed as 409.
        logger.warning(f"Remediation guard refused {incident_id}: {guard}")
        raise HTTPException(status_code=409,
            detail="Remediation refused by a fail-closed guard: a required remediation role session is not available.")
    except Exception as e:
        logger.error(f"Remediation failed for {incident_id}: {type(e).__name__}", exc_info=True)
        await repo.add_remediation_record(
            incident_id=incident_id, organization_id=current_user.organization_id,
            action_type=playbook.action.value, action_risk_tier=playbook.action_risk_tier.value,
            decision="auto_executed", detail="execution error (see server logs)",
            approved_by_id=current_user.id, success=False,
            error_message=type(e).__name__,
        )
        await repo.update_status(incident_id, current_user.organization_id,
                                 IncidentStatus.remediation_failed)
        raise HTTPException(status_code=500, detail="Remediation failed. See server logs.")

    new_status = IncidentStatus.remediated if success else IncidentStatus.remediation_failed
    await repo.update_status(incident_id, current_user.organization_id, new_status,
        resolved_at=datetime.now(timezone.utc) if success else None)
    await audit_log(db, organization_id=current_user.organization_id, user_id=current_user.id,
        action="remediation.approved", resource_type="incident", resource_id=incident_id,
        detail=f"action={playbook.action.value} success={success} {detail}"[:2000],
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255])
    await repo.add_remediation_record(
        incident_id=incident_id, organization_id=current_user.organization_id,
        action_type=playbook.action.value, action_risk_tier=playbook.action_risk_tier.value,
        decision="auto_executed", detail=detail, approved_by_id=current_user.id,
        success=success,
    )

    outcome = "success" if success else "false_positive"
    try:
        learning_result = await record_analyst_action(
            alert=alert,
            organization_id=current_user.organization_id,
            incident_id=incident_id,
            analyst_action=playbook.action.value,
            analyst_user_id=current_user.id,
            outcome=outcome,
            db=db,
            analyst_notes=body.analyst_notes,
            investigation_steps=body.investigation_steps,
        )
        await db.commit()
        logger.info(
            f"Learning recorded for {incident_id}: "
            f"pattern={learning_result['fingerprint'][:12]} "
            f"status={learning_result['status']} "
            f"trust={learning_result['trust_score']:.2f}"
        )
    except Exception as e:
        logger.warning(f"Learning engine record failed (non-fatal): {e}")
        await db.commit()

    return RemediationResponse(
        event_id=incident.event_id, decision="auto_executed",
        action=playbook.action.value,
        action_risk_tier=playbook.action_risk_tier.value,
        detail=detail,
        executed_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/{incident_id}/dismiss", response_model=RemediationResponse)
async def dismiss_incident(
    incident_id: str,
    body: DismissRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Dismiss as false positive. Also recorded by the learning engine —
    false positives lower the confidence and trust of matching patterns.
    """
    repo     = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id, current_user.organization_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    await repo.update_status(incident_id, current_user.organization_id,
        IncidentStatus.false_positive, false_positive_reason=body.reason)
    await audit_log(db, organization_id=current_user.organization_id, user_id=current_user.id,
        action="incident.dismissed", resource_type="incident", resource_id=incident_id,
        detail=(body.reason or "")[:2000],
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255])

    alert = _rebuild_alert(incident)
    try:
        await record_analyst_action(
            alert=alert,
            organization_id=current_user.organization_id,
            incident_id=incident_id,
            analyst_action="dismissed_false_positive",
            analyst_user_id=current_user.id,
            outcome="false_positive",
            db=db,
            analyst_notes=body.analyst_notes or body.reason,
        )
        await db.commit()
    except Exception as e:
        logger.warning(f"Learning engine record failed on dismiss (non-fatal): {e}")
        await db.commit()

    logger.info(f"[{incident_id}] Dismissed as false positive by {current_user.email}: {body.reason}")
    return RemediationResponse(
        event_id=incident.event_id, decision="false_positive",
        action=None, action_risk_tier=None,
        detail=f"Marked as false positive: {body.reason}",
        executed_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/{incident_id}/status", response_model=RemediationResponse)
async def get_remediation_status(
    incident_id: str,
    current_user: CurrentUser = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    repo     = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id, current_user.organization_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    last_action = incident.remediations[-1] if incident.remediations else None
    return RemediationResponse(
        event_id=incident.event_id, decision=incident.status,
        action=last_action.action_type if last_action else None,
        action_risk_tier=last_action.action_risk_tier if last_action else incident.risk_tier,
        detail=last_action.detail if last_action else f"Current status: {incident.status}",
        executed_at=(last_action.executed_at.isoformat() if last_action
                     else incident.updated_at.isoformat()),
    )
