"""
Alert routes — scoped to the authenticated user's organization.

GET  /alerts          List recent alerts (org-scoped, filterable)
GET  /alerts/{id}     Full detail for a single alert
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.models import AlertDetail, AlertListResponse, AlertSummary
from core.auth import CurrentUser, get_current_user, require_min_role
from db.engine import get_db
from db.repositories.incident_repo import IncidentRepository

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity_min: int = Query(default=0, ge=0, le=100),
    severity_max: int = Query(default=100, ge=0, le=100),
    risk_tier: Optional[str] = Query(default=None),
    tactic: Optional[str] = Query(default=None),
    alert_status: Optional[str] = Query(default=None, alias="status"),
    source: Optional[str] = Query(default=None),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return alerts for the authenticated user's organization.
    All results are automatically scoped to their org — no cross-tenant leakage possible.
    """
    repo = IncidentRepository(db)
    incidents, total = await repo.list_for_org(
        organization_id=current_user.organization_id,
        limit=limit,
        offset=offset,
        severity_min=severity_min,
        severity_max=severity_max,
        risk_tier=risk_tier,
        tactic=tactic,
        status=alert_status,
        source=source,
    )

    filters_applied = {}
    if severity_min > 0 or severity_max < 100:
        filters_applied["severity"] = f"{severity_min}-{severity_max}"
    if risk_tier:
        filters_applied["risk_tier"] = risk_tier
    if tactic:
        filters_applied["tactic"] = tactic
    if alert_status:
        filters_applied["status"] = alert_status
    if source:
        filters_applied["source"] = source

    alerts = [AlertSummary(
        event_id=i.event_id,
        source=i.source,
        event_name=i.event_name,
        event_time=i.event_time.isoformat(),
        technique_id=i.technique_id,
        technique_name=i.technique_name,
        tactic=i.tactic,
        severity=i.severity,
        risk_tier=i.risk_tier,
        actor_arn=i.actor_arn,
        region=i.aws_region,
        status=i.status,
        remediation_action=(i.remediations[-1].action_type if i.remediations else None),
    ) for i in incidents]

    return AlertListResponse(alerts=alerts, total=total, filters_applied=filters_applied)


@router.get("/{incident_id}", response_model=AlertDetail)
async def get_alert(
    incident_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return full detail for a single alert.
    Returns 404 if the alert doesn't exist OR belongs to a different org.
    """
    repo = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id, current_user.organization_id)

    if incident is None:
        raise HTTPException(status_code=404, detail=f"Alert '{incident_id}' not found")

    return AlertDetail(
        event_id=incident.event_id,
        source=incident.source,
        event_name=incident.event_name,
        event_time=incident.event_time.isoformat(),
        technique_id=incident.technique_id,
        technique_name=incident.technique_name,
        tactic=incident.tactic,
        severity=incident.severity,
        risk_tier=incident.risk_tier,
        actor_arn=incident.actor_arn,
        region=incident.aws_region,
        status=incident.status,
        remediation_action=(incident.remediations[-1].action_type if incident.remediations else None),
        description=incident.description,
        account_id=incident.organization_id,
        source_ip=incident.source_ip,
        modifiers=incident.modifiers or [],
        stored_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
    )
