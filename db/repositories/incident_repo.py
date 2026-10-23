"""
Incident repository — all queries scoped to organization_id.

This is the production replacement for LocalJSONLStore / DynamoDBStore.
The rule engine output (DetectedAlert) maps directly to Incident rows.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from db.models.incident import Incident, IncidentStatus, RemediationAction
from db.models.user import User


class IncidentRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        organization_id: str,
        aws_account_db_id: str,
        event_id: str,
        source: str,
        event_name: str,
        event_time: datetime,
        technique_id: str,
        technique_name: str,
        tactic: str,
        severity: int,
        risk_tier: str,
        description: str,
        actor_arn: str,
        aws_region: str,
        source_ip: Optional[str] = None,
        modifiers: Optional[list[str]] = None,
        ml_anomaly_score: Optional[float] = None,
        service: Optional[str] = None,
        resource_id: Optional[str] = None,
        title: Optional[str] = None,
        recommendation: Optional[str] = None,
        compliance: Optional[list[str]] = None,
    ) -> Incident:
        incident = Incident(
            organization_id=organization_id,
            aws_account_id=aws_account_db_id,
            event_id=event_id,
            source=source,
            event_name=event_name,
            event_time=event_time,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            severity=severity,
            risk_tier=risk_tier,
            description=description,
            actor_arn=actor_arn,
            aws_region=aws_region,
            source_ip=source_ip,
            modifiers=modifiers or [],
            ml_anomaly_score=ml_anomaly_score,
            service=service,
            resource_id=resource_id,
            title=title,
            recommendation=recommendation,
            compliance=compliance or [],
        )
        self.db.add(incident)
        await self.db.flush()
        return incident

    async def get_by_id(self, incident_id: str, organization_id: str) -> Incident | None:
        """Always include organization_id in the WHERE clause — tenant isolation."""
        result = await self.db.execute(
            select(Incident)
            .where(Incident.id == incident_id, Incident.organization_id == organization_id)
            .options(selectinload(Incident.remediations))
        )
        incident = result.scalar_one_or_none()
        if incident is None:
            # Dashboard actions may pass the alert's event_id instead of the
            # incident UUID — resolve it, still tenant-scoped.
            result = await self.db.execute(
                select(Incident)
                .where(Incident.event_id == incident_id, Incident.organization_id == organization_id)
                .options(selectinload(Incident.remediations))
            )
            incident = result.scalar_one_or_none()
        return incident

    async def get_by_event_id(self, event_id: str, organization_id: str) -> Incident | None:
        result = await self.db.execute(
            select(Incident).where(
                Incident.event_id == event_id,
                Incident.organization_id == organization_id
            )
        )
        return result.scalar_one_or_none()

    async def list_for_org(
        self,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
        severity_min: int = 0,
        severity_max: int = 100,
        risk_tier: Optional[str] = None,
        tactic: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        service: Optional[str] = None,
    ) -> tuple[list[Incident], int]:
        """Return (incidents, total_count) with filtering. All scoped to org."""
        conditions = [
            Incident.organization_id == organization_id,
            Incident.severity >= severity_min,
            Incident.severity <= severity_max,
        ]
        if risk_tier:
            conditions.append(Incident.risk_tier == risk_tier)
        if tactic:
            conditions.append(Incident.tactic.ilike(f"%{tactic}%"))
        if status:
            conditions.append(Incident.status == status)
        if source:
            conditions.append(Incident.source == source)
        if service:
            conditions.append(Incident.service.ilike(service))

        where_clause = and_(*conditions)

        total_result = await self.db.execute(
            select(func.count()).select_from(Incident).where(where_clause)
        )
        total = total_result.scalar_one()

        result = await self.db.execute(
            select(Incident)
            .where(where_clause)
            .options(selectinload(Incident.remediations))
            .order_by(desc(Incident.created_at))
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all()), total

    async def update_status(
        self,
        incident_id: str,
        organization_id: str,
        status: IncidentStatus,
        resolved_at: Optional[datetime] = None,
        false_positive_reason: Optional[str] = None,
    ) -> Incident | None:
        incident = await self.get_by_id(incident_id, organization_id)
        if incident is None:
            return None
        incident.status = status
        if resolved_at:
            incident.resolved_at = resolved_at
        if false_positive_reason:
            incident.false_positive_reason = false_positive_reason
        await self.db.flush()
        return incident

    async def assign_to(self, incident_id: str, organization_id: str,
                        user_id: str) -> Incident | None:
        incident = await self.get_by_id(incident_id, organization_id)
        if incident is None:
            return None
        incident.assigned_to_id = user_id
        await self.db.flush()
        return incident

    async def count_by_tactic(self, organization_id: str) -> dict[str, int]:
        """For the MITRE coverage endpoint — active alerts per tactic."""
        result = await self.db.execute(
            select(Incident.tactic, func.count().label("cnt"))
            .where(
                Incident.organization_id == organization_id,
                Incident.status.not_in([
                    IncidentStatus.remediated,
                    IncidentStatus.false_positive,
                    IncidentStatus.suppressed,
                ])
            )
            .group_by(Incident.tactic)
        )
        return {row.tactic: row.cnt for row in result}

    _OPEN_STATUSES = [
        IncidentStatus.detected, IncidentStatus.pending_approval,
        IncidentStatus.remediating, IncidentStatus.remediation_failed,
    ]

    async def count_by_severity(self, organization_id: str, open_only: bool = True) -> dict[str, int]:
        """Open-finding counts per risk_tier — feeds /dashboard/summary and /dashboard/risk-score."""
        conditions = [Incident.organization_id == organization_id]
        if open_only:
            conditions.append(Incident.status.in_(self._OPEN_STATUSES))
        result = await self.db.execute(
            select(Incident.risk_tier, func.count().label("cnt"))
            .where(and_(*conditions))
            .group_by(Incident.risk_tier)
        )
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        counts.update({row.risk_tier: row.cnt for row in result})
        return counts

    async def count_open(self, organization_id: str) -> int:
        result = await self.db.execute(
            select(func.count()).select_from(Incident).where(
                Incident.organization_id == organization_id,
                Incident.status.in_(self._OPEN_STATUSES),
            )
        )
        return result.scalar_one()

    async def count_total(self, organization_id: str) -> int:
        result = await self.db.execute(
            select(func.count()).select_from(Incident)
            .where(Incident.organization_id == organization_id)
        )
        return result.scalar_one()

    async def list_open_compliance_fields(self, organization_id: str) -> list[tuple]:
        """Lightweight (service, resource_id, compliance) rows for open findings — used
        to compute the compliance rollup in Python rather than a JSON-column DB query
        (portable across SQLite/Postgres, and this isn't a hot path)."""
        result = await self.db.execute(
            select(Incident.service, Incident.resource_id, Incident.compliance)
            .where(
                Incident.organization_id == organization_id,
                Incident.status.in_(self._OPEN_STATUSES),
            )
        )
        return result.all()

    async def add_remediation_record(
        self,
        incident_id: str,
        organization_id: str,
        action_type: str,
        action_risk_tier: str,
        decision: str,
        detail: str,
        approved_by_id: Optional[str] = None,
        success: Optional[bool] = None,
        error_message: Optional[str] = None,
    ) -> RemediationAction:
        record = RemediationAction(
            organization_id=organization_id,
            incident_id=incident_id,
            action_type=action_type,
            action_risk_tier=action_risk_tier,
            decision=decision,
            detail=detail,
            approved_by_id=approved_by_id,
            success=success,
            error_message=error_message,
        )
        self.db.add(record)
        await self.db.flush()
        return record
