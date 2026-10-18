"""
Dashboard routes — the standardized, org-wide views a frontend dashboard
needs, all in one consistent shape regardless of which scanner produced
a given finding.

GET /dashboard/summary       Top-line counts: findings by severity, accounts, last scan, risk score
GET /dashboard/assets        Resource inventory (every resource scanners have seen)
GET /dashboard/findings      Standardized findings list (paginated, filterable)
GET /dashboard/compliance    Compliance control coverage rollup (CIS/FSBP)
GET /dashboard/risk-score    Risk score detail with the full severity breakdown
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import CurrentUser, get_current_user
from db.engine import get_db
from db.models.aws_account import AWSAccount, AccountStatus
from db.models.incident import Incident
from db.repositories.incident_repo import IncidentRepository
from db.repositories.asset_repo import AssetRepository
from db.repositories.scan_run_repo import ScanRunRepository
from detection.compliance_mappings import COMPLIANCE_MAP
from detection.risk_score import compute_risk_score

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ─── Response models ────────────────────────────────────────────────────────

class StandardFinding(BaseModel):
    """
    The one shape every finding is returned in, regardless of which
    scanner (config_scan, cloudtrail, guardduty) produced it.
    """
    id: str
    service: Optional[str] = None
    resource_id: Optional[str] = None
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    title: str
    description: str
    recommendation: Optional[str] = None
    compliance: list[str] = []
    mitre: list[dict] = []
    status: str
    timestamp: str

class FindingsListResponse(BaseModel):
    findings: list[StandardFinding]
    total: int

class AssetResponse(BaseModel):
    id: str
    service: str
    resource_type: str
    resource_id: str
    region: str
    open_findings: int
    first_seen_at: str
    last_seen_at: str

class AssetsListResponse(BaseModel):
    assets: list[AssetResponse]
    total: int
    by_service: dict[str, int]

class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class LastScanSummary(BaseModel):
    id: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    findings_count: int

class DashboardSummaryResponse(BaseModel):
    total_findings: int
    open_findings: int
    findings_by_severity: SeverityCounts
    connected_accounts: int
    active_accounts: int
    total_assets: int
    last_scan: Optional[LastScanSummary] = None
    risk_posture_score: int
    risk_grade: str

class ComplianceControlRollup(BaseModel):
    control: str
    framework: str
    open_findings: int

class ComplianceServiceRollup(BaseModel):
    service: str
    total_assets: int
    assets_with_open_findings: int
    pass_rate: float

class ComplianceResponse(BaseModel):
    controls: list[ComplianceControlRollup]
    by_service: list[ComplianceServiceRollup]
    frameworks_covered: list[str]
    note: str = (
        "Control coverage is based on the checks Cloud Guardian currently runs, "
        "mapped to CIS AWS Foundations Benchmark and AWS FSBP control IDs. "
        "This is a coverage rollup, not a certified compliance audit."
    )

class RiskScoreResponse(BaseModel):
    risk_points: int
    posture_score: int
    grade: str
    breakdown: dict


def _severity_label(risk_tier: str) -> str:
    return (risk_tier or "low").upper()


def _finding_to_standard(incident: Incident) -> StandardFinding:
    return StandardFinding(
        id=incident.id,
        service=incident.service,
        resource_id=incident.resource_id,
        severity=_severity_label(incident.risk_tier),
        title=incident.title or incident.event_name,
        description=incident.description,
        recommendation=incident.recommendation,
        compliance=incident.compliance or [],
        mitre=[{
            "technique_id": incident.technique_id,
            "technique_name": incident.technique_name,
            "tactic": incident.tactic,
        }],
        status=incident.status,
        timestamp=incident.event_time.isoformat() if incident.event_time else incident.created_at.isoformat(),
    )


# ─── Endpoints ──────────────────────────────────────────────────────────────

@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Top-line org-wide counts for the main dashboard view."""
    org_id = current_user.organization_id
    incident_repo = IncidentRepository(db)
    asset_repo = AssetRepository(db)
    scan_run_repo = ScanRunRepository(db)

    total_findings = await incident_repo.count_total(org_id)
    open_findings = await incident_repo.count_open(org_id)
    severity_counts = await incident_repo.count_by_severity(org_id, open_only=True)

    account_counts = await db.execute(
        select(AWSAccount.status, func.count()).where(
            AWSAccount.organization_id == org_id
        ).group_by(AWSAccount.status)
    )
    by_status = {row[0]: row[1] for row in account_counts}
    connected_accounts = sum(by_status.values())
    active_accounts = by_status.get(AccountStatus.active, 0)

    _, total_assets = await asset_repo.list_for_org(org_id, limit=1)

    last_run = await scan_run_repo.last_run(org_id)
    last_scan = None
    if last_run:
        last_scan = LastScanSummary(
            id=last_run.id, status=last_run.status,
            started_at=last_run.started_at.isoformat(),
            completed_at=last_run.completed_at.isoformat() if last_run.completed_at else None,
            findings_count=last_run.findings_count,
        )

    risk = compute_risk_score(severity_counts)

    return DashboardSummaryResponse(
        total_findings=total_findings,
        open_findings=open_findings,
        findings_by_severity=SeverityCounts(**severity_counts),
        connected_accounts=connected_accounts,
        active_accounts=active_accounts,
        total_assets=total_assets,
        last_scan=last_scan,
        risk_posture_score=risk["posture_score"],
        risk_grade=risk["grade"],
    )


@router.get("/assets", response_model=AssetsListResponse)
async def get_dashboard_assets(
    service: Optional[str] = Query(default=None, description="Filter by service, e.g. S3, IAM, EC2"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resource inventory — every resource Cloud Guardian has scanned, not just ones with findings."""
    org_id = current_user.organization_id
    asset_repo = AssetRepository(db)
    incident_repo = IncidentRepository(db)

    assets, total = await asset_repo.list_for_org(org_id, service=service, limit=limit, offset=offset)
    by_service = await asset_repo.count_by_service(org_id)

    # Open-finding count per resource, so each asset card can show "clean" vs "N issues".
    open_fields = await incident_repo.list_open_compliance_fields(org_id)
    open_counts: dict[tuple, int] = {}
    for svc, resource_id, _compliance in open_fields:
        if svc and resource_id:
            key = (svc, resource_id)
            open_counts[key] = open_counts.get(key, 0) + 1

    return AssetsListResponse(
        assets=[
            AssetResponse(
                id=a.id, service=a.service, resource_type=a.resource_type,
                resource_id=a.resource_id, region=a.region,
                open_findings=open_counts.get((a.service, a.resource_id), 0),
                first_seen_at=a.first_seen_at.isoformat(),
                last_seen_at=a.last_seen_at.isoformat(),
            ) for a in assets
        ],
        total=total,
        by_service=by_service,
    )


@router.get("/findings", response_model=FindingsListResponse)
async def get_dashboard_findings(
    severity: Optional[str] = Query(default=None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    service: Optional[str] = Query(default=None, description="Filter by service, e.g. S3, IAM, EC2"),
    status: Optional[str] = Query(default=None, description="detected | remediated | false_positive | ..."),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Standardized findings list — one consistent shape for every scanner's output."""
    incident_repo = IncidentRepository(db)
    incidents, total = await incident_repo.list_for_org(
        organization_id=current_user.organization_id,
        limit=limit, offset=offset,
        risk_tier=severity.lower() if severity else None,
        status=status,
    )
    if service:
        incidents = [i for i in incidents if (i.service or "").lower() == service.lower()]

    return FindingsListResponse(
        findings=[_finding_to_standard(i) for i in incidents],
        total=total,
    )


@router.get("/compliance", response_model=ComplianceResponse)
async def get_dashboard_compliance(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compliance control coverage rollup. Two views:
      - controls: open-finding counts per CIS/FSBP control ID Cloud Guardian checks for
      - by_service: asset-level pass rate (resources with zero open findings / total resources)
    """
    org_id = current_user.organization_id
    incident_repo = IncidentRepository(db)
    asset_repo = AssetRepository(db)

    open_fields = await incident_repo.list_open_compliance_fields(org_id)

    control_counts: dict[str, int] = {}
    service_bad_resources: dict[str, set] = {}
    for service, resource_id, compliance in open_fields:
        for control in (compliance or []):
            control_counts[control] = control_counts.get(control, 0) + 1
        if service and resource_id:
            service_bad_resources.setdefault(service, set()).add(resource_id)

    frameworks = sorted({c.split(" ")[0] for c in control_counts} | {"CIS-AWS", "AWS-FSBP"})

    controls = [
        ComplianceControlRollup(control=control, framework=control.split(" ")[0], open_findings=count)
        for control, count in sorted(control_counts.items(), key=lambda kv: -kv[1])
    ]

    assets_by_service = await asset_repo.count_by_service(org_id)
    by_service = []
    for service, total_assets in assets_by_service.items():
        bad = len(service_bad_resources.get(service, set()))
        pass_rate = round(100.0 * (total_assets - bad) / total_assets, 1) if total_assets else 100.0
        by_service.append(ComplianceServiceRollup(
            service=service, total_assets=total_assets,
            assets_with_open_findings=bad, pass_rate=pass_rate,
        ))
    by_service.sort(key=lambda r: r.pass_rate)

    return ComplianceResponse(
        controls=controls, by_service=by_service, frameworks_covered=frameworks,
    )


@router.get("/risk-score", response_model=RiskScoreResponse)
async def get_dashboard_risk_score(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Risk score detail — see detection/risk_score.py for the formula.
    Weighted, capped, inverted count of OPEN findings by severity into a
    0-100 posture score (100 = best). Transparent by design: the full
    per-severity breakdown is included, not just the final number.
    """
    incident_repo = IncidentRepository(db)
    severity_counts = await incident_repo.count_by_severity(current_user.organization_id, open_only=True)
    return RiskScoreResponse(**compute_risk_score(severity_counts))
