"""
Health and MITRE coverage routes.
Health is public (no auth). Coverage requires authentication.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.models import CoverageResponse, HealthResponse, TacticCoverage
from core.auth import CurrentUser, get_current_user
from db.engine import get_db
from db.repositories.incident_repo import IncidentRepository
from detection.cloudtrail_ingest import check_credentials
from detection.guardduty_ingest import list_active_detectors
from detection.mitre_mappings import EVENT_TECHNIQUE_MAP, all_tactics_summary
from config.settings import AWS, REMEDIATION, STORAGE

router = APIRouter(tags=["System"])
MODEL_PATH = "./data/anomaly_model.joblib"


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Public health check — no auth required. Used by load balancers and monitoring."""
    identity = check_credentials()

    cloudtrail_ok = False
    guardduty_ok = False
    if identity["ok"]:
        try:
            from detection.cloudtrail_ingest import fetch_recent_events
            list(fetch_recent_events(lookback_minutes=1))
            cloudtrail_ok = True
        except Exception:
            pass
        try:
            guardduty_ok = len(list_active_detectors()) > 0
        except Exception:
            pass

    api_status = ("no_credentials" if not identity["ok"]
                  else "degraded" if not cloudtrail_ok else "healthy")

    return HealthResponse(
        status=api_status,
        aws_account=identity.get("account"),
        aws_arn=identity.get("arn"),
        region=AWS.region,
        guardduty_enabled=guardduty_ok,
        cloudtrail_accessible=cloudtrail_ok,
        model_loaded=Path(MODEL_PATH).exists(),
        remediation_enabled=REMEDIATION.enabled,
        storage_backend="local_jsonl" if STORAGE.use_local_store else "dynamodb",
    )


@router.get("/coverage", response_model=CoverageResponse)
async def mitre_coverage(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """MITRE ATT&CK coverage + active alert count by tactic — org-scoped."""
    repo = IncidentRepository(db)
    tactic_counts = await repo.count_by_tactic(current_user.organization_id)
    tactic_technique_counts = all_tactics_summary()

    tactics = [
        TacticCoverage(
            tactic=tactic,
            technique_count=count,
            active_alerts=tactic_counts.get(tactic, 0),
        )
        for tactic, count in tactic_technique_counts.items()
        if count > 0
    ]
    tactics.sort(key=lambda t: t.active_alerts, reverse=True)

    total_active = sum(tactic_counts.values())

    return CoverageResponse(
        total_techniques_mapped=len(EVENT_TECHNIQUE_MAP),
        tactics=tactics,
        active_alert_count=total_active,
    )
