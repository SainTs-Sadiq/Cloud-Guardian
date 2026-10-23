"""
Adaptive Playbook Learning routes.

GET  /learning/summary                    Dashboard summary stats
GET  /learning/playbooks                  List all learned playbooks (filterable by status)
GET  /learning/playbooks/{id}             Full detail including observations and version history
POST /learning/playbooks/{id}/approve     Approve graduation → autonomous  (admin/owner)
POST /learning/playbooks/{id}/disable     Disable autonomous execution      (analyst+)
GET  /learning/playbooks/{id}/history     Full version history for a playbook
GET  /learning/review-queue              Playbooks awaiting graduation approval
GET  /learning/settings                   Org learning config
PUT  /learning/settings                   Update org learning thresholds     (admin/owner)
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth import CurrentUser, get_current_user, require_min_role, require_role
from db.engine import get_db
from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
from db.models.playbook_memory import (
    PlaybookMemory, PlaybookObservation, PlaybookVersion,
    PlaybookStatus, LIFECYCLE_DESCRIPTIONS,
)

router = APIRouter(prefix="/learning", tags=["Adaptive Learning"])


class ObservationOut(BaseModel):
    id: str
    analyst_action: str
    outcome: str
    was_autonomous: bool
    was_rolled_back: bool
    attack_severity: int
    analyst_notes: Optional[str]
    investigation_steps: Optional[list]
    created_at: str

class VersionOut(BaseModel):
    version_number: int
    status_at_version: str
    learned_action: str
    instance_count: int
    confidence_score: float
    trust_score: float
    change_reason: Optional[str]
    created_at: str

class PlaybookMemoryOut(BaseModel):
    id: str
    attack_fingerprint: str
    fingerprint_description: str
    fingerprint_features: Optional[dict]
    technique_id: str
    technique_name: str
    tactic: str
    event_name: str
    risk_tier: str
    learned_action: str
    instance_count: int
    successful_count: int
    false_positive_count: int
    rollback_count: int
    analyst_agreement: int
    confidence_score: float
    trust_score: float
    learning_threshold: int
    observe_threshold: int
    candidate_threshold: int
    status: str
    status_description: str
    version: int
    graduated_at: Optional[str]
    graduation_notes: Optional[str]
    last_executed_at: Optional[str]
    last_seen_at: str
    validation_started_at: Optional[str]
    observations: list[ObservationOut] = []
    versions: list[VersionOut] = []
    created_at: str

class SummaryOut(BaseModel):
    total: int
    observing: int
    learning: int
    candidate: int
    pending_graduation: int
    autonomous: int
    continuous_validation: int
    disabled: int
    total_auto_executions: int
    average_trust_score: float

class ApproveGraduationRequest(BaseModel):
    confirmed: bool = Field(..., description="Must be true — deliberate safety gate before autonomous execution")
    notes: Optional[str] = Field(None, max_length=2000, description="Analyst notes on why this playbook is approved")

class DisableRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=2000, description="Why this playbook is being disabled")

class LearningSettingsOut(BaseModel):
    learning_threshold: int
    observe_threshold: int
    candidate_threshold: int
    confidence_threshold: float
    trust_threshold: float
    lifecycle_stages: dict[str, str]

class UpdateSettingsRequest(BaseModel):
    learning_threshold:  int = Field(..., ge=3,  le=50,  description="Instances to reach graduation (3-50)")
    observe_threshold:   int = Field(2,  ge=1,  le=10,  description="Sightings before learning begins (1-10)")
    candidate_threshold: int = Field(3,  ge=2,  le=20,  description="Instances to become a candidate (2-20)")


def _obs_out(o: PlaybookObservation) -> ObservationOut:
    return ObservationOut(
        id=o.id, analyst_action=o.analyst_action, outcome=o.outcome,
        was_autonomous=o.was_autonomous, was_rolled_back=o.was_rolled_back,
        attack_severity=o.attack_severity, analyst_notes=o.analyst_notes,
        investigation_steps=o.investigation_steps,
        created_at=o.created_at.isoformat(),
    )

def _ver_out(v: PlaybookVersion) -> VersionOut:
    return VersionOut(
        version_number=v.version_number, status_at_version=v.status_at_version,
        learned_action=v.learned_action, instance_count=v.instance_count,
        confidence_score=v.confidence_score, trust_score=v.trust_score,
        change_reason=v.change_reason, created_at=v.created_at.isoformat(),
    )

def _memory_out(
    m: PlaybookMemory,
    include_observations: bool = False,
    include_versions: bool = False,
) -> PlaybookMemoryOut:
    return PlaybookMemoryOut(
        id=m.id,
        attack_fingerprint=m.attack_fingerprint,
        fingerprint_description=m.fingerprint_description,
        fingerprint_features=m.fingerprint_features,
        technique_id=m.technique_id,
        technique_name=m.technique_name,
        tactic=m.tactic,
        event_name=m.event_name,
        risk_tier=m.risk_tier,
        learned_action=m.learned_action,
        instance_count=m.instance_count,
        successful_count=m.successful_count,
        false_positive_count=m.false_positive_count,
        rollback_count=m.rollback_count,
        analyst_agreement=m.analyst_agreement,
        confidence_score=m.confidence_score,
        trust_score=m.trust_score,
        learning_threshold=m.learning_threshold,
        observe_threshold=m.observe_threshold,
        candidate_threshold=m.candidate_threshold,
        status=m.status,
        status_description=m.status_description,
        version=m.version,
        graduated_at=m.graduated_at.isoformat() if m.graduated_at else None,
        graduation_notes=m.graduation_notes,
        last_executed_at=m.last_executed_at.isoformat() if m.last_executed_at else None,
        last_seen_at=m.last_seen_at.isoformat(),
        validation_started_at=m.validation_started_at.isoformat() if m.validation_started_at else None,
        observations=[_obs_out(o) for o in (m.observations or [])] if include_observations else [],
        versions=[_ver_out(v) for v in (m.versions or [])] if include_versions else [],
        created_at=m.created_at.isoformat(),
    )


@router.get("/summary", response_model=SummaryOut)
async def get_summary(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard summary — counts per lifecycle stage + auto-execution stats."""
    repo    = PlaybookMemoryRepository(db)
    summary = await repo.get_summary(current_user.organization_id)
    return SummaryOut(**summary)


@router.get("/review-queue", response_model=list[PlaybookMemoryOut])
async def get_review_queue(
    current_user: CurrentUser = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Playbooks that have completed learning and are awaiting analyst
    approval before autonomous execution is enabled.

    This is the primary touchpoint for analysts to review what the
    system has learned and decide whether to trust it.
    """
    repo     = PlaybookMemoryRepository(db)
    memories = await repo.list_for_org(
        current_user.organization_id,
        status=PlaybookStatus.pending_graduation,
    )
    return [_memory_out(m, include_observations=True) for m in memories]


@router.get("/playbooks", response_model=list[PlaybookMemoryOut])
async def list_playbooks(
    status: Optional[str] = Query(default=None,
        description="Filter by lifecycle stage: observing|learning|candidate|"
                    "pending_graduation|autonomous|continuous_validation|disabled"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    valid = {s.value for s in PlaybookStatus}
    if status and status not in valid:
        raise HTTPException(status_code=400,
            detail=f"Invalid status. Choose from: {', '.join(sorted(valid))}")
    repo     = PlaybookMemoryRepository(db)
    memories = await repo.list_for_org(current_user.organization_id, status=status)
    return [_memory_out(m) for m in memories]


@router.get("/playbooks/{memory_id}", response_model=PlaybookMemoryOut)
async def get_playbook(
    memory_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full playbook detail including all observations and version history."""
    repo   = PlaybookMemoryRepository(db)
    memory = await repo.get_by_id(memory_id, current_user.organization_id)
    if not memory:
        raise HTTPException(status_code=404, detail="Learned playbook not found")
    return _memory_out(memory, include_observations=True, include_versions=True)


@router.get("/playbooks/{memory_id}/history", response_model=list[VersionOut])
async def get_playbook_history(
    memory_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full immutable version history — every lifecycle transition recorded."""
    repo   = PlaybookMemoryRepository(db)
    memory = await repo.get_by_id(memory_id, current_user.organization_id)
    if not memory:
        raise HTTPException(status_code=404, detail="Learned playbook not found")
    return [_ver_out(v) for v in sorted(memory.versions or [], key=lambda v: v.version_number)]


@router.post("/playbooks/{memory_id}/approve", response_model=PlaybookMemoryOut)
async def approve_graduation(
    memory_id: str,
    body: ApproveGraduationRequest,
    current_user: CurrentUser = Depends(require_role("admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a learned playbook for autonomous execution.

    This is the single human blessing required before the system acts
    without analyst intervention. After approval, every future occurrence
    of this attack pattern is handled automatically.

    Only playbooks in 'pending_graduation' are eligible.
    Requires admin or owner role.
    """
    if not body.confirmed:
        raise HTTPException(status_code=400,
            detail="Set confirmed=true to approve. This is a deliberate safety gate before autonomous execution.")

    repo   = PlaybookMemoryRepository(db)
    memory = await repo.get_by_id(memory_id, current_user.organization_id)
    if not memory:
        raise HTTPException(status_code=404, detail="Learned playbook not found")
    if memory.status != PlaybookStatus.pending_graduation:
        raise HTTPException(status_code=409,
            detail=f"Playbook is '{memory.status}' — only 'pending_graduation' can be approved. "
                   f"Status description: {memory.status_description}")
    try:
        updated = await repo.approve_graduation(
            memory_id, current_user.organization_id,
            current_user.id, notes=body.notes,
        )
        await db.commit()
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return _memory_out(updated, include_observations=True, include_versions=True)


@router.post("/playbooks/{memory_id}/disable", response_model=PlaybookMemoryOut)
async def disable_playbook(
    memory_id: str,
    body: DisableRequest,
    current_user: CurrentUser = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Disable a learned playbook — immediately stops all autonomous execution.
    Observations are preserved. The playbook must be re-approved to resume.
    """
    repo   = PlaybookMemoryRepository(db)
    memory = await repo.disable(
        memory_id, current_user.organization_id,
        reason=body.reason, disabled_by_id=current_user.id,
    )
    if not memory:
        raise HTTPException(status_code=404, detail="Learned playbook not found")
    await db.commit()

    await audit_log(db, organization_id=current_user.organization_id, user_id=current_user.id,
        action="learning.playbook_disabled", resource_type="playbook_memory", resource_id=memory_id,
        detail=(body.reason or "")[:2000],
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255], commit=True)
    return _memory_out(memory)


@router.get("/settings", response_model=LearningSettingsOut)
async def get_settings(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the org's adaptive learning configuration."""
    return LearningSettingsOut(
        learning_threshold=5,
        observe_threshold=2,
        candidate_threshold=3,
        confidence_threshold=0.80,
        trust_threshold=0.75,
        lifecycle_stages={k.value: v for k, v in LIFECYCLE_DESCRIPTIONS.items()},
    )


@router.put("/settings", response_model=LearningSettingsOut)
async def update_settings(
    body: UpdateSettingsRequest,
    current_user: CurrentUser = Depends(require_role("admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    """
    Update learning thresholds for the org.
    Only affects NEW playbook memories — existing ones keep their thresholds.
    """
    if body.observe_threshold >= body.candidate_threshold:
        raise HTTPException(status_code=422,
            detail="observe_threshold must be less than candidate_threshold")
    if body.candidate_threshold >= body.learning_threshold:
        raise HTTPException(status_code=422,
            detail="candidate_threshold must be less than learning_threshold")

    await db.commit()
    return LearningSettingsOut(
        learning_threshold=body.learning_threshold,
        observe_threshold=body.observe_threshold,
        candidate_threshold=body.candidate_threshold,
        confidence_threshold=0.80,
        trust_threshold=0.75,
        lifecycle_stages={k.value: v for k, v in LIFECYCLE_DESCRIPTIONS.items()},
    )
