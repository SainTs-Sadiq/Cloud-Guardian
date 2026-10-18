import logging
from datetime import timezone, datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from detection.rule_engine import DetectedAlert
from detection import remediation_actions as actions
from db.models.playbook_memory import PlaybookStatus
from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
from learning.fingerprint import build_fingerprint

logger = logging.getLogger("cloud_guardian.learning.engine")


class LearningEngineResult:
    def __init__(self, action: str, was_autonomous: bool, detail: str,
                 memory_id: Optional[str], status: str, trust_score: float = 0.0):
        self.action         = action
        self.was_autonomous = was_autonomous
        self.detail         = detail
        self.memory_id      = memory_id
        self.status         = status
        self.trust_score    = trust_score


async def check_and_apply_learned_playbook(
    alert: DetectedAlert,
    organization_id: str,
    db: AsyncSession,
) -> Optional[LearningEngineResult]:
    """
    Check whether a fully autonomous learned playbook exists for this alert.
    Only fires for memories in 'autonomous' status — all other stages are
    still in observation / approval mode and will not auto-execute.

    Returns LearningEngineResult if a learned playbook executed, else None.
    """
    fp_hash, fp_desc, fp_features = build_fingerprint(alert)
    repo   = PlaybookMemoryRepository(db)
    memory = await repo.get_by_fingerprint(fp_hash, organization_id)

    if not memory:
        return None

    if memory.status != PlaybookStatus.autonomous:
        logger.debug(
            f"[{fp_hash[:12]}] learned playbook exists (status={memory.status}) "
            f"— not autonomous yet, skipping auto-execution"
        )
        return None

    handler = getattr(actions, memory.learned_action, None)
    if handler is None:
        logger.error(f"Learned action '{memory.learned_action}' has no handler implementation")
        return None

    logger.info(
        f"[{fp_hash[:12]}] AUTONOMOUS execution: {memory.learned_action} "
        f"(trust={memory.trust_score:.2f} confidence={memory.confidence_score:.2f} "
        f"instances={memory.instance_count})"
    )

    try:
        success, detail = handler(alert)
        outcome = "success" if success else "false_positive"
    except Exception as e:
        logger.error(f"Learned playbook execution raised: {e}", exc_info=True)
        success, detail, outcome = False, f"Execution error: {e}", "false_positive"

    await repo.record_observation(
        memory=memory,
        organization_id=organization_id,
        incident_id=None,
        analyst_action=memory.learned_action,
        analyst_user_id=None,
        outcome=outcome,
        attack_severity=alert.severity,
        was_autonomous=True,
        attack_context=fp_features,
    )
    await repo.mark_executed(memory)

    if not success:
        logger.warning(
            f"[{fp_hash[:12]}] Autonomous execution failed. "
            f"New trust={memory.trust_score:.2f} confidence={memory.confidence_score:.2f}"
        )
        if memory.status == PlaybookStatus.continuous_validation:
            logger.warning(
                f"[{fp_hash[:12]}] Moved to continuous_validation — "
                f"outcomes under re-evaluation"
            )

    return LearningEngineResult(
        action=memory.learned_action,
        was_autonomous=True,
        detail=detail,
        memory_id=memory.id,
        status="executed" if success else "failed",
        trust_score=memory.trust_score,
    )


async def record_analyst_action(
    alert: DetectedAlert,
    organization_id: str,
    incident_id: str,
    analyst_action: str,
    analyst_user_id: str,
    outcome: str,
    db: AsyncSession,
    org_learning_threshold: int = 5,
    org_observe_threshold: int = 2,
    org_candidate_threshold: int = 3,
    analyst_notes: Optional[str] = None,
    investigation_steps: Optional[list] = None,
    was_rolled_back: bool = False,
) -> dict:
    """
    Record an analyst's remediation decision and advance the learning lifecycle.

    Called when an analyst:
      - Approves a remediation (POST /remediation/{id}/approve)
      - Dismisses as false positive (POST /remediation/{id}/dismiss)

    The system learns the action + context, computes updated confidence
    and trust scores, and advances the lifecycle stage automatically.
    """
    fp_hash, fp_desc, fp_features = build_fingerprint(alert)
    repo   = PlaybookMemoryRepository(db)
    memory = await repo.get_by_fingerprint(fp_hash, organization_id)

    is_new = memory is None
    if is_new:
        memory = await repo.create(
            organization_id         = organization_id,
            attack_fingerprint      = fp_hash,
            fingerprint_description = fp_desc,
            technique_id            = alert.technique_id,
            technique_name          = alert.technique_name,
            tactic                  = alert.tactic,
            event_name              = alert.event_name,
            risk_tier               = alert.risk_tier,
            learned_action          = analyst_action,
            learning_threshold      = org_learning_threshold,
            observe_threshold       = org_observe_threshold,
            candidate_threshold     = org_candidate_threshold,
            fingerprint_features    = fp_features,
        )
        logger.info(
            f"[NEW] Playbook memory created for {fp_hash[:16]}: "
            f"{alert.technique_id} — {analyst_action}"
        )

    prev_status = memory.status
    await repo.record_observation(
        memory              = memory,
        organization_id     = organization_id,
        incident_id         = incident_id,
        analyst_action      = analyst_action,
        analyst_user_id     = analyst_user_id,
        outcome             = outcome,
        attack_severity     = alert.severity,
        was_autonomous      = False,
        was_rolled_back     = was_rolled_back,
        attack_context      = fp_features,
        analyst_notes       = analyst_notes,
        investigation_steps = investigation_steps,
    )

    status_changed = memory.status != prev_status
    remaining      = max(0, memory.learning_threshold - memory.instance_count)

    result = {
        "memory_id":         memory.id,
        "fingerprint":       fp_hash,
        "description":       fp_desc,
        "is_new_pattern":    is_new,
        "instance_count":    memory.instance_count,
        "confidence_score":  memory.confidence_score,
        "trust_score":       memory.trust_score,
        "status":            memory.status,
        "status_changed":    status_changed,
        "previous_status":   prev_status if status_changed else None,
        "remaining_to_threshold": remaining,
    }

    _add_status_message(result, memory, remaining)
    return result


def _add_status_message(result: dict, memory, remaining: int) -> None:
    s = memory.status

    if s == PlaybookStatus.observing:
        result["message"] = (
            f"Observing — {memory.instance_count}/{memory.observe_threshold} "
            f"initial sightings recorded."
        )
    elif s == PlaybookStatus.learning:
        result["message"] = (
            f"Learning — {memory.instance_count} observations collected. "
            f"{remaining} more needed to become a candidate."
        )
    elif s == PlaybookStatus.candidate:
        result["message"] = (
            f"Candidate — building confidence and trust. "
            f"Confidence: {memory.confidence_score:.0%} | "
            f"Trust: {memory.trust_score:.0%}. "
            f"Needs ≥80% on both to progress."
        )
    elif s == PlaybookStatus.pending_graduation:
        result["message"] = (
            f"Ready for graduation! {memory.instance_count} confirmed instances, "
            f"confidence {memory.confidence_score:.0%}, "
            f"trust {memory.trust_score:.0%}. "
            f"Awaiting admin/owner approval to enable autonomous execution."
        )
    elif s == PlaybookStatus.autonomous:
        result["message"] = (
            f"Autonomous — this pattern will be handled automatically. "
            f"Trust score: {memory.trust_score:.0%}."
        )
    elif s == PlaybookStatus.continuous_validation:
        result["message"] = (
            f"Under review — trust dropped below threshold "
            f"({memory.trust_score:.0%}). Re-evaluating outcomes."
        )
