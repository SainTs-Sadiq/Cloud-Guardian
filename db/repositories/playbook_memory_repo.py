import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from db.models.playbook_memory import (
    PlaybookMemory, PlaybookObservation, PlaybookVersion, PlaybookStatus
)

logger = logging.getLogger("cloud_guardian.learning.repo")

AUTONOMOUS_CONFIDENCE_THRESHOLD = 0.80
AUTONOMOUS_TRUST_THRESHOLD      = 0.75
REVERSION_TRUST_THRESHOLD       = 0.50


class PlaybookMemoryRepository:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_fingerprint(self, fingerprint: str, org_id: str) -> Optional[PlaybookMemory]:
        result = await self.db.execute(
            select(PlaybookMemory)
            .where(
                PlaybookMemory.attack_fingerprint == fingerprint,
                PlaybookMemory.organization_id    == org_id,
                PlaybookMemory.status             != PlaybookStatus.disabled,
            )
            .options(selectinload(PlaybookMemory.observations))
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, memory_id: str, org_id: str) -> Optional[PlaybookMemory]:
        result = await self.db.execute(
            select(PlaybookMemory)
            .where(
                PlaybookMemory.id              == memory_id,
                PlaybookMemory.organization_id == org_id,
            )
            .options(
                selectinload(PlaybookMemory.observations),
                selectinload(PlaybookMemory.versions),
            )
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        organization_id: str,
        attack_fingerprint: str,
        fingerprint_description: str,
        technique_id: str,
        technique_name: str,
        tactic: str,
        event_name: str,
        risk_tier: str,
        learned_action: str,
        learning_threshold: int = 5,
        observe_threshold:  int = 2,
        candidate_threshold:int = 3,
        fingerprint_features: Optional[dict] = None,
    ) -> PlaybookMemory:
        memory = PlaybookMemory(
            organization_id         = organization_id,
            attack_fingerprint      = attack_fingerprint,
            fingerprint_description = fingerprint_description,
            fingerprint_features    = fingerprint_features,
            technique_id            = technique_id,
            technique_name          = technique_name,
            tactic                  = tactic,
            event_name              = event_name,
            risk_tier               = risk_tier,
            learned_action          = learned_action,
            learning_threshold      = learning_threshold,
            observe_threshold       = observe_threshold,
            candidate_threshold     = candidate_threshold,
            status                  = PlaybookStatus.observing,
            version                 = 1,
        )
        self.db.add(memory)
        await self.db.flush()
        await self._snapshot_version(memory, reason="Created — initial observation")
        return memory

    async def record_observation(
        self,
        memory: PlaybookMemory,
        organization_id: str,
        incident_id: Optional[str],
        analyst_action: str,
        analyst_user_id: Optional[str],
        outcome: str,
        attack_severity: int,
        was_autonomous: bool = False,
        was_rolled_back: bool = False,
        attack_context: Optional[dict] = None,
        analyst_notes: Optional[str] = None,
        investigation_steps: Optional[list] = None,
    ) -> PlaybookObservation:
        obs = PlaybookObservation(
            organization_id     = organization_id,
            memory_id           = memory.id,
            incident_id         = incident_id,
            analyst_action      = analyst_action,
            analyst_user_id     = analyst_user_id,
            analyst_notes       = analyst_notes,
            outcome             = outcome,
            was_autonomous      = was_autonomous,
            was_rolled_back     = was_rolled_back,
            attack_severity     = attack_severity,
            attack_context      = attack_context,
            investigation_steps = investigation_steps,
        )
        self.db.add(obs)

        memory.instance_count += 1
        memory.last_seen_at    = datetime.now(timezone.utc)

        if outcome == "success":
            memory.successful_count += 1
            if not was_autonomous:
                memory.analyst_agreement += 1
        elif outcome == "false_positive":
            memory.false_positive_count += 1
        if was_rolled_back:
            memory.rollback_count += 1

        memory.learned_action  = analyst_action
        memory.confidence_score = self._compute_confidence(memory)
        memory.trust_score      = self._compute_trust(memory)

        prev_status = memory.status
        await self._advance_lifecycle(memory)

        if memory.status != prev_status or memory.confidence_score != memory.confidence_score:
            memory.version += 1
            await self._snapshot_version(
                memory,
                reason=f"Status: {prev_status} → {memory.status}",
                changed_by_id=analyst_user_id,
            )

        await self.db.flush()
        return obs

    def _compute_confidence(self, memory: PlaybookMemory) -> float:
        if memory.instance_count == 0:
            return 0.0
        weighted = memory.successful_count * 1.0 - memory.false_positive_count * 2.0
        return round(max(0.0, min(1.0, weighted / memory.instance_count)), 4)

    def _compute_trust(self, memory: PlaybookMemory) -> float:
        """
        Trust Score — composite of four signals per the document recommendation:
          1. Similarity score   (confidence across confirmed similar attacks)  30%
          2. Success rate       (successful / total non-false-positive)        30%
          3. Rollback rate      (inverted — lower rollbacks = higher trust)    20%
          4. Analyst agreement  (analyst-confirmed / total observations)       20%
        """
        if memory.instance_count == 0:
            return 0.0

        similarity    = memory.confidence_score
        success_rate  = (memory.successful_count / memory.instance_count)
        rollback_rate = (memory.rollback_count   / memory.instance_count)
        agreement     = (memory.analyst_agreement / memory.instance_count)

        trust = (
            similarity   * 0.30 +
            success_rate * 0.30 +
            (1 - rollback_rate) * 0.20 +
            agreement    * 0.20
        )
        return round(max(0.0, min(1.0, trust)), 4)

    async def _advance_lifecycle(self, memory: PlaybookMemory) -> None:
        """
        Move the memory through the 7-stage lifecycle based on instance
        count and trust/confidence scores.

        observing → learning        once observe_threshold is reached
        learning  → candidate       once candidate_threshold is reached
        candidate → pending_graduation  once learning_threshold + confidence met
        autonomous → continuous_validation  if trust drops (re-evaluation)
        continuous_validation → learning    if trust stays low (regression)
        """
        s = memory.status

        if s == PlaybookStatus.observing:
            if memory.instance_count >= memory.observe_threshold:
                memory.status = PlaybookStatus.learning
                logger.info(f"[{memory.id[:8]}] observing → learning ({memory.instance_count} observations)")

        elif s == PlaybookStatus.learning:
            if memory.instance_count >= memory.candidate_threshold:
                memory.status = PlaybookStatus.candidate
                logger.info(f"[{memory.id[:8]}] learning → candidate ({memory.instance_count} observations)")

        elif s == PlaybookStatus.candidate:
            if (memory.instance_count  >= memory.learning_threshold
                    and memory.confidence_score >= AUTONOMOUS_CONFIDENCE_THRESHOLD
                    and memory.trust_score      >= AUTONOMOUS_TRUST_THRESHOLD):
                memory.status = PlaybookStatus.pending_graduation
                logger.info(
                    f"[{memory.id[:8]}] candidate → pending_graduation "
                    f"(confidence={memory.confidence_score:.2f} trust={memory.trust_score:.2f})"
                )

        elif s == PlaybookStatus.autonomous:
            if memory.trust_score < REVERSION_TRUST_THRESHOLD:
                memory.status = PlaybookStatus.continuous_validation
                memory.validation_started_at = datetime.now(timezone.utc)
                logger.warning(
                    f"[{memory.id[:8]}] autonomous → continuous_validation "
                    f"(trust dropped to {memory.trust_score:.2f})"
                )

        elif s == PlaybookStatus.continuous_validation:
            if memory.trust_score >= AUTONOMOUS_TRUST_THRESHOLD:
                memory.status = PlaybookStatus.autonomous
                logger.info(
                    f"[{memory.id[:8]}] continuous_validation → autonomous "
                    f"(trust recovered to {memory.trust_score:.2f})"
                )
            elif memory.false_positive_count / max(memory.instance_count, 1) > 0.40:
                memory.status = PlaybookStatus.learning
                logger.warning(
                    f"[{memory.id[:8]}] continuous_validation → learning "
                    f"(false positive rate > 40%)"
                )

    async def _snapshot_version(
        self,
        memory: PlaybookMemory,
        reason: str = "",
        changed_by_id: Optional[str] = None,
    ) -> PlaybookVersion:
        snapshot = {
            "fingerprint_description": memory.fingerprint_description,
            "technique_id":            memory.technique_id,
            "learned_action":          memory.learned_action,
            "instance_count":          memory.instance_count,
            "successful_count":        memory.successful_count,
            "false_positive_count":    memory.false_positive_count,
            "rollback_count":          memory.rollback_count,
            "analyst_agreement":       memory.analyst_agreement,
        }
        version = PlaybookVersion(
            organization_id   = memory.organization_id,
            memory_id         = memory.id,
            version_number    = memory.version,
            status_at_version = memory.status,
            learned_action    = memory.learned_action,
            instance_count    = memory.instance_count,
            confidence_score  = memory.confidence_score,
            trust_score       = memory.trust_score,
            changed_by_id     = changed_by_id,
            change_reason     = reason,
            snapshot          = snapshot,
        )
        self.db.add(version)
        await self.db.flush()
        return version

    async def approve_graduation(
        self,
        memory_id: str,
        organization_id: str,
        approving_user_id: str,
        notes: Optional[str] = None,
    ) -> Optional[PlaybookMemory]:
        memory = await self.get_by_id(memory_id, organization_id)
        if not memory:
            return None
        if memory.status != PlaybookStatus.pending_graduation:
            raise ValueError(
                f"Memory {memory_id} is not pending graduation (status: {memory.status})"
            )
        memory.status                    = PlaybookStatus.autonomous
        memory.graduated_at              = datetime.now(timezone.utc)
        memory.graduation_approved_by_id = approving_user_id
        memory.graduation_notes          = notes
        memory.version                  += 1
        await self._snapshot_version(
            memory,
            reason=f"Graduated to autonomous — approved by {approving_user_id}. Notes: {notes or 'none'}",
            changed_by_id=approving_user_id,
        )
        await self.db.flush()
        logger.info(f"[{memory_id[:8]}] pending_graduation → autonomous (approved)")
        return memory

    async def mark_executed(self, memory: PlaybookMemory) -> None:
        memory.last_executed_at = datetime.now(timezone.utc)
        await self.db.flush()

    async def disable(self, memory_id: str, org_id: str, reason: Optional[str] = None,
                      disabled_by_id: Optional[str] = None) -> Optional[PlaybookMemory]:
        memory = await self.get_by_id(memory_id, org_id)
        if memory:
            memory.status  = PlaybookStatus.disabled
            memory.version += 1
            await self._snapshot_version(
                memory,
                reason=f"Disabled — {reason or 'no reason given'}",
                changed_by_id=disabled_by_id,
            )
            await self.db.flush()
        return memory

    async def list_for_org(
        self,
        organization_id: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[PlaybookMemory]:
        conditions = [PlaybookMemory.organization_id == organization_id]
        if status:
            conditions.append(PlaybookMemory.status == status)
        result = await self.db.execute(
            select(PlaybookMemory)
            .where(and_(*conditions))
            .order_by(desc(PlaybookMemory.trust_score), desc(PlaybookMemory.instance_count))
            .limit(limit)
            .options(selectinload(PlaybookMemory.observations))
        )
        return list(result.scalars().all())

    async def get_summary(self, organization_id: str) -> dict:
        all_m = await self.list_for_org(organization_id, limit=1000)
        status_counts = {s.value: 0 for s in PlaybookStatus}
        for m in all_m:
            status_counts[m.status] = status_counts.get(m.status, 0) + 1
        total_auto = sum(
            sum(1 for o in m.observations if o.was_autonomous)
            for m in all_m
        )
        avg_trust = round(
            sum(m.trust_score for m in all_m) / len(all_m), 3
        ) if all_m else 0.0
        return {
            "total":                  len(all_m),
            "observing":              status_counts.get("observing", 0),
            "learning":               status_counts.get("learning", 0),
            "candidate":              status_counts.get("candidate", 0),
            "pending_graduation":     status_counts.get("pending_graduation", 0),
            "autonomous":             status_counts.get("autonomous", 0),
            "continuous_validation":  status_counts.get("continuous_validation", 0),
            "disabled":               status_counts.get("disabled", 0),
            "total_auto_executions":  total_auto,
            "average_trust_score":    avg_trust,
        }
