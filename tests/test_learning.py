"""
Adaptive Playbook Learning tests.

Covers:
  - Fingerprint extraction (MFA, privilege, time, service)
  - 7-stage lifecycle transitions
  - Confidence + trust score computation
  - Versioning on every transition
  - Learning engine: record_analyst_action + check_and_apply_learned_playbook
  - API routes: summary, list, review queue, approve, disable, settings

No real AWS calls. No Stripe. Uses in-memory SQLite + auth_client fixture.
"""
import asyncio
import os
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from detection.rule_engine import DetectedAlert
from learning.fingerprint import (
    extract_features, compute_fingerprint, describe_fingerprint, build_fingerprint,
    _mfa_status, _privilege_level, _service_from_event, _time_bucket,
)


def make_alert(
    technique_id="T1078", event_name="ConsoleLogin", tactic="Initial Access",
    risk_tier="medium", actor_arn="arn:aws:iam::123:user/alice",
    modifiers=None, source="cloudtrail", severity=50,
    event_time=None,
):
    return DetectedAlert(
        event_id=f"evt-{technique_id}",
        source=source,
        event_name=event_name,
        event_time=event_time or datetime(2026, 6, 14, 10, 0, 0, tzinfo=timezone.utc),
        technique_id=technique_id,
        technique_name="Valid Accounts",
        tactic=tactic,
        severity=severity,
        risk_tier=risk_tier,
        description="Test alert",
        actor_arn=actor_arn,
        account_id="123456789012",
        region="us-east-1",
        source_ip="1.2.3.4",
        modifiers=modifiers or [],
        raw_event={},
    )


class TestFingerprinting:
    def test_mfa_status_no_mfa(self):
        assert _mfa_status(["Console login without MFA"]) == "no_mfa"

    def test_mfa_status_present(self):
        assert _mfa_status(["MFA verified"]) == "mfa_present"

    def test_mfa_status_unknown(self):
        assert _mfa_status([]) == "unknown"

    def test_privilege_level_root(self):
        assert _privilege_level(["Root account used (high risk)"], "") == "high"

    def test_privilege_level_admin_policy(self):
        assert _privilege_level(["High-privilege policy attached: AdministratorAccess"], "") == "high"

    def test_privilege_level_root_arn(self):
        assert _privilege_level([], "arn:aws:iam::123:root") == "high"

    def test_privilege_level_power_user(self):
        assert _privilege_level(["PowerUserAccess attached"], "") == "medium"

    def test_privilege_level_low(self):
        assert _privilege_level([], "arn:aws:iam::123:user/alice") == "low"

    def test_service_iam(self):
        assert _service_from_event("CreateAccessKey") == "IAM"

    def test_service_s3(self):
        assert _service_from_event("PutBucketAcl") == "S3"

    def test_service_ec2(self):
        assert _service_from_event("RunInstances") == "EC2"

    def test_service_lambda(self):
        assert _service_from_event("CreateFunction20150331") == "Lambda"

    def test_time_bucket_business_hours(self):
        assert _time_bucket(14) == "business_hours"

    def test_time_bucket_off_hours_night(self):
        assert _time_bucket(3) == "off_hours_night"

    def test_time_bucket_evening(self):
        assert _time_bucket(20) == "evening"

    def test_extract_features_has_all_keys(self):
        alert = make_alert()
        features = extract_features(alert)
        for key in ("technique_id", "event_name", "tactic", "risk_tier",
                    "service", "actor_type", "time_bucket", "source",
                    "privilege_level", "mfa_status"):
            assert key in features, f"Missing feature: {key}"

    def test_extract_features_mfa_captured(self):
        alert = make_alert(modifiers=["Console login without MFA"])
        features = extract_features(alert)
        assert features["mfa_status"] == "no_mfa"

    def test_extract_features_privilege_captured(self):
        alert = make_alert(modifiers=["Root account used (high risk)"])
        features = extract_features(alert)
        assert features["privilege_level"] == "high"

    def test_fingerprint_deterministic(self):
        alert = make_alert()
        fp1, _, _ = build_fingerprint(alert)
        fp2, _, _ = build_fingerprint(alert)
        assert fp1 == fp2

    def test_different_mfa_different_fingerprint(self):
        a1 = make_alert(modifiers=["Console login without MFA"])
        a2 = make_alert(modifiers=[])
        fp1, _, _ = build_fingerprint(a1)
        fp2, _, _ = build_fingerprint(a2)
        assert fp1 != fp2

    def test_different_privilege_different_fingerprint(self):
        a1 = make_alert(modifiers=["Root account used (high risk)"])
        a2 = make_alert(modifiers=[])
        fp1, _, _ = build_fingerprint(a1)
        fp2, _, _ = build_fingerprint(a2)
        assert fp1 != fp2

    def test_description_includes_no_mfa(self):
        alert = make_alert(modifiers=["Console login without MFA"])
        _, desc, _ = build_fingerprint(alert)
        assert "without MFA" in desc

    def test_description_includes_privilege(self):
        alert = make_alert(modifiers=["Root account used (high risk)"])
        _, desc, _ = build_fingerprint(alert)
        assert "high privilege" in desc


class TestLifecycleTransitions:
    """Test the 7-stage lifecycle using the repository directly."""

    @pytest.fixture
    def db_setup(self):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from db.engine import Base
        engine = create_async_engine("sqlite+aiosqlite:///:memory:",
                                      connect_args={"check_same_thread": False})
        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        asyncio.get_event_loop().run_until_complete(_init())
        SM = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        return SM

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    async def _make_memory(self, db, org_id="org-1", threshold=5,
                           observe_threshold=2, candidate_threshold=3):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        repo = PlaybookMemoryRepository(db)
        return await repo.create(
            organization_id="org-1", attack_fingerprint="fp-test-abc123",
            fingerprint_description="T1078 · ConsoleLogin · IAM · iam_user · business_hours",
            technique_id="T1078", technique_name="Valid Accounts",
            tactic="Initial Access", event_name="ConsoleLogin", risk_tier="medium",
            learned_action="revoke_session_token",
            learning_threshold=threshold, observe_threshold=observe_threshold,
            candidate_threshold=candidate_threshold,
        )

    def test_initial_status_is_observing(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db)
                assert mem.status == PlaybookStatus.observing
        self._run(_run())

    def test_observing_to_learning_at_observe_threshold(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, observe_threshold=2)
                repo = PlaybookMemoryRepository(db)
                await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                    "user-1", "success", 50)
                assert mem.status == PlaybookStatus.observing
                await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                    "user-1", "success", 50)
                assert mem.status == PlaybookStatus.learning
        self._run(_run())

    def test_learning_to_candidate_at_candidate_threshold(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, observe_threshold=2, candidate_threshold=3)
                repo = PlaybookMemoryRepository(db)
                for _ in range(3):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                assert mem.status == PlaybookStatus.candidate
        self._run(_run())

    def test_candidate_to_pending_graduation_at_threshold(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, threshold=5, observe_threshold=2,
                                               candidate_threshold=3)
                repo = PlaybookMemoryRepository(db)
                for _ in range(5):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                assert mem.status == PlaybookStatus.pending_graduation
        self._run(_run())

    def test_false_positive_lowers_confidence(self, db_setup):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db)
                repo = PlaybookMemoryRepository(db)
                await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                    "user-1", "success", 50)
                before = mem.confidence_score
                await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                    "user-1", "false_positive", 50)
                assert mem.confidence_score < before
        self._run(_run())

    def test_versioning_on_status_change(self, db_setup):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, observe_threshold=2)
                repo = PlaybookMemoryRepository(db)
                await db.commit()
                for _ in range(2):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                await db.commit()
                fresh = await repo.get_by_id(mem.id, "org-1")
                assert fresh.version > 1, f"Expected version > 1, got {fresh.version}"
        self._run(_run())

    def test_approve_graduation(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, threshold=5, observe_threshold=2,
                                               candidate_threshold=3)
                repo = PlaybookMemoryRepository(db)
                for _ in range(5):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                assert mem.status == PlaybookStatus.pending_graduation
                updated = await repo.approve_graduation(mem.id, "org-1", "admin-1",
                                                         notes="Looks good")
                assert updated.status == PlaybookStatus.autonomous
                assert updated.graduation_notes == "Looks good"
                assert updated.graduated_at is not None
        self._run(_run())

    def test_autonomous_reverts_to_validation_on_low_trust(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, threshold=5, observe_threshold=2,
                                               candidate_threshold=3)
                repo = PlaybookMemoryRepository(db)
                for _ in range(5):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                await repo.approve_graduation(mem.id, "org-1", "admin-1")
                assert mem.status == PlaybookStatus.autonomous
                for _ in range(5):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "false_positive", 50, was_autonomous=True)
                assert mem.status in (PlaybookStatus.continuous_validation,
                                       PlaybookStatus.learning)
        self._run(_run())

    def test_disable_stops_autonomous(self, db_setup):
        from db.models.playbook_memory import PlaybookStatus
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db, threshold=5, observe_threshold=2,
                                               candidate_threshold=3)
                repo = PlaybookMemoryRepository(db)
                for _ in range(5):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                await repo.approve_graduation(mem.id, "org-1", "admin-1")
                await repo.disable(mem.id, "org-1", reason="Test disable")
                assert mem.status == PlaybookStatus.disabled
                result = await repo.get_by_fingerprint("fp-test-abc123", "org-1")
                assert result is None
        self._run(_run())

    def test_trust_score_composite(self, db_setup):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db)
                repo = PlaybookMemoryRepository(db)
                for _ in range(4):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                assert 0.0 <= mem.trust_score <= 1.0
                assert mem.trust_score > 0.0
        self._run(_run())

    def test_rollback_lowers_trust(self, db_setup):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                mem = await self._make_memory(db)
                repo = PlaybookMemoryRepository(db)
                for _ in range(3):
                    await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                        "user-1", "success", 50)
                trust_before = mem.trust_score
                await repo.record_observation(mem, "org-1", None, "revoke_session_token",
                    "user-1", "success", 50, was_rolled_back=True)
                assert mem.trust_score < trust_before
        self._run(_run())

    def test_summary_counts_all_stages(self, db_setup):
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                repo = PlaybookMemoryRepository(db)
                await repo.create(
                    organization_id="org-1", attack_fingerprint="fp-1",
                    fingerprint_description="desc-1", technique_id="T1078",
                    technique_name="Test", tactic="Initial Access",
                    event_name="ConsoleLogin", risk_tier="medium",
                    learned_action="revoke_session_token",
                )
                summary = await repo.get_summary("org-1")
                assert "total"             in summary
                assert "observing"         in summary
                assert "learning"          in summary
                assert "candidate"         in summary
                assert "pending_graduation" in summary
                assert "autonomous"        in summary
                assert "continuous_validation" in summary
                assert "disabled"          in summary
                assert "average_trust_score" in summary
                assert summary["total"] == 1
                assert summary["observing"] == 1
        self._run(_run())


class TestLearningAPI:
    def _reg(self, client, slug, email):
        r = client.post("/auth/register", json={
            "org_name": f"Org {slug}", "org_slug": slug,
            "email": email, "full_name": "Test", "password": "SecurePass123",
        })
        assert r.status_code == 201, r.text
        return r.json()

    def _auth(self, tokens):
        return {"Authorization": f"Bearer {tokens['access_token']}"}

    def test_summary_requires_auth(self, auth_client):
        assert auth_client.get("/learning/summary").status_code == 401

    def test_summary_empty_for_new_org(self, auth_client):
        tokens = self._reg(auth_client, "learn-sum", "sum@learn.com")
        r = auth_client.get("/learning/summary", headers=self._auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0
        assert data["autonomous"] == 0
        assert data["pending_graduation"] == 0

    def test_playbooks_empty_for_new_org(self, auth_client):
        tokens = self._reg(auth_client, "learn-list", "list@learn.com")
        r = auth_client.get("/learning/playbooks", headers=self._auth(tokens))
        assert r.status_code == 200
        assert r.json() == []

    def test_review_queue_empty_for_new_org(self, auth_client):
        tokens = self._reg(auth_client, "learn-rq", "rq@learn.com")
        r = auth_client.get("/learning/review-queue", headers=self._auth(tokens))
        assert r.status_code == 200
        assert r.json() == []

    def test_playbooks_invalid_status_returns_400(self, auth_client):
        tokens = self._reg(auth_client, "learn-inv", "inv@learn.com")
        r = auth_client.get("/learning/playbooks?status=nonexistent",
                            headers=self._auth(tokens))
        assert r.status_code == 400

    def test_playbook_not_found_returns_404(self, auth_client):
        tokens = self._reg(auth_client, "learn-404", "404@learn.com")
        r = auth_client.get("/learning/playbooks/nonexistent-id",
                            headers=self._auth(tokens))
        assert r.status_code == 404

    def test_approve_not_found_returns_404(self, auth_client):
        tokens = self._reg(auth_client, "learn-app404", "app404@learn.com")
        r = auth_client.post("/learning/playbooks/nonexistent/approve",
                             headers=self._auth(tokens), json={"notes": "test"})
        assert r.status_code == 404

    def test_approve_requires_admin(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        viewer = CurrentUser(id="v", organization_id="o", email="v@v.com",
                             full_name="V", role="viewer", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.post("/learning/playbooks/some-id/approve", json={"notes": ""})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_disable_requires_analyst_min(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        viewer = CurrentUser(id="v", organization_id="o", email="v@v.com",
                             full_name="V", role="viewer", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.post("/learning/playbooks/some-id/disable",
                             json={"reason": "test"})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_settings_returned(self, auth_client):
        tokens = self._reg(auth_client, "learn-set", "set@learn.com")
        r = auth_client.get("/learning/settings", headers=self._auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert "learning_threshold"   in data
        assert "observe_threshold"    in data
        assert "candidate_threshold"  in data
        assert "confidence_threshold" in data
        assert "trust_threshold"      in data
        assert "lifecycle_stages"     in data
        assert len(data["lifecycle_stages"]) == 7

    def test_settings_update_valid(self, auth_client):
        tokens = self._reg(auth_client, "learn-upd", "upd@learn.com")
        r = auth_client.put("/learning/settings",
                             headers=self._auth(tokens),
                             json={"learning_threshold": 7,
                                   "observe_threshold": 2,
                                   "candidate_threshold": 4})
        assert r.status_code == 200
        data = r.json()
        assert data["learning_threshold"] == 7

    def test_settings_invalid_order_returns_422(self, auth_client):
        tokens = self._reg(auth_client, "learn-bad", "bad@learn.com")
        r = auth_client.put("/learning/settings",
                             headers=self._auth(tokens),
                             json={"learning_threshold": 3,
                                   "observe_threshold": 5,
                                   "candidate_threshold": 4})
        assert r.status_code == 422

    def test_playbook_history_requires_auth(self, auth_client):
        r = auth_client.get("/learning/playbooks/some-id/history")
        assert r.status_code == 401

    def test_review_queue_requires_analyst_min(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        viewer = CurrentUser(id="v", organization_id="o", email="v@v.com",
                             full_name="V", role="viewer", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.get("/learning/review-queue")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_tenant_isolation_playbooks(self, auth_client):
        tokens_a = self._reg(auth_client, "learn-iso-a", "a@iso.com")
        tokens_b = self._reg(auth_client, "learn-iso-b", "b@iso.com")
        r_a = auth_client.get("/learning/playbooks", headers=self._auth(tokens_a))
        r_b = auth_client.get("/learning/playbooks", headers=self._auth(tokens_b))
        assert r_a.status_code == 200
        assert r_b.status_code == 200
        assert r_a.json() == []
        assert r_b.json() == []


class TestLearningEngineIntegration:
    """End-to-end: learning engine creates and advances memories correctly."""

    @pytest.fixture
    def db_setup(self):
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from db.engine import Base
        engine = create_async_engine("sqlite+aiosqlite:///:memory:",
                                      connect_args={"check_same_thread": False})
        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        asyncio.get_event_loop().run_until_complete(_init())
        SM = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        return SM

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_first_observation_creates_memory(self, db_setup):
        from learning.engine import record_analyst_action
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                result = await record_analyst_action(
                    alert=alert, organization_id="org-1",
                    incident_id="inc-1", analyst_action="revoke_session_token",
                    analyst_user_id="user-1", outcome="success", db=db,
                )
                assert result["is_new_pattern"] is True
                assert result["instance_count"] == 1
                assert "memory_id" in result
                assert result["status"] == "observing"
        self._run(_run())

    def test_repeated_observations_advance_lifecycle(self, db_setup):
        from learning.engine import record_analyst_action
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                statuses = []
                for i in range(5):
                    result = await record_analyst_action(
                        alert=alert, organization_id="org-1",
                        incident_id=f"inc-{i}", analyst_action="revoke_session_token",
                        analyst_user_id="user-1", outcome="success", db=db,
                        org_learning_threshold=5, org_observe_threshold=2,
                        org_candidate_threshold=3,
                    )
                    statuses.append(result["status"])
                assert "observing" in statuses
                assert "learning" in statuses
                assert "candidate" in statuses or "pending_graduation" in statuses
        self._run(_run())

    def test_different_fingerprints_separate_memories(self, db_setup):
        from learning.engine import record_analyst_action
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                alert_mfa    = make_alert(modifiers=["Console login without MFA"])
                alert_no_mfa = make_alert(modifiers=[])
                r1 = await record_analyst_action(
                    alert=alert_mfa, organization_id="org-1",
                    incident_id="inc-1", analyst_action="revoke_session_token",
                    analyst_user_id="user-1", outcome="success", db=db,
                )
                r2 = await record_analyst_action(
                    alert=alert_no_mfa, organization_id="org-1",
                    incident_id="inc-2", analyst_action="revoke_session_token",
                    analyst_user_id="user-1", outcome="success", db=db,
                )
                assert r1["memory_id"] != r2["memory_id"]
                assert r1["fingerprint"] != r2["fingerprint"]
        self._run(_run())

    def test_no_auto_execute_before_graduation(self, db_setup):
        from learning.engine import record_analyst_action, check_and_apply_learned_playbook
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                for i in range(4):
                    await record_analyst_action(
                        alert=alert, organization_id="org-1",
                        incident_id=f"inc-{i}", analyst_action="revoke_session_token",
                        analyst_user_id="user-1", outcome="success", db=db,
                        org_learning_threshold=5, org_observe_threshold=2,
                        org_candidate_threshold=3,
                    )
                result = await check_and_apply_learned_playbook(
                    alert=alert, organization_id="org-1", db=db,
                )
                assert result is None
        self._run(_run())

    def test_auto_executes_after_graduation_approval(self, db_setup):
        from learning.engine import record_analyst_action, check_and_apply_learned_playbook
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        from db.models.playbook_memory import PlaybookStatus
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                for i in range(5):
                    await record_analyst_action(
                        alert=alert, organization_id="org-1",
                        incident_id=f"inc-{i}", analyst_action="revoke_session_token",
                        analyst_user_id="user-1", outcome="success", db=db,
                        org_learning_threshold=5, org_observe_threshold=2,
                        org_candidate_threshold=3,
                    )
                fp_hash, _, _ = build_fingerprint(alert)
                repo   = PlaybookMemoryRepository(db)
                memory = await repo.get_by_fingerprint(fp_hash, "org-1")
                assert memory is not None
                if memory.status == PlaybookStatus.pending_graduation:
                    await repo.approve_graduation(memory.id, "org-1", "admin-1",
                                                   notes="Approved in test")
                    mock_handler = MagicMock(return_value=(True, "mocked revoke success"))
                    with patch("detection.remediation_actions.revoke_session_token", mock_handler):
                        result = await check_and_apply_learned_playbook(
                            alert=alert, organization_id="org-1", db=db,
                        )
                    assert result is not None
                    assert result.was_autonomous is True
                    assert result.status == "executed"
        self._run(_run())

    def test_analyst_notes_stored_on_observation(self, db_setup):
        from learning.engine import record_analyst_action
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                await record_analyst_action(
                    alert=alert, organization_id="org-1",
                    incident_id="inc-1", analyst_action="revoke_session_token",
                    analyst_user_id="user-1", outcome="success", db=db,
                    analyst_notes="Confirmed malicious — credentials stolen from CI/CD",
                )
                fp_hash, _, _ = build_fingerprint(alert)
                repo   = PlaybookMemoryRepository(db)
                memory = await repo.get_by_fingerprint(fp_hash, "org-1")
                assert len(memory.observations) == 1
                assert memory.observations[0].analyst_notes == "Confirmed malicious — credentials stolen from CI/CD"
        self._run(_run())

    def test_investigation_steps_stored(self, db_setup):
        from learning.engine import record_analyst_action
        from db.repositories.playbook_memory_repo import PlaybookMemoryRepository
        async def _run():
            async with db_setup() as db:
                alert = make_alert()
                steps = ["Checked IP geolocation", "Reviewed CloudTrail for 2h prior",
                          "Confirmed no MFA registered for this user"]
                await record_analyst_action(
                    alert=alert, organization_id="org-1",
                    incident_id="inc-1", analyst_action="revoke_session_token",
                    analyst_user_id="user-1", outcome="success", db=db,
                    investigation_steps=steps,
                )
                fp_hash, _, _ = build_fingerprint(alert)
                repo   = PlaybookMemoryRepository(db)
                memory = await repo.get_by_fingerprint(fp_hash, "org-1")
                stored_steps = memory.observations[0].investigation_steps
                assert stored_steps == steps
        self._run(_run())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
