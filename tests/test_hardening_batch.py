"""
Hardening batch tests:
  12  durable anomaly model store is fail-closed (missing / tampered / unreadable)
  14  REDIS_URL selects the Redis-backed limiter; fallback when Redis is down
  16  remediation claim makes a retry skip an already-applied AWS action
"""
import asyncio
import importlib
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ml.anomaly_detector import AnomalyDetector, FeatureRow


def _fitted_detector():
    import random
    rng = random.Random(7)
    rows = [FeatureRow(event_name_freq=rng.random(), hour_of_day=rng.randint(0, 23),
                       is_weekend=rng.randint(0, 1), new_source_ip=rng.randint(0, 1),
                       new_region=rng.randint(0, 1), actor_event_count_1h=rng.randint(0, 9),
                       is_management_event=rng.randint(0, 1)) for _ in range(40)]
    d = AnomalyDetector(contamination=0.05)
    d.fit(rows)
    return d


# ---------------------------------------------------------------- item 12
@pytest.fixture
def model_db(auth_client):
    from ml import model_store
    model_store.clear_cache()
    yield auth_client
    model_store.clear_cache()


def _run(client, coro):
    return client.loop.run_until_complete(coro)


class TestModelStoreFailClosed:
    def test_round_trip_through_db(self, model_db):
        from ml import model_store
        det = _fitted_detector()

        async def go():
            async with model_db.session_factory() as db:
                await model_store.save_model(db, "scope-a", det)
                await db.commit()
            model_store.clear_cache()
            async with model_db.session_factory() as db:
                return await model_store.load_model(db, "scope-a")

        loaded = _run(model_db, go())
        assert loaded is not None
        assert loaded.n_training_samples == det.n_training_samples

    def test_missing_model_returns_none_and_warns(self, model_db, caplog):
        from ml import model_store

        async def go():
            async with model_db.session_factory() as db:
                return await model_store.load_model(db, "no-such-scope")

        with caplog.at_level("WARNING"):
            assert _run(model_db, go()) is None
        assert any("running without learned state" in r.message for r in caplog.records)

    def test_tampered_blob_is_refused_not_unpickled(self, model_db, caplog):
        from ml import model_store
        from db.models.anomaly_model import AnomalyModelRecord
        det = _fitted_detector()

        async def go():
            async with model_db.session_factory() as db:
                await model_store.save_model(db, "scope-t", det)
                await db.commit()
            model_store.clear_cache()
            async with model_db.session_factory() as db:
                row = await db.get(AnomalyModelRecord, "scope-t")
                row.blob = b"malicious-pickle-bytes"  # signature no longer matches
                await db.commit()
            async with model_db.session_factory() as db:
                return await model_store.load_model(db, "scope-t")

        with caplog.at_level("WARNING"):
            assert _run(model_db, go()) is None
        assert any("signature mismatch" in r.message for r in caplog.records)

    def test_bad_signature_is_refused(self, model_db):
        from ml import model_store
        from db.models.anomaly_model import AnomalyModelRecord
        det = _fitted_detector()

        async def go():
            async with model_db.session_factory() as db:
                await model_store.save_model(db, "scope-s", det)
                await db.commit()
            model_store.clear_cache()
            async with model_db.session_factory() as db:
                row = await db.get(AnomalyModelRecord, "scope-s")
                row.signature = "0" * 64
                await db.commit()
            async with model_db.session_factory() as db:
                return await model_store.load_model(db, "scope-s")

        assert _run(model_db, go()) is None

    def test_db_error_fails_closed(self, model_db):
        from ml import model_store

        class Boom:
            async def get(self, *a, **k):
                raise RuntimeError("db down")

        assert _run(model_db, model_store.load_model(Boom(), "x")) is None

    def test_missing_secret_key_fails_closed_not_raises(self, model_db, monkeypatch):
        from ml import model_store
        monkeypatch.delenv("SECRET_KEY", raising=False)
        model_store.clear_cache()

        async def go():
            async with model_db.session_factory() as db:
                return await model_store.load_model(db, "scope-nokey")

        assert _run(model_db, go()) is None

    def test_no_data_directory_path_is_used(self):
        import pathlib
        for rel in ["detection/orchestrator.py", "workers/tasks.py",
                    "api/dependencies.py", "api/routes/health.py", "ml/train_baseline.py"]:
            src = pathlib.Path(rel).read_text()
            assert "anomaly_model.joblib" not in src, rel
            assert "CG_MODEL_DIR" not in src, rel


# ---------------------------------------------------------------- item 14
class TestRateLimitRedisWiring:
    def test_redis_url_selects_redis_store(self, monkeypatch):
        import core.rate_limit as rl
        monkeypatch.setattr(rl, "REDIS_URL", "redis://example.invalid:6379/0")
        sentinel = object()
        with patch.object(rl, "_RedisStore", return_value=sentinel) as rs:
            assert rl._make_store() is sentinel
            rs.assert_called_once_with("redis://example.invalid:6379/0")

    def test_no_redis_url_uses_in_process_store(self, monkeypatch):
        import core.rate_limit as rl
        monkeypatch.setattr(rl, "REDIS_URL", "")
        assert isinstance(rl._make_store(), rl._InProcessStore)

    def test_redis_construction_failure_falls_back(self, monkeypatch):
        import core.rate_limit as rl
        monkeypatch.setattr(rl, "REDIS_URL", "redis://down:6379/0")
        with patch.object(rl, "_RedisStore", side_effect=RuntimeError("no redis")):
            assert isinstance(rl._make_store(), rl._InProcessStore)

    def test_redis_count_failure_fails_open_to_in_process(self):
        import core.rate_limit as rl
        store = rl._RedisStore.__new__(rl._RedisStore)
        pipe = MagicMock()
        pipe.execute.side_effect = ConnectionError("redis gone")
        store._r = MagicMock(pipeline=MagicMock(return_value=pipe))
        n = store.count(("1.2.3.4", "global"), 1000.0)
        assert isinstance(n, int) and n >= 1


# ---------------------------------------------------------------- item 16
class TestRemediationClaim:
    def test_claim_model_exists_and_is_unique_per_action(self):
        from db.models.remediation_attempt import RemediationAttempt
        cols = {c.name for c in RemediationAttempt.__table__.columns}
        assert {"incident_id", "action_type", "status", "attempts"} <= cols
        uniq = [c for c in RemediationAttempt.__table__.constraints
                if c.__class__.__name__ == "UniqueConstraint"]
        assert any({c.name for c in u.columns} == {"incident_id", "action_type"} for u in uniq)

    def test_worker_claims_before_handler_and_skips_succeeded(self):
        import inspect
        from workers import tasks
        src = inspect.getsource(tasks._do_remediation)
        claim_idx = src.index("RemediationAttempt")
        handler_idx = src.index("handler(alert)")
        assert claim_idx < handler_idx, "claim must be written before the AWS handler runs"
        assert '"succeeded", "running", "unknown"' in src

    def test_unknown_outcome_is_not_retried_into_a_second_run(self):
        import inspect
        from workers import tasks
        src = inspect.getsource(tasks._do_remediation)
        exc_branch = src[src.index('claim.status, claim.detail = "unknown"'):]
        assert "raise" in exc_branch[:300]

    def test_retry_cap_unchanged(self):
        from workers.tasks import execute_remediation
        assert execute_remediation.max_retries == 2


class TestRemediationClaimBehaviour:
    """Drive _do_remediation for real against the in-memory DB with a fake handler."""

    def _setup(self, client):
        import uuid as _u
        from datetime import datetime as _dt, timezone as _tz
        from db.models.incident import Incident, IncidentStatus
        from db.models.aws_account import AWSAccount, AccountStatus
        from tests.test_tenant_isolation import _seed_org_a_rows
        from tests.test_auth_integration import register_and_login
        from tests.test_tenant_isolation import _org_id_of
        a = register_and_login(client, "claim-org", "owner.claim@example.com")
        org = _org_id_of(a)
        ids = _seed_org_a_rows(client, org)
        return org, ids

    def test_second_run_after_success_does_not_call_handler_again(self, auth_client):
        from workers import tasks
        from db.engine import AsyncSessionLocal
        from detection import remediation_actions as actions
        org, ids = self._setup(auth_client)
        calls = []

        def fake_handler(alert):
            calls.append(alert.event_id)
            return True, "applied"

        async def run_once():
            return await tasks._do_remediation(ids["incident"], org, "approver-1", False)

        # point the worker at the test DB and stub the AWS-facing pieces
        from db import engine as eng
        with patch.object(eng, "AsyncSessionLocal", auth_client.session_factory), \
             patch("workers.tasks.AsyncSessionLocal", auth_client.session_factory, create=True), \
             patch.object(actions, "restore_cloudtrail_logging", fake_handler), \
             patch("detection.playbooks.get_playbook") as gp, \
             patch("workers.tasks._load_account_for_incident", side_effect=_fake_account_loader), \
             patch("core.aws_session.get_session_for_account", return_value=MagicMock()):
            gp.return_value = _fake_playbook()
            first = auth_client.loop.run_until_complete(run_once())
            second = auth_client.loop.run_until_complete(run_once())
        assert first.get("status") == "ok", first
        assert second.get("status") == "already_applied", second
        assert len(calls) == 1, "the AWS handler must run exactly once across retries"


async def _fake_account_loader(db, incident, org_id):
    m = MagicMock()
    m.aws_account_id = incident.aws_account_id
    m.role_arn = "arn:aws:iam::111122223333:role/auto"
    m.auto_remediation_role_arn = "arn:aws:iam::111122223333:role/auto"
    m.destructive_remediation_role_arn = "arn:aws:iam::111122223333:role/destr"
    m.external_id = "ext"
    m.primary_region = "us-east-1"
    return m


def _fake_playbook():
    from detection.playbooks import get_playbook as _g  # noqa: F401
    from types import SimpleNamespace
    from detection.playbooks import ActionType, RiskTier
    return SimpleNamespace(action=ActionType.RESTORE_CLOUDTRAIL_LOGGING,
                           action_risk_tier=RiskTier.LOW)
