"""
End-to-end integration test: connect an AWS account, verify it (with STS
mocked out via moto instead of a real AWS account), and confirm the
auto-triggered first scan actually persists config-scan findings as
Incidents that show up through the API.

This exercises the full chain built across the AWS-onboarding and
config-scanner work:

    POST /accounts
      -> POST /accounts/{id}/verify
      -> dispatch_scan_for_org (no Redis in test env -> sync path)
      -> _run_sync_scan
      -> detection.config_scanner.run_config_scan
      -> workers.tasks._persist_incidents
      -> Incident rows in the DB, visible via GET /alerts

_persist_incidents does its own lazy `from db.engine import
AsyncSessionLocal` rather than using FastAPI's per-request DI (this is
correct in production, where there's one real Postgres DB either way, but
in tests each engine is an isolated in-memory SQLite DB). So this test
points db.engine.AsyncSessionLocal at the same engine used for the API's
DB session via monkeypatch, so every code path sees the same database.
"""
import asyncio
import os

os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "True")

import boto3
import pytest
from moto import mock_aws
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from fastapi.testclient import TestClient

import db.engine as db_engine_module
from db.engine import Base, get_db
from tests.conftest import _get_or_create_event_loop
from api.app import app


@pytest.fixture
def scan_client(monkeypatch):
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False},
    )

    async def _setup():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    _get_or_create_event_loop().run_until_complete(_setup())

    TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with TestSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    # _persist_incidents resolves db.engine.AsyncSessionLocal fresh on every
    # call (lazy import) — point it at our test engine so both the API and
    # the background persistence step see the same database.
    monkeypatch.setattr(db_engine_module, "AsyncSessionLocal", TestSessionLocal)

    client = TestClient(app, raise_server_exceptions=True)
    yield client

    app.dependency_overrides.clear()
    _get_or_create_event_loop().run_until_complete(test_engine.dispose())


def _register(client, slug, email):
    r = client.post("/auth/register", json={
        "org_name": slug, "org_slug": slug, "email": email,
        "full_name": "Test User", "password": "SecurePass123",
    })
    assert r.status_code == 201, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class _SessionWithSafeLookupEvents:
    """
    Wraps a moto-backed boto3.Session so verify_account's direct
    `cloudtrail_client.lookup_events(...)` connectivity probe degrades
    gracefully instead of raising — moto doesn't implement LookupEvents
    (it does support DescribeTrails/GetTrailStatus/etc., which is what the
    config scanner actually relies on). Every other client/service passes
    through to the real session untouched.
    """
    def __init__(self, real_session):
        self._real = real_session

    def client(self, service_name, *args, **kwargs):
        c = self._real.client(service_name, *args, **kwargs)
        if service_name == "cloudtrail":
            original_lookup_events = c.lookup_events

            def _safe_lookup_events(*a, **kw):
                try:
                    return original_lookup_events(*a, **kw)
                except Exception:
                    return {"Events": []}

            c.lookup_events = _safe_lookup_events
        return c


class TestFirstScanEndToEnd:
    @mock_aws
    def test_verify_triggers_scan_and_persists_config_findings(self, scan_client, monkeypatch):
        client = scan_client
        tokens = _register(client, "e2e-org", "e2e@test.com")
        headers = _auth(tokens)

        # Seed the "customer account" (moto) with an obviously-misconfigured
        # resource so the config scanner has something concrete to find.
        moto_session = boto3.Session(region_name="us-east-1")
        s3 = moto_session.client("s3")
        s3.create_bucket(Bucket="e2e-test-bucket")  # no encryption -> guaranteed finding

        r = client.post("/accounts", headers=headers, json={
            "aws_account_id": "123456789012",
            "display_name": "E2E Test Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole",
            "primary_region": "us-east-1",
        })
        assert r.status_code == 201, r.text
        account_id = r.json()["id"]

        # Stand in for the real cross-account STS AssumeRole with our
        # moto-backed session — there's no real AWS account behind this
        # test's role ARN.
        wrapped_session = _SessionWithSafeLookupEvents(moto_session)
        import api.routes.accounts as accounts_module
        monkeypatch.setattr(accounts_module, "get_session_for_account", lambda **kw: wrapped_session)
        import core.aws_session as aws_session_module
        monkeypatch.setattr(aws_session_module, "get_session_for_account", lambda **kw: wrapped_session)

        r = client.post(f"/accounts/{account_id}/verify", headers=headers)
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["status"] == "verified"
        assert result["first_scan"]["status"] == "completed"
        assert result["first_scan"]["alerts_found"] >= 1

        r = client.get("/alerts", headers=headers)
        assert r.status_code == 200, r.text
        event_names = {a["event_name"] for a in r.json()["alerts"]}
        assert "S3BucketUnencrypted" in event_names

        r = client.get("/accounts", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()[0]["last_scan_at"] is not None

    @mock_aws
    def test_reverify_does_not_duplicate_incidents(self, scan_client, monkeypatch):
        """Re-running the scan against an unchanged account shouldn't double-count findings."""
        client = scan_client
        tokens = _register(client, "e2e-dedup-org", "dedup@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        moto_session.client("s3").create_bucket(Bucket="dedup-bucket")

        r = client.post("/accounts", headers=headers, json={
            "aws_account_id": "123456789012",
            "display_name": "Dedup Test Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole",
            "primary_region": "us-east-1",
        })
        account_id = r.json()["id"]

        wrapped_session = _SessionWithSafeLookupEvents(moto_session)
        import api.routes.accounts as accounts_module
        monkeypatch.setattr(accounts_module, "get_session_for_account", lambda **kw: wrapped_session)
        import core.aws_session as aws_session_module
        monkeypatch.setattr(aws_session_module, "get_session_for_account", lambda **kw: wrapped_session)

        client.post(f"/accounts/{account_id}/verify", headers=headers)
        first_count = client.get("/alerts", headers=headers).json()["total"]

        r = client.post(f"/accounts/{account_id}/verify", headers=headers)
        assert r.json()["first_scan"]["status"] == "completed"
        second_count = client.get("/alerts", headers=headers).json()["total"]

        assert first_count >= 1
        assert second_count == first_count
