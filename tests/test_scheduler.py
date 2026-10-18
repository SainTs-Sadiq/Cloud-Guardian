"""
Tests for the scheduler pieces:
  - Organization.scan_frequency defaults and the /organizations/settings endpoint
  - workers.tasks._due_orgs_for_scheduled_scan (per-org cadence logic)
  - core.notifications.send_scan_notification (webhook, mocked HTTP)
"""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from fastapi.testclient import TestClient

import db.engine as db_engine_module
from db.engine import Base, get_db
from api.app import app


def _register(client, slug, email):
    r = client.post("/auth/register", json={
        "org_name": slug, "org_slug": slug, "email": email,
        "full_name": "Test User", "password": "SecurePass123",
    })
    assert r.status_code == 201, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestOrgSettingsEndpoint:
    def test_default_settings(self, auth_client):
        tokens = _register(auth_client, "sched-default-org", "default@sched.com")
        r = auth_client.get("/organizations/settings", headers=_auth(tokens))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_frequency"] == "daily"
        assert body["notification_webhook_url"] is None

    def test_owner_can_update_settings(self, auth_client):
        tokens = _register(auth_client, "sched-update-org", "update@sched.com")
        r = auth_client.patch("/organizations/settings", headers=_auth(tokens), json={
            "scan_frequency": "hourly",
            "notification_webhook_url": "https://example.com/webhook",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_frequency"] == "hourly"
        assert body["notification_webhook_url"] == "https://example.com/webhook"

        # Confirm it persisted.
        r = auth_client.get("/organizations/settings", headers=_auth(tokens))
        assert r.json()["scan_frequency"] == "hourly"

    def test_invalid_scan_frequency_rejected(self, auth_client):
        tokens = _register(auth_client, "sched-invalid-org", "invalid@sched.com")
        r = auth_client.patch("/organizations/settings", headers=_auth(tokens), json={
            "scan_frequency": "weekly",
        })
        assert r.status_code == 422

    def test_clearing_webhook_with_empty_string(self, auth_client):
        tokens = _register(auth_client, "sched-clear-org", "clear@sched.com")
        auth_client.patch("/organizations/settings", headers=_auth(tokens),
                          json={"notification_webhook_url": "https://example.com/hook"})
        r = auth_client.patch("/organizations/settings", headers=_auth(tokens),
                              json={"notification_webhook_url": ""})
        assert r.status_code == 200
        assert r.json()["notification_webhook_url"] is None

    def test_non_admin_cannot_update_settings(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        tokens = _register(auth_client, "sched-viewer-org", "viewer@sched.com")
        org_id = auth_client.get("/organizations/settings", headers=_auth(tokens)).json()["id"]

        viewer = CurrentUser(id="x", organization_id=org_id,
                             email="v@v.com", full_name="V", role="viewer", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.patch("/organizations/settings", headers=_auth(tokens),
                              json={"scan_frequency": "hourly"})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_settings_requires_auth(self, auth_client):
        r = auth_client.get("/organizations/settings")
        assert r.status_code == 401


class TestNotifications:
    @pytest.mark.asyncio
    async def test_no_webhook_configured_returns_false(self):
        from core.notifications import send_scan_notification

        org = type("Org", (), {"notification_webhook_url": None, "name": "Test", "id": "o1"})()
        run = type("Run", (), {"id": "r1", "status": "success", "trigger": "manual",
                                "findings_count": 5, "completed_at": None})()

        sent = await send_scan_notification(org, run, {"critical": 1, "high": 0, "medium": 0, "low": 0})
        assert sent is False

    @pytest.mark.asyncio
    async def test_no_high_or_critical_findings_skips_notification(self):
        from core.notifications import send_scan_notification

        org = type("Org", (), {"notification_webhook_url": "https://example.com/hook",
                               "name": "Test", "id": "o1"})()
        run = type("Run", (), {"id": "r1", "status": "success", "trigger": "manual",
                                "findings_count": 5, "completed_at": None})()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            sent = await send_scan_notification(org, run, {"critical": 0, "high": 0, "medium": 5, "low": 0})
            assert sent is False
            mock_post.assert_not_called()

    @pytest.mark.asyncio
    async def test_high_severity_findings_triggers_webhook_post(self):
        from core.notifications import send_scan_notification

        org = type("Org", (), {"notification_webhook_url": "https://example.com/hook",
                               "name": "Test Org", "id": "o1"})()
        run = type("Run", (), {"id": "r1", "status": "success", "trigger": "scheduled",
                                "findings_count": 3, "completed_at": datetime.now(timezone.utc)})()

        mock_response = type("Resp", (), {"raise_for_status": lambda self: None})()
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            sent = await send_scan_notification(org, run, {"critical": 1, "high": 2, "medium": 0, "low": 0})
            assert sent is True
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            assert call_kwargs.args[0] == "https://example.com/hook"
            payload = call_kwargs.kwargs["json"]
            assert payload["high_or_critical_count"] == 3
            assert payload["organization"] == "Test Org"

    @pytest.mark.asyncio
    async def test_webhook_failure_does_not_raise(self):
        from core.notifications import send_scan_notification

        org = type("Org", (), {"notification_webhook_url": "https://example.com/hook",
                               "name": "Test", "id": "o1"})()
        run = type("Run", (), {"id": "r1", "status": "success", "trigger": "manual",
                                "findings_count": 1, "completed_at": None})()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("connection refused")
            sent = await send_scan_notification(org, run, {"critical": 1, "high": 0, "medium": 0, "low": 0})
            assert sent is False  # never raises


@pytest_asyncio.fixture
async def sched_engine(monkeypatch):
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False},
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(db_engine_module, "AsyncSessionLocal", TestSessionLocal)

    yield TestSessionLocal

    await test_engine.dispose()


class TestScheduledScanDueCheck:
    @pytest.mark.asyncio
    async def test_never_scanned_org_is_due(self, sched_engine):
        from db.models.organization import Organization
        from db.models.aws_account import AWSAccount, AccountStatus
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="Never Scanned", slug="never-scanned", scan_frequency="daily")
            db.add(org)
            await db.flush()
            db.add(AWSAccount(
                organization_id=org.id, aws_account_id="123456789012",
                display_name="Acc", role_arn="arn:aws:iam::123456789012:role/X",
                external_id="cg-abc", primary_region="us-east-1", status=AccountStatus.active,
            ))
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert any(o.slug == "never-scanned" for o, _ in due)

    @pytest.mark.asyncio
    async def test_manual_frequency_org_never_due(self, sched_engine):
        from db.models.organization import Organization
        from db.models.aws_account import AWSAccount, AccountStatus
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="Manual Org", slug="manual-org", scan_frequency="manual")
            db.add(org)
            await db.flush()
            db.add(AWSAccount(
                organization_id=org.id, aws_account_id="123456789012",
                display_name="Acc", role_arn="arn:aws:iam::123456789012:role/X",
                external_id="cg-abc", primary_region="us-east-1", status=AccountStatus.active,
            ))
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert not any(o.slug == "manual-org" for o, _ in due)

    @pytest.mark.asyncio
    async def test_recently_scanned_daily_org_not_due(self, sched_engine):
        from db.models.organization import Organization
        from db.models.aws_account import AWSAccount, AccountStatus
        from db.models.scan_run import ScanRun
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="Recent Org", slug="recent-org", scan_frequency="daily")
            db.add(org)
            await db.flush()
            db.add(AWSAccount(
                organization_id=org.id, aws_account_id="123456789012",
                display_name="Acc", role_arn="arn:aws:iam::123456789012:role/X",
                external_id="cg-abc", primary_region="us-east-1", status=AccountStatus.active,
            ))
            db.add(ScanRun(
                organization_id=org.id, status="success", trigger="scheduled",
                started_at=datetime.now(timezone.utc) - timedelta(hours=2),
                completed_at=datetime.now(timezone.utc) - timedelta(hours=2),
                accounts_targeted=1, accounts_succeeded=1,
            ))
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert not any(o.slug == "recent-org" for o, _ in due)

    @pytest.mark.asyncio
    async def test_stale_daily_org_is_due(self, sched_engine):
        from db.models.organization import Organization
        from db.models.aws_account import AWSAccount, AccountStatus
        from db.models.scan_run import ScanRun
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="Stale Org", slug="stale-org", scan_frequency="daily")
            db.add(org)
            await db.flush()
            db.add(AWSAccount(
                organization_id=org.id, aws_account_id="123456789012",
                display_name="Acc", role_arn="arn:aws:iam::123456789012:role/X",
                external_id="cg-abc", primary_region="us-east-1", status=AccountStatus.active,
            ))
            db.add(ScanRun(
                organization_id=org.id, status="success", trigger="scheduled",
                started_at=datetime.now(timezone.utc) - timedelta(days=2),
                completed_at=datetime.now(timezone.utc) - timedelta(days=2),
                accounts_targeted=1, accounts_succeeded=1,
            ))
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert any(o.slug == "stale-org" for o, _ in due)

    @pytest.mark.asyncio
    async def test_hourly_org_due_after_90_minutes(self, sched_engine):
        from db.models.organization import Organization
        from db.models.aws_account import AWSAccount, AccountStatus
        from db.models.scan_run import ScanRun
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="Hourly Org", slug="hourly-org", scan_frequency="hourly")
            db.add(org)
            await db.flush()
            db.add(AWSAccount(
                organization_id=org.id, aws_account_id="123456789012",
                display_name="Acc", role_arn="arn:aws:iam::123456789012:role/X",
                external_id="cg-abc", primary_region="us-east-1", status=AccountStatus.active,
            ))
            db.add(ScanRun(
                organization_id=org.id, status="success", trigger="scheduled",
                started_at=datetime.now(timezone.utc) - timedelta(minutes=90),
                completed_at=datetime.now(timezone.utc) - timedelta(minutes=90),
                accounts_targeted=1, accounts_succeeded=1,
            ))
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert any(o.slug == "hourly-org" for o, _ in due)

    @pytest.mark.asyncio
    async def test_org_with_no_active_accounts_never_due(self, sched_engine):
        from db.models.organization import Organization
        from workers.tasks import _due_orgs_for_scheduled_scan

        async with sched_engine() as db:
            org = Organization(name="No Accounts Org", slug="no-accounts-org", scan_frequency="hourly")
            db.add(org)
            await db.commit()

        due = await _due_orgs_for_scheduled_scan()
        assert not any(o.slug == "no-accounts-org" for o, _ in due)
