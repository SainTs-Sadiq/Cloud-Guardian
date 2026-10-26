"""
End-to-end integration tests for the Phase-1 workflow additions:
  - Standardized findings schema (service/resource_id/title/recommendation/compliance)
  - Durable scan lifecycle (ScanRun: history, last-successful)
  - Asset inventory (discovered independent of findings)
  - Dashboard APIs (summary, assets, findings, compliance, risk-score)

Uses the same moto-backed-session + shared-test-engine pattern as
test_scan_integration.py, seeding several real misconfigurations so every
endpoint has non-trivial data to report on.
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
def dash_client(monkeypatch):
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
    """See test_scan_integration.py — moto doesn't implement CloudTrail
    LookupEvents, so verify_account's direct connectivity probe needs a
    graceful fallback. Every other client passes through untouched."""
    def __init__(self, real_session):
        self._real = real_session

    def client(self, service_name, *a, **kw):
        c = self._real.client(service_name, *a, **kw)
        if service_name == "cloudtrail":
            original = c.lookup_events

            def _safe(*a2, **kw2):
                try:
                    return original(*a2, **kw2)
                except Exception:
                    return {"Events": []}
            c.lookup_events = _safe
        return c


def _seed_misconfigured_account(moto_session):
    """Seed a handful of real, varied misconfigurations across services."""
    s3 = moto_session.client("s3")
    s3.create_bucket(Bucket="dash-test-bucket")  # unencrypted, not public -> 1 finding

    ec2 = moto_session.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="dash-test-sg", Description="test", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    iam = moto_session.client("iam")
    iam.create_user(UserName="dash-test-user")
    iam.create_login_profile(UserName="dash-test-user", Password=os.environ.get("CG_TEST_IAM_PASSWORD", "Sup3rSecret!23"))  # no MFA -> finding


def _connect_and_verify(client, headers, monkeypatch, moto_session):
    r = client.post("/accounts", headers=headers, json={
        "aws_account_id": "123456789012",
        "display_name": "Dashboard Test Account",
        "role_arn": "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole",
        "primary_region": "us-east-1",
    })
    assert r.status_code == 201, r.text
    account_id = r.json()["id"]

    wrapped = _SessionWithSafeLookupEvents(moto_session)
    import api.routes.accounts as accounts_module
    monkeypatch.setattr(accounts_module, "get_session_for_account", lambda **kw: wrapped)
    import core.aws_session as aws_session_module
    monkeypatch.setattr(aws_session_module, "get_session_for_account", lambda **kw: wrapped)

    r = client.post(f"/accounts/{account_id}/verify", headers=headers)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["first_scan"]["status"] == "completed"
    assert result["first_scan"]["alerts_found"] >= 3  # unencrypted bucket + open SSH + no MFA
    return account_id, result


class TestDashboardEndToEnd:
    @mock_aws
    def test_summary_reflects_seeded_findings(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-summary-org", "summary@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/summary", headers=headers)
        assert r.status_code == 200, r.text
        summary = r.json()

        assert summary["open_findings"] >= 3
        assert summary["connected_accounts"] == 1
        assert summary["active_accounts"] == 1
        assert summary["total_assets"] >= 3  # bucket + security group + IAM user, at minimum
        assert summary["last_scan"] is not None
        assert summary["last_scan"]["status"] == "success"
        assert 0 <= summary["risk_posture_score"] <= 100
        assert summary["risk_grade"] in ("A", "B", "C", "D", "F")
        assert sum(summary["findings_by_severity"].values()) == summary["open_findings"]

    @mock_aws
    def test_findings_match_standardized_schema(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-findings-org", "findings@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/findings", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] >= 3
        assert len(body["findings"]) >= 3

        required_keys = {
            "id", "service", "resource_id", "severity", "title", "description",
            "recommendation", "compliance", "mitre", "status", "timestamp",
        }
        for f in body["findings"]:
            assert required_keys.issubset(f.keys())
            assert f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert isinstance(f["compliance"], list)
            assert isinstance(f["mitre"], list)
            assert f["mitre"][0]["technique_id"]

        event_names_seen = {f["title"] for f in body["findings"]}
        assert any("S3" in t or "MFA" in t or "SSH" in t for t in event_names_seen)

        # Config-scan findings should have real compliance mappings and recommendations.
        s3_findings = [f for f in body["findings"] if f["service"] == "S3"]
        assert s3_findings
        assert s3_findings[0]["compliance"]
        assert s3_findings[0]["recommendation"]

    @mock_aws
    def test_findings_filter_by_severity_and_service(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-filter-org", "filter@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/findings", headers=headers, params={"service": "S3"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] >= 1
        assert all(f["service"] == "S3" for f in body["findings"])

        r = client.get("/dashboard/findings", headers=headers, params={"severity": "CRITICAL"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert all(f["severity"] == "CRITICAL" for f in body["findings"])

    @mock_aws
    def test_assets_inventory_includes_clean_and_flagged_resources(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-assets-org", "assets@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        # An extra, fully-clean bucket with encryption on — should appear in
        # inventory with open_findings == 0, proving assets aren't just
        # derived from findings.
        s3 = moto_session.client("s3")
        s3.create_bucket(Bucket="dash-clean-bucket")
        s3.put_bucket_encryption(Bucket="dash-clean-bucket", ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        })

        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/assets", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] >= 4  # 2 buckets + 1 SG + 1 IAM user
        assert "S3" in body["by_service"]
        assert body["by_service"]["S3"] >= 2

        clean = [a for a in body["assets"] if a["resource_id"] == "dash-clean-bucket"]
        assert clean and clean[0]["open_findings"] == 0

        flagged = [a for a in body["assets"] if a["resource_id"] == "dash-test-bucket"]
        assert flagged and flagged[0]["open_findings"] >= 1

    @mock_aws
    def test_assets_filter_by_service(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-assets-filter-org", "assetsfilter@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/assets", headers=headers, params={"service": "IAM"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert all(a["service"] == "IAM" for a in body["assets"])
        assert body["total"] >= 1

    @mock_aws
    def test_compliance_rollup(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-compliance-org", "compliance@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/compliance", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()

        assert body["controls"]
        assert "CIS-AWS" in body["frameworks_covered"]
        assert "AWS-FSBP" in body["frameworks_covered"]
        assert all(c["open_findings"] > 0 for c in body["controls"])

        assert body["by_service"]
        s3_rollup = [s for s in body["by_service"] if s["service"] == "S3"][0]
        assert s3_rollup["total_assets"] >= 1
        assert 0 <= s3_rollup["pass_rate"] <= 100

    @mock_aws
    def test_risk_score_detail(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "dash-risk-org", "risk@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/risk-score", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()

        assert body["risk_points"] > 0
        assert 0 <= body["posture_score"] <= 100
        assert body["grade"] in ("A", "B", "C", "D", "F")
        assert set(body["breakdown"].keys()) == {"critical", "high", "medium", "low"}
        # risk_points should equal the weighted sum of the breakdown
        expected = sum(b["points"] for b in body["breakdown"].values())
        assert body["risk_points"] == expected

    @mock_aws
    def test_empty_org_has_sane_defaults(self, dash_client):
        """An org with no connected accounts shouldn't error on any dashboard endpoint."""
        client = dash_client
        tokens = _register(client, "dash-empty-org", "empty@test.com")
        headers = _auth(tokens)

        for path in ("/dashboard/summary", "/dashboard/assets", "/dashboard/findings",
                     "/dashboard/compliance", "/dashboard/risk-score"):
            r = client.get(path, headers=headers)
            assert r.status_code == 200, f"{path}: {r.text}"

        summary = client.get("/dashboard/summary", headers=headers).json()
        assert summary["open_findings"] == 0
        assert summary["connected_accounts"] == 0
        assert summary["last_scan"] is None
        assert summary["risk_posture_score"] == 100
        assert summary["risk_grade"] == "A"


class TestScanRunLifecycle:
    @mock_aws
    def test_scan_history_and_last_successful(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "scanrun-org", "scanrun@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        account_id, verify_result = _connect_and_verify(client, headers, monkeypatch, moto_session)
        scan_run_id = verify_result["first_scan"]["scan_run_id"]

        r = client.get(f"/scan/runs/{scan_run_id}", headers=headers)
        assert r.status_code == 200, r.text
        run = r.json()
        assert run["status"] == "success"
        assert run["trigger"] == "verification"
        assert run["accounts_targeted"] == 1
        assert run["accounts_succeeded"] == 1
        assert run["accounts_failed"] == 0
        assert run["findings_count"] >= 3
        assert run["completed_at"] is not None

        r = client.get("/scan/runs/last-successful", headers=headers)
        assert r.status_code == 200, r.text
        last = r.json()
        assert last["id"] == scan_run_id

        r = client.get("/scan/runs", headers=headers)
        assert r.status_code == 200, r.text
        history = r.json()
        assert history["total"] >= 1
        assert any(run["id"] == scan_run_id for run in history["runs"])

    @mock_aws
    def test_manual_scan_dispatch_creates_scan_run(self, dash_client, monkeypatch):
        client = dash_client
        tokens = _register(client, "manual-scan-org", "manualscan@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_misconfigured_account(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.post("/scan", headers=headers, json={"minutes": 15, "use_ml": False})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_run_id"]

        r = client.get(f"/scan/runs/{body['scan_run_id']}", headers=headers)
        assert r.status_code == 200
        assert r.json()["trigger"] == "manual"

    def test_no_scan_runs_yet(self, dash_client):
        client = dash_client
        tokens = _register(client, "no-scans-org", "noscans@test.com")
        headers = _auth(tokens)

        r = client.get("/scan/runs/last-successful", headers=headers)
        assert r.status_code == 200
        assert r.json() is None

        r = client.get("/scan/runs", headers=headers)
        assert r.status_code == 200
        assert r.json()["total"] == 0
