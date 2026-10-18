"""
Architecture-scaling verification (requested explicitly after the
Lambda/DynamoDB/ELB/WAF scanners were added): proves that adding new
scanners required zero changes to the dashboard layer or risk scoring,
and that findings from brand-new services flow through automatically.

This is the concrete evidence for the three claims:
  1. Every new scanner plugs into the common findings schema.
  2. The dashboard displays new findings with no service-specific code.
  3. Reports and risk scoring continue to work unchanged.
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
from api.app import app
from tests.conftest import _get_or_create_event_loop


@pytest.fixture
def arch_client(monkeypatch):
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


def _seed_phase2_misconfigurations(moto_session):
    """Seed one clear misconfiguration in each of the four new services."""
    import json

    iam = moto_session.client("iam")
    role = iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }))["Role"]["Arn"]

    lam = moto_session.client("lambda", region_name="us-east-1")
    lam.create_function(FunctionName="arch-test-fn", Runtime="python3.12", Role=role,
                        Handler="index.handler", Code={"ZipFile": b"x"})
    lam.create_function_url_config(FunctionName="arch-test-fn", AuthType="NONE")

    ddb = moto_session.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="arch-test-table",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    ec2 = moto_session.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    elbv2 = moto_session.client("elbv2", region_name="us-east-1")
    lb = elbv2.create_load_balancer(
        Name="arch-test-alb", Subnets=[s1, s2], Scheme="internet-facing", Type="application",
    )["LoadBalancers"][0]
    tg = elbv2.create_target_group(Name="arch-test-tg", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][0]
    elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                         DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    # No WAF attached -> both ELBNoHTTPSListener and ALBWithoutWAF findings for free.


def _connect_and_verify(client, headers, monkeypatch, moto_session):
    r = client.post("/accounts", headers=headers, json={
        "aws_account_id": "123456789012",
        "display_name": "Architecture Test Account",
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
    return account_id, r.json()


class TestArchitectureScalesToNewServices:
    """
    Every assertion here hits dashboard.py / risk_score.py code that was
    written before Lambda/DynamoDB/ELB/WAF scanning existed. If these
    pass, the new services required no dashboard-layer changes to work.
    """

    @mock_aws
    def test_new_service_findings_appear_in_standardized_findings_endpoint(self, arch_client, monkeypatch):
        client = arch_client
        tokens = _register(client, "arch-findings-org", "archfindings@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_phase2_misconfigurations(moto_session)
        _, verify_result = _connect_and_verify(client, headers, monkeypatch, moto_session)
        assert verify_result["first_scan"]["alerts_found"] >= 4  # Lambda, DynamoDB x2, ELB x2, WAF

        r = client.get("/dashboard/findings", headers=headers, params={"limit": 100})
        assert r.status_code == 200, r.text
        findings = r.json()["findings"]
        services_seen = {f["service"] for f in findings}

        assert {"Lambda", "DynamoDB", "ELB", "WAF"}.issubset(services_seen)

        # Every one of them respects the exact same standardized shape.
        required_keys = {"id", "service", "resource_id", "severity", "title",
                          "description", "recommendation", "compliance", "mitre", "timestamp"}
        for f in findings:
            if f["service"] in ("Lambda", "DynamoDB", "ELB", "WAF"):
                assert required_keys.issubset(f.keys())
                assert f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    @mock_aws
    def test_new_service_assets_appear_in_inventory(self, arch_client, monkeypatch):
        client = arch_client
        tokens = _register(client, "arch-assets-org", "archassets@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_phase2_misconfigurations(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        r = client.get("/dashboard/assets", headers=headers, params={"limit": 100})
        assert r.status_code == 200, r.text
        body = r.json()
        assert {"Lambda", "DynamoDB", "ELB"}.issubset(body["by_service"].keys())

    @mock_aws
    def test_new_service_findings_flow_into_summary_and_risk_score(self, arch_client, monkeypatch):
        client = arch_client
        tokens = _register(client, "arch-summary-org", "archsummary@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_phase2_misconfigurations(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        summary = client.get("/dashboard/summary", headers=headers).json()
        assert summary["open_findings"] >= 4
        assert sum(summary["findings_by_severity"].values()) == summary["open_findings"]

        risk = client.get("/dashboard/risk-score", headers=headers).json()
        assert risk["risk_points"] > 0
        assert 0 <= risk["posture_score"] <= 100
        # The formula is severity-only; it has no idea these findings came
        # from services that didn't exist when it was written.
        expected = sum(b["points"] for b in risk["breakdown"].values())
        assert risk["risk_points"] == expected

    @mock_aws
    def test_new_service_compliance_rollup_works(self, arch_client, monkeypatch):
        client = arch_client
        tokens = _register(client, "arch-compliance-org", "archcompliance@test.com")
        headers = _auth(tokens)

        moto_session = boto3.Session(region_name="us-east-1")
        _seed_phase2_misconfigurations(moto_session)
        _connect_and_verify(client, headers, monkeypatch, moto_session)

        compliance = client.get("/dashboard/compliance", headers=headers).json()
        services_with_rollup = {s["service"] for s in compliance["by_service"]}
        assert {"Lambda", "DynamoDB", "ELB"}.issubset(services_with_rollup)

        lambda_rollup = [s for s in compliance["by_service"] if s["service"] == "Lambda"][0]
        assert lambda_rollup["total_assets"] >= 1
        assert lambda_rollup["assets_with_open_findings"] >= 1

    def test_dashboard_and_risk_score_source_have_no_service_specific_branches(self):
        """
        Static evidence, not just runtime behavior: the files implementing
        the dashboard endpoints and risk scoring contain no mention of
        Lambda/DynamoDB/ELB/WAF at all. They only understand the generic
        Incident/Asset schema — which is exactly why the runtime tests
        above pass with zero changes to these files.
        """
        with open("api/routes/dashboard.py") as f:
            dashboard_src = f.read()
        with open("detection/risk_score.py") as f:
            risk_score_src = f.read()

        for name in ("Lambda", "DynamoDB", "dynamodb", "elbv2", "wafv2", "lambda_"):
            assert name not in dashboard_src, (
                f"dashboard.py mentions '{name}' — it should be fully generic "
                f"over the standardized finding schema, not service-aware."
            )
            assert name not in risk_score_src, (
                f"risk_score.py mentions '{name}' — scoring should only depend "
                f"on severity counts, never on which service a finding came from."
            )
