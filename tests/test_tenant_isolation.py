"""
Cross-tenant isolation: for every list/detail route that filters by
organization_id, org B must not read or mutate org A's resources.

Two orgs are registered through the real auth API. Org A's incident and
remediation rows are seeded directly into the same in-memory DB the app uses
(via auth_client.session_factory), then org B is asserted to get 404 or an
empty list, never A's data. Fast: in-memory SQLite, no AWS calls.
"""
import uuid
from datetime import datetime, timezone

import pytest

from db.models.incident import Incident, IncidentStatus, RemediationAction
from db.models.aws_account import AWSAccount, AccountStatus
from tests.test_auth_integration import auth_headers, register_and_login


def _seed_org_a_rows(client, org_id):
    """Insert one account, one incident, one remediation for org_id. Returns ids."""
    loop = client.loop

    async def _go():
        async with client.session_factory() as db:
            acct = AWSAccount(
                id=str(uuid.uuid4()), organization_id=org_id, aws_account_id="111122223333",
                display_name="org-a-prod", role_arn="arn:aws:iam::111122223333:role/cg",
                external_id="ext-a", primary_region="us-east-1", status=AccountStatus.active,
            )
            inc = Incident(
                id=str(uuid.uuid4()), organization_id=org_id, aws_account_id="111122223333",
                event_id=f"evt-{uuid.uuid4().hex[:8]}", source="cloudtrail", event_name="DeleteTrail",
                event_time=datetime.now(timezone.utc), technique_id="T1562.008",
                technique_name="Disable Cloud Logs", tactic="defense-evasion", severity=90,
                risk_tier="critical", description="org A secret incident", actor_arn="arn:aws:iam::111122223333:user/a",
                aws_region="us-east-1", status=IncidentStatus.pending_approval,
            )
            rem = RemediationAction(
                id=str(uuid.uuid4()), organization_id=org_id, incident_id=inc.id,
                action_type="restore_cloudtrail_logging", action_risk_tier="critical",
                decision="pending", detail="org A remediation",
            )
            db.add_all([acct, inc, rem])
            await db.commit()
            return {"account": acct.id, "incident": inc.id, "remediation": rem.id}

    return loop.run_until_complete(_go())


def _org_id_of(tokens):
    from core.security import decode_token
    return decode_token(tokens["access_token"])["org"]


@pytest.fixture
def tenants(auth_client):
    a = register_and_login(auth_client, "tenant-a", "owner.a@example.com")
    b = register_and_login(auth_client, "tenant-b", "owner.b@example.com")
    org_a = _org_id_of(a)
    ids = _seed_org_a_rows(auth_client, org_a)
    return auth_client, auth_headers(a), auth_headers(b), ids


class TestAlertsIsolation:
    def test_org_b_alert_list_excludes_org_a(self, tenants):
        client, _, hb, ids = tenants
        r = client.get("/alerts", headers=hb)
        assert r.status_code == 200
        assert ids["incident"] not in r.text
        assert "org A secret incident" not in r.text

    def test_org_b_cannot_read_org_a_alert_detail(self, tenants):
        client, _, hb, ids = tenants
        r = client.get(f"/alerts/{ids['incident']}", headers=hb)
        assert r.status_code == 404
        assert "org A secret incident" not in r.text


class TestRemediationIsolation:
    def test_org_b_pending_list_excludes_org_a(self, tenants):
        client, _, hb, ids = tenants
        r = client.get("/remediation/pending", headers=hb)
        assert r.status_code == 200
        assert "org A secret incident" not in r.text

    def test_org_b_cannot_approve_org_a_incident(self, tenants):
        client, _, hb, ids = tenants
        r = client.post(f"/remediation/{ids['incident']}/approve", headers=hb, json={})
        assert r.status_code in (404, 403, 409, 422)
        assert "org A secret incident" not in r.text

    def test_org_b_cannot_dismiss_org_a_incident(self, tenants):
        client, _, hb, ids = tenants
        r = client.post(f"/remediation/{ids['incident']}/dismiss", headers=hb, json={"reason": "x"})
        assert r.status_code in (404, 403, 422)

    def test_org_b_cannot_read_org_a_remediation_status(self, tenants):
        client, _, hb, ids = tenants
        r = client.get(f"/remediation/{ids['incident']}/status", headers=hb)
        assert r.status_code == 404
        assert "org A remediation" not in r.text


class TestAccountsIsolation:
    def test_org_b_account_list_excludes_org_a(self, tenants):
        client, _, hb, ids = tenants
        r = client.get("/accounts", headers=hb)
        assert r.status_code == 200
        assert "org-a-prod" not in r.text
        assert ids["account"] not in r.text

    def test_org_b_cannot_read_org_a_account_detail(self, tenants):
        client, _, hb, ids = tenants
        r = client.get(f"/accounts/{ids['account']}", headers=hb)
        assert r.status_code == 404
        assert "org-a-prod" not in r.text

    def test_org_b_cannot_delete_org_a_account(self, tenants):
        client, _, hb, ids = tenants
        r = client.delete(f"/accounts/{ids['account']}", headers=hb)
        assert r.status_code in (404, 403)


class TestDashboardAndOtherRoutesIsolation:
    def test_dashboard_summary_counts_are_org_scoped(self, tenants):
        client, _, hb, _ = tenants
        r = client.get("/dashboard/summary", headers=hb)
        assert r.status_code == 200
        body = r.json()
        assert body["total_findings"] == 0
        assert body["connected_accounts"] == 0

    def test_scan_runs_list_is_org_scoped(self, tenants):
        client, _, hb, _ = tenants
        r = client.get("/scan/runs", headers=hb)
        assert r.status_code == 200
        assert "org A" not in r.text
