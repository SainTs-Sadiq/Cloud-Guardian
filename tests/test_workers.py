"""
Worker and multi-tenancy tests.
No Redis or real AWS required — tasks are called directly (eager mode).

Run: python -m pytest tests/test_workers.py -v
"""
import os
import pytest


os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"
os.environ["CELERY_TASK_EAGER_PROPAGATES"] = "true"


class TestCeleryApp:
    def test_celery_app_importable(self):
        from workers.celery_app import app
        assert app.main == "cloud_guardian"

    def test_tasks_registered(self):
        from workers.celery_app import app
        from workers import tasks
        registered = list(app.tasks.keys())
        expected = [
            "workers.tasks.run_account_scan",
            "workers.tasks.run_org_full_scan",
            "workers.tasks.run_all_accounts_scan",
            "workers.tasks.execute_remediation",
            "workers.tasks.retrain_anomaly_model",
            "workers.tasks.retrain_all_models",
        ]
        for task_name in expected:
            assert task_name in registered, f"Task not registered: {task_name}"

    def test_task_queues_configured(self):
        from workers.celery_app import app
        queue_names = [q.name for q in app.conf.task_queues]
        assert "scans" in queue_names
        assert "remediations" in queue_names
        assert "default" in queue_names

    def test_beat_schedule_has_periodic_scan(self):
        from workers.celery_app import app
        schedule = app.conf.beat_schedule
        assert "scan-all-accounts-15min" in schedule
        assert "retrain-models-daily" in schedule


class TestAWSSessionManager:
    def test_validate_role_arn_valid(self):
        from core.aws_session import validate_role_arn
        assert validate_role_arn("arn:aws:iam::123456789012:role/CloudGuardianDetectionRole")

    def test_validate_role_arn_invalid(self):
        from core.aws_session import validate_role_arn
        assert not validate_role_arn("not-an-arn")
        assert not validate_role_arn("arn:aws:s3:::my-bucket")
        assert not validate_role_arn("")

    def test_generate_external_id_deterministic(self):
        from core.aws_session import generate_external_id
        id1 = generate_external_id("org-abc-123")
        id2 = generate_external_id("org-abc-123")
        assert id1 == id2

    def test_generate_external_id_unique_per_org(self):
        from core.aws_session import generate_external_id
        assert generate_external_id("org-a") != generate_external_id("org-b")

    def test_generate_external_id_format(self):
        from core.aws_session import generate_external_id
        ext_id = generate_external_id("test-org")
        assert ext_id.startswith("cg-")
        assert len(ext_id) == 19

    def test_session_cache_stores_and_retrieves(self):
        from core.aws_session import SessionCache, TemporaryCredentials
        import time
        cache = SessionCache()
        creds = TemporaryCredentials(
            access_key_id="AKID", secret_access_key="secret",
            session_token="token", expiration=time.time() + 3600,
            role_arn="arn:aws:iam::123:role/test", aws_account_id="123", region="us-east-1",
        )
        cache.set("test-key", creds)
        retrieved = cache.get("test-key")
        assert retrieved is not None
        assert retrieved.access_key_id == "AKID"

    def test_session_cache_returns_none_for_expired(self):
        from core.aws_session import SessionCache, TemporaryCredentials
        import time
        cache = SessionCache()

        creds = TemporaryCredentials(
            access_key_id="AKID", secret_access_key="secret",
            session_token="token", expiration=time.time() - 10,
            role_arn="arn:test", aws_account_id="123", region="us-east-1",
        )
        cache.set("expired-key", creds)
        assert cache.get("expired-key") is None

    def test_session_cache_buffer_seconds(self):
        from core.aws_session import SessionCache, TemporaryCredentials
        import time
        cache = SessionCache()

        creds = TemporaryCredentials(
            access_key_id="AKID", secret_access_key="secret",
            session_token="token", expiration=time.time() + 240,
            role_arn="arn:test", aws_account_id="123", region="us-east-1",
        )
        cache.set("near-expiry", creds)

        assert cache.get("near-expiry") is None

    def test_no_role_arn_uses_default_credentials(self, monkeypatch):
        """Empty role_arn falls back to default credential chain (dev mode)."""
        from core.aws_session import get_session_for_account
        import boto3

        session = get_session_for_account(
            role_arn="", external_id=None, region="us-east-1",
            org_id="test-org", aws_account_id="123456789012",
        )
        assert isinstance(session, boto3.Session)


class TestAccountsAPI:
    def test_list_accounts_requires_auth(self, auth_client):
        r = auth_client.get("/accounts")
        assert r.status_code == 401

    def test_list_accounts_empty_for_new_org(self, auth_client):
        tokens = _register(auth_client, "acc-list", "acc@list.com")
        r = auth_client.get("/accounts", headers=_auth(tokens))
        assert r.status_code == 200
        assert r.json() == []

    def test_connect_account_invalid_arn_returns_422(self, auth_client):
        tokens = _register(auth_client, "acc-arn", "arn@test.com")
        r = auth_client.post("/accounts", headers=_auth(tokens), json={
            "aws_account_id": "123456789012",
            "display_name": "Prod",
            "role_arn": "not-a-valid-arn",
        })
        assert r.status_code == 422

    def test_connect_account_invalid_aws_id_returns_422(self, auth_client):
        tokens = _register(auth_client, "acc-id", "id@test.com")
        r = auth_client.post("/accounts", headers=_auth(tokens), json={
            "aws_account_id": "not-12-digits",
            "display_name": "Prod",
            "role_arn": "arn:aws:iam::123456789012:role/TestRole",
        })
        assert r.status_code == 422

    def test_connect_account_valid_creates_pending(self, auth_client):
        tokens = _register(auth_client, "acc-create", "create@acc.com")
        r = auth_client.post("/accounts", headers=_auth(tokens), json={
            "aws_account_id": "123456789012",
            "display_name": "Production US",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole",
            "primary_region": "us-east-1",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["aws_account_id"] == "123456789012"
        assert data["status"] == "pending"
        assert data["display_name"] == "Production US"

    def test_connect_duplicate_account_returns_409(self, auth_client):
        tokens = _register(auth_client, "acc-dup", "dup@acc.com")
        payload = {
            "aws_account_id": "123456789012",
            "display_name": "Prod",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardianDetectionRole",
        }
        auth_client.post("/accounts", headers=_auth(tokens), json=payload)
        r = auth_client.post("/accounts", headers=_auth(tokens), json=payload)
        assert r.status_code == 409

    def test_setup_guide_returns_trust_policy(self, auth_client):
        tokens = _register(auth_client, "acc-guide", "guide@acc.com")
        r = auth_client.get("/accounts/setup-guide?aws_account_id=123456789012",
                            headers=_auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert "trust_policy" in data
        assert "external_id" in data
        assert "instructions" in data
        assert len(data["instructions"]) > 0
        assert data["external_id"].startswith("cg-")

    def test_setup_guide_external_id_stable_per_org(self, auth_client):
        """Same org always gets the same external ID (deterministic)."""
        tokens = _register(auth_client, "acc-stable", "stable@acc.com")
        r1 = auth_client.get("/accounts/setup-guide?aws_account_id=111111111111", headers=_auth(tokens))
        r2 = auth_client.get("/accounts/setup-guide?aws_account_id=222222222222", headers=_auth(tokens))
        assert r1.json()["external_id"] == r2.json()["external_id"]

    def test_get_account_requires_auth(self, auth_client):
        r = auth_client.get("/accounts/some-id")
        assert r.status_code == 401

    def test_get_account_not_found_returns_404(self, auth_client):
        tokens = _register(auth_client, "acc-404", "404@acc.com")
        r = auth_client.get("/accounts/nonexistent", headers=_auth(tokens))
        assert r.status_code == 404

    def test_tenant_isolation_account_not_visible_to_other_org(self, auth_client):
        """Org B cannot see Org A's accounts."""
        tokens_a = _register(auth_client, "acc-iso-a", "a@iso.com")
        tokens_b = _register(auth_client, "acc-iso-b", "b@iso.com")


        auth_client.post("/accounts", headers=_auth(tokens_a), json={
            "aws_account_id": "111111111111",
            "display_name": "Org A Prod",
            "role_arn": "arn:aws:iam::111111111111:role/CGRole",
        })


        r = auth_client.get("/accounts", headers=_auth(tokens_b))
        assert r.status_code == 200
        assert r.json() == []

    def test_plan_limit_enforced(self, auth_client):
        """Free plan allows only 1 account — second attempt should be rejected."""
        tokens = _register(auth_client, "acc-limit", "limit@acc.com")

        auth_client.post("/accounts", headers=_auth(tokens), json={
            "aws_account_id": "111111111111", "display_name": "Account 1",
            "role_arn": "arn:aws:iam::111111111111:role/CGRole",
        })

        r = auth_client.post("/accounts", headers=_auth(tokens), json={
            "aws_account_id": "222222222222", "display_name": "Account 2",
            "role_arn": "arn:aws:iam::222222222222:role/CGRole",
        })
        assert r.status_code == 402

    def test_remove_account_requires_owner(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        analyst = CurrentUser(id="x", organization_id="o", email="a@a.com",
                              full_name="A", role="analyst", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: analyst
        r = auth_client.delete("/accounts/some-id")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_cloudformation_template_requires_auth(self, auth_client):
        r = auth_client.get("/accounts/cloudformation-template?aws_account_id=123456789012")
        assert r.status_code == 401

    def test_cloudformation_template_structure(self, auth_client):
        tokens = _register(auth_client, "acc-cfn", "cfn@acc.com")
        r = auth_client.get("/accounts/cloudformation-template?aws_account_id=123456789012",
                            headers=_auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["role_name"] == "CloudGuardianDetectionRole"
        assert data["external_id"].startswith("cg-")
        assert data["filename"].endswith(".template.json")

        tmpl = data["template"]
        assert tmpl["AWSTemplateFormatVersion"] == "2010-09-09"
        role = tmpl["Resources"]["CloudGuardianDetectionRole"]
        assert role["Type"] == "AWS::IAM::Role"
        trust_stmt = role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
        assert trust_stmt["Condition"]["StringEquals"]["sts:ExternalId"] == data["external_id"]
        assert "RoleArn" in tmpl["Outputs"]

    def test_cloudformation_template_external_id_matches_setup_guide(self, auth_client):
        """CloudFormation path and manual IAM path must produce a role Cloud Guardian can assume."""
        tokens = _register(auth_client, "acc-cfn-match", "cfnmatch@acc.com")
        guide = auth_client.get("/accounts/setup-guide?aws_account_id=123456789012",
                                headers=_auth(tokens)).json()
        cfn = auth_client.get("/accounts/cloudformation-template?aws_account_id=123456789012",
                              headers=_auth(tokens)).json()
        assert guide["external_id"] == cfn["external_id"]


class TestScanAsyncAPI:
    def test_scan_requires_auth(self, auth_client):
        r = auth_client.post("/scan", json={"minutes": 5})
        assert r.status_code == 401

    def test_scan_no_accounts_returns_422(self, auth_client):
        """Scan without connected accounts returns 422."""
        tokens = _register(auth_client, "scan-noact", "noact@scan.com")
        r = auth_client.post("/scan", json={"minutes": 5}, headers=_auth(tokens))
        assert r.status_code == 422
        assert "No active AWS accounts" in r.json()["detail"]

    def test_scan_job_status_without_redis(self, auth_client):
        """GET /scan/{job_id} returns gracefully when Redis isn't configured."""
        tokens = _register(auth_client, "scan-stat", "stat@scan.com")
        r = auth_client.get("/scan/some-job-id", headers=_auth(tokens))

        assert r.status_code == 200
        data = r.json()
        assert data["job_id"] == "some-job-id"

    def test_sync_scan_returns_valid_structure(self, auth_client, monkeypatch):
        tokens = _register(auth_client, "scan-sync", "sync@scan.com")
        import detection.cloudtrail_ingest as ct
        import detection.guardduty_ingest as gd
        monkeypatch.setattr(ct, "fetch_recent_events", lambda **kw: iter([]))
        monkeypatch.setattr(gd, "fetch_findings", lambda **kw: [])
        r = auth_client.post("/scan/sync",
            json={"minutes": 5, "use_ml": False},
            headers=_auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert "alerts_found" in data
        assert "scan_duration_seconds" in data


def _register(client, slug, email):
    r = client.post("/auth/register", json={
        "org_name": f"Org {slug}", "org_slug": slug,
        "email": email, "full_name": "Test", "password": "SecurePass123",
    })
    assert r.status_code == 201
    return r.json()

def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
