"""
API smoke tests — verifies routing, auth gating, and response shapes.
Full functional tests are in test_auth_integration.py.

These tests use the auth_client fixture and a real registered user.
"""

from unittest.mock import patch

from tests.test_auth_integration import auth_headers, register_and_login
import pytest
from fastapi.testclient import TestClient


def register(client, slug, email):
    r = client.post("/auth/register", json={
        "org_name": f"Org {slug}", "org_slug": slug,
        "email": email, "full_name": "Test User", "password": "SecurePass123",
    })
    assert r.status_code == 201
    return r.json()

def auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestRoot:
    def test_root(self, auth_client):
        r = auth_client.get("/")
        assert r.status_code == 200
        assert r.json()["service"] == "Cloud Guardian"
        assert r.json()["version"] == "2.0.0"


class TestHealth:
    def test_health_is_public(self, auth_client):
        r = auth_client.get("/health")
        assert r.status_code == 200

    def test_health_is_liveness_only(self, auth_client):
        data = auth_client.get("/health").json()
        assert data == {"status": "ok"}

    def test_health_makes_no_aws_calls(self, auth_client):
        with patch("api.routes.health.check_credentials") as cc, \
             patch("api.routes.health.list_active_detectors") as ld:
            assert auth_client.get("/health").status_code == 200
        cc.assert_not_called()
        ld.assert_not_called()

    def test_health_deep_requires_auth(self, auth_client):
        assert auth_client.get("/health/deep").status_code == 401

    def test_health_deep_returns_detail_when_authenticated(self, auth_client):
        tokens = register_and_login(auth_client, "deep-health", "deep@test.com")
        with patch("api.routes.health.check_credentials", return_value={"ok": False}):
            r = auth_client.get("/health/deep", headers=auth_headers(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "no_credentials"
        for field in ["region", "guardduty_enabled", "cloudtrail_accessible",
                      "model_loaded", "remediation_enabled", "storage_backend"]:
            assert field in data, f"Missing: {field}"


class TestAlerts:
    def test_alerts_requires_auth(self, auth_client):
        assert auth_client.get("/alerts").status_code == 401

    def test_alerts_returns_empty_for_new_org(self, auth_client):
        tokens = register(auth_client, "al-smoke", "al@smoke.com")
        r = auth_client.get("/alerts", headers=auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0
        assert data["alerts"] == []
        assert isinstance(data["filters_applied"], dict)

    def test_alerts_invalid_limit_returns_422(self, auth_client):
        tokens = register(auth_client, "al-lim", "lim@smoke.com")
        r = auth_client.get("/alerts?limit=0", headers=auth(tokens))
        assert r.status_code == 422

    def test_alert_detail_404_for_unknown_id(self, auth_client):
        tokens = register(auth_client, "al-404", "404@smoke.com")
        r = auth_client.get("/alerts/nonexistent", headers=auth(tokens))
        assert r.status_code == 404


class TestCoverage:
    def test_coverage_requires_auth(self, auth_client):
        assert auth_client.get("/coverage").status_code == 401

    def test_coverage_returns_valid_structure(self, auth_client):
        tokens = register(auth_client, "cov-smoke", "cov@smoke.com")
        r = auth_client.get("/coverage", headers=auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["total_techniques_mapped"] > 0
        assert isinstance(data["tactics"], list)
        assert data["active_alert_count"] == 0

    def test_coverage_tactics_sorted_by_active_alerts(self, auth_client):
        tokens = register(auth_client, "cov-sort", "sort@smoke.com")
        r = auth_client.get("/coverage", headers=auth(tokens))
        tactics = r.json()["tactics"]
        if len(tactics) > 1:
            assert tactics[0]["active_alerts"] >= tactics[-1]["active_alerts"]


class TestRemediation:
    def test_pending_requires_analyst_min(self, auth_client):

        assert auth_client.get("/remediation/pending").status_code == 401

    def test_pending_returns_empty_for_new_org(self, auth_client):
        tokens = register(auth_client, "rem-smoke", "rem@smoke.com")
        r = auth_client.get("/remediation/pending", headers=auth(tokens))
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_approve_without_auth_returns_401(self, auth_client):
        r = auth_client.post("/remediation/fake/approve", json={"confirmed": True})
        assert r.status_code == 401

    def test_approve_confirmed_false_returns_400(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        admin = CurrentUser(id="x", organization_id="o", email="a@a.com",
                            full_name="A", role="admin", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: admin
        r = auth_client.post("/remediation/fake/approve", json={"confirmed": False})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 400

    def test_dismiss_nonexistent_returns_404(self, auth_client):
        tokens = register(auth_client, "dis-smoke", "dis@smoke.com")
        r = auth_client.post("/remediation/nonexistent/dismiss",
            headers=auth(tokens), json={"reason": "test"})
        assert r.status_code == 404

    def test_status_nonexistent_returns_404(self, auth_client):
        tokens = register(auth_client, "stat-smoke", "stat@smoke.com")
        r = auth_client.get("/remediation/nonexistent/status", headers=auth(tokens))
        assert r.status_code == 404


class TestScan:
    def test_scan_requires_auth(self, auth_client):
        assert auth_client.post("/scan", json={"minutes": 5}).status_code == 401

    def test_scan_invalid_minutes_returns_422(self, auth_client):
        tokens = register(auth_client, "scan-422", "scan422@smoke.com")
        r = auth_client.post("/scan", json={"minutes": 0}, headers=auth(tokens))
        assert r.status_code == 422

    def test_scan_no_accounts_returns_422(self, auth_client):
        """POST /scan requires at least one active AWS account."""
        tokens = register(auth_client, "scan-smoke", "scan@smoke.com")
        r = auth_client.post("/scan", json={"minutes": 5, "use_ml": False},
                              headers=auth(tokens))
        assert r.status_code == 422
        assert "No active AWS accounts" in r.json()["detail"]


class TestUsers:
    def test_users_me_requires_auth(self, auth_client):
        assert auth_client.get("/users/me").status_code == 401

    def test_users_list_requires_admin(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        viewer = CurrentUser(id="v", organization_id="o", email="v@v.com",
                             full_name="V", role="viewer", is_active=True)
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.get("/users")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_create_api_key_requires_auth(self, auth_client):
        r = auth_client.post("/users/me/api-keys", json={"name": "test"})
        assert r.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
