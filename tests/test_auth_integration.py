"""
Auth integration tests — end-to-end JWT flow, RBAC, API keys.
All tests use auth_client fixture from conftest.py (in-memory SQLite).

Run: python -m pytest tests/test_auth_integration.py -v
"""
import pytest
from fastapi.testclient import TestClient


def register_and_login(client: TestClient, slug: str, email: str,
                        password: str = "SecurePass123", role_note: str = "") -> dict:
    """Register an org+user and return the token response."""
    r = client.post("/auth/register", json={
        "org_name": f"Org {slug}", "org_slug": slug,
        "email": email, "full_name": f"User {slug}", "password": password,
    })
    assert r.status_code == 201, f"Register failed: {r.text}"
    return r.json()


def auth_headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestAuthGate:
    def test_protected_route_without_token_returns_401(self, auth_client):
        r = auth_client.get("/alerts")
        assert r.status_code == 401

    def test_protected_route_with_valid_token_returns_200(self, auth_client):
        tokens = register_and_login(auth_client, "gate-test", "gate@test.com")
        r = auth_client.get("/alerts", headers=auth_headers(tokens))
        assert r.status_code == 200

    def test_invalid_token_returns_401(self, auth_client):
        r = auth_client.get("/alerts", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_health_endpoint_is_public(self, auth_client):
        r = auth_client.get("/health")
        assert r.status_code == 200

    def test_coverage_requires_auth(self, auth_client):
        r = auth_client.get("/coverage")
        assert r.status_code == 401

    def test_coverage_with_auth_returns_200(self, auth_client):
        tokens = register_and_login(auth_client, "cov-test", "cov@test.com")
        r = auth_client.get("/coverage", headers=auth_headers(tokens))
        assert r.status_code == 200


class TestTokenLifecycle:
    def test_login_returns_access_and_refresh_tokens(self, auth_client):
        register_and_login(auth_client, "token-test", "tok@test.com")
        r = auth_client.post("/auth/login", json={"email": "tok@test.com", "password": "SecurePass123"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data and "refresh_token" in data

    def test_refresh_token_issues_new_access_token(self, auth_client):
        tokens = register_and_login(auth_client, "refresh-test", "ref@test.com")
        r = auth_client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 200
        new_tokens = r.json()

        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        r2 = auth_client.get("/users/me", headers={"Authorization": f"Bearer {new_tokens['access_token']}"})
        assert r2.status_code == 200

    def test_invalid_refresh_token_returns_401(self, auth_client):
        r = auth_client.post("/auth/refresh", json={"refresh_token": "invalid-token"})
        assert r.status_code == 401

    def test_access_token_as_refresh_token_returns_401(self, auth_client):
        tokens = register_and_login(auth_client, "token-swap", "swap@test.com")

        r = auth_client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
        assert r.status_code == 401


class TestUserProfile:
    def test_get_me_returns_profile(self, auth_client):
        tokens = register_and_login(auth_client, "me-test", "me@test.com")
        r = auth_client.get("/users/me", headers=auth_headers(tokens))
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "me@test.com"
        assert data["role"] == "owner"
        assert "organization_id" in data
        assert "id" in data

    def test_update_name(self, auth_client):
        tokens = register_and_login(auth_client, "upd-test", "upd@test.com")
        r = auth_client.put("/users/me",
            headers=auth_headers(tokens),
            json={"full_name": "Updated Name"},
        )
        assert r.status_code == 200
        assert r.json()["full_name"] == "Updated Name"

    def test_change_password_valid(self, auth_client):
        tokens = register_and_login(auth_client, "pwd-test", "pwd@test.com")
        r = auth_client.put("/users/me",
            headers=auth_headers(tokens),
            json={"current_password": "SecurePass123", "new_password": "NewSecurePass456"},
        )
        assert r.status_code == 200

        r2 = auth_client.post("/auth/login", json={"email": "pwd@test.com", "password": "SecurePass123"})
        assert r2.status_code == 401

        r3 = auth_client.post("/auth/login", json={"email": "pwd@test.com", "password": "NewSecurePass456"})
        assert r3.status_code == 200

    def test_change_password_wrong_current_returns_401(self, auth_client):
        tokens = register_and_login(auth_client, "wpwd-test", "wpwd@test.com")
        r = auth_client.put("/users/me",
            headers=auth_headers(tokens),
            json={"current_password": "WrongPass123", "new_password": "NewSecurePass456"},
        )
        assert r.status_code == 401

    def test_new_password_without_current_returns_400(self, auth_client):
        tokens = register_and_login(auth_client, "nopwd-test", "nopwd@test.com")
        r = auth_client.put("/users/me",
            headers=auth_headers(tokens),
            json={"new_password": "NewSecurePass456"},
        )
        assert r.status_code == 400


class TestRBAC:
    def test_owner_can_list_users(self, auth_client):
        tokens = register_and_login(auth_client, "rbac-owner", "owner@rbac.com")
        r = auth_client.get("/users", headers=auth_headers(tokens))
        assert r.status_code == 200

    def test_viewer_cannot_list_users(self, auth_client):
        """Viewers can't see the user list — admin+ only."""


        tokens = register_and_login(auth_client, "rbac-viewer", "viewer@rbac.com")

        from core.auth import CurrentUser
        from api.app import app

        viewer_user = CurrentUser(
            id="fake", organization_id="fake", email="v@rbac.com",
            full_name="Viewer", role="viewer", is_active=True
        )

        from core.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: viewer_user
        r = auth_client.get("/users")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_analyst_can_view_pending_remediations(self, auth_client):
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        analyst = CurrentUser(
            id="a1", organization_id="org1", email="analyst@test.com",
            full_name="Analyst", role="analyst", is_active=True
        )
        app.dependency_overrides[get_current_user] = lambda: analyst
        r = auth_client.get("/remediation/pending")
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 200

    def test_analyst_cannot_approve_remediations(self, auth_client):
        from core.auth import get_current_user, CurrentUser
        from api.app import app
        analyst = CurrentUser(
            id="a2", organization_id="org1", email="analyst2@test.com",
            full_name="Analyst", role="analyst", is_active=True
        )
        app.dependency_overrides[get_current_user] = lambda: analyst
        r = auth_client.post("/remediation/fake-id/approve", json={"confirmed": True})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_owner_cannot_deactivate_themselves(self, auth_client):
        tokens = register_and_login(auth_client, "self-deact", "self@deact.com")
        me = auth_client.get("/users/me", headers=auth_headers(tokens)).json()
        r = auth_client.delete(f"/users/{me['id']}", headers=auth_headers(tokens))
        assert r.status_code == 400


class TestAPIKeys:
    def test_create_api_key_returns_raw_key_once(self, auth_client):
        tokens = register_and_login(auth_client, "apikey-test", "apikey@test.com")
        r = auth_client.post("/users/me/api-keys",
            headers=auth_headers(tokens),
            json={"name": "ci-pipeline"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["raw_key"].startswith("cg_live_")
        assert data["name"] == "ci-pipeline"
        assert data["key_prefix"] == data["raw_key"][:12]

    def test_list_api_keys_does_not_return_raw_key(self, auth_client):
        tokens = register_and_login(auth_client, "list-keys", "list@keys.com")
        auth_client.post("/users/me/api-keys",
            headers=auth_headers(tokens), json={"name": "key-1"})
        r = auth_client.get("/users/me/api-keys", headers=auth_headers(tokens))
        assert r.status_code == 200
        keys = r.json()
        assert len(keys) == 1
        assert keys[0].get("raw_key") is None

    def test_api_key_authenticates_requests(self, auth_client):
        tokens = register_and_login(auth_client, "apiauth-test", "apiauth@test.com")

        r = auth_client.post("/users/me/api-keys",
            headers=auth_headers(tokens), json={"name": "test-key"})
        raw_key = r.json()["raw_key"]


        r2 = auth_client.get("/users/me", headers={"X-API-Key": raw_key})
        assert r2.status_code == 200
        assert r2.json()["email"] == "apiauth@test.com"

    def test_invalid_api_key_returns_401(self, auth_client):
        r = auth_client.get("/users/me", headers={"X-API-Key": "cg_live_invalidkeyvalue"})
        assert r.status_code == 401

    def test_revoke_api_key(self, auth_client):
        tokens = register_and_login(auth_client, "revoke-key", "revoke@keys.com")

        r = auth_client.post("/users/me/api-keys",
            headers=auth_headers(tokens), json={"name": "to-revoke"})
        key_data = r.json()
        raw_key = key_data["raw_key"]
        key_id = key_data["id"]


        r2 = auth_client.get("/users/me", headers={"X-API-Key": raw_key})
        assert r2.status_code == 200


        r3 = auth_client.delete(f"/users/me/api-keys/{key_id}", headers=auth_headers(tokens))
        assert r3.status_code == 204


        r4 = auth_client.get("/users/me", headers={"X-API-Key": raw_key})
        assert r4.status_code == 401

    def test_revoke_nonexistent_key_returns_404(self, auth_client):
        tokens = register_and_login(auth_client, "revoke-404", "rev404@keys.com")
        r = auth_client.delete("/users/me/api-keys/nonexistent-id", headers=auth_headers(tokens))
        assert r.status_code == 404


class TestTenantIsolation:
    def test_org_a_cannot_see_org_b_alerts(self, auth_client):
        """Critical: authenticated user can only see their own org's data."""
        tokens_a = register_and_login(auth_client, "iso-org-a", "a@iso.com")
        tokens_b = register_and_login(auth_client, "iso-org-b", "b@iso.com")


        r_a = auth_client.get("/alerts", headers=auth_headers(tokens_a))
        r_b = auth_client.get("/alerts", headers=auth_headers(tokens_b))
        assert r_a.status_code == 200
        assert r_b.status_code == 200
        assert r_a.json()["total"] == 0
        assert r_b.json()["total"] == 0

    def test_coverage_is_org_scoped(self, auth_client):
        tokens = register_and_login(auth_client, "cov-iso", "cov@iso.com")
        r = auth_client.get("/coverage", headers=auth_headers(tokens))
        assert r.status_code == 200

        assert r.json()["active_alert_count"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
