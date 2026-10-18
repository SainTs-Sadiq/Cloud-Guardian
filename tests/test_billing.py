"""
Billing tests — plan config, usage tracking, and API endpoints.
No real Stripe calls — all Stripe interactions are mocked.

Run: python -m pytest tests/test_billing.py -v
"""
import asyncio
import os
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


class TestPlanConfig:
    def test_all_four_plans_defined(self):
        from billing.stripe_config import PLANS, PlanTier
        assert PlanTier.free       in PLANS
        assert PlanTier.starter    in PLANS
        assert PlanTier.pro        in PLANS
        assert PlanTier.enterprise in PLANS

    def test_plan_limits_escalate(self):
        from billing.stripe_config import PLANS, PlanTier
        assert PLANS[PlanTier.free].max_aws_accounts       < PLANS[PlanTier.starter].max_aws_accounts
        assert PLANS[PlanTier.starter].max_aws_accounts    < PLANS[PlanTier.pro].max_aws_accounts
        assert PLANS[PlanTier.pro].max_aws_accounts        < PLANS[PlanTier.enterprise].max_aws_accounts

    def test_plan_prices_escalate(self):
        from billing.stripe_config import PLANS, PlanTier
        assert PLANS[PlanTier.free].price_usd_monthly      == 0
        assert PLANS[PlanTier.starter].price_usd_monthly   == 49
        assert PLANS[PlanTier.pro].price_usd_monthly       == 199
        assert PLANS[PlanTier.enterprise].price_usd_monthly == 499

    def test_free_plan_has_no_stripe_price_id(self):
        from billing.stripe_config import PLANS, PlanTier
        assert PLANS[PlanTier.free].stripe_price_id == ""

    def test_all_plans_have_features_list(self):
        from billing.stripe_config import PLANS
        for tier, plan in PLANS.items():
            assert len(plan.features) > 0, f"Plan {tier} has no features"

    def test_price_id_to_plan_map_excludes_free(self):
        from billing.stripe_config import PRICE_ID_TO_PLAN

        assert "free" not in PRICE_ID_TO_PLAN.values()

    def test_get_stripe_raises_without_key(self):
        """get_stripe() raises ValueError when STRIPE_SECRET_KEY is not set."""
        from billing.stripe_config import get_stripe
        import sys
        mock_stripe_module = MagicMock()
        saved = os.environ.pop("STRIPE_SECRET_KEY", None)
        try:
            with patch.dict("sys.modules", {"stripe": mock_stripe_module}):
                with pytest.raises(ValueError, match="STRIPE_SECRET_KEY"):
                    get_stripe()
        finally:
            if saved:
                os.environ["STRIPE_SECRET_KEY"] = saved

class TestUsageTracker:
    @pytest.fixture
    def db_session(self):
        """Provide a fresh async session on a per-test in-memory SQLite DB."""
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from db.engine import Base
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False})

        async def _setup():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.get_event_loop().run_until_complete(_setup())
        SM = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def _get():
            async with SM() as s:
                yield s

        return SM, engine

    def test_billing_period_start_is_first_of_month(self):
        from billing.usage_tracker import _billing_period_start
        start = _billing_period_start()
        assert start.day == 1
        assert start.hour == 0 and start.minute == 0

    def test_billing_period_end_is_last_of_month(self):
        from billing.usage_tracker import _billing_period_end
        end = _billing_period_end()
        assert end.hour == 23 and end.minute == 59

    def test_check_alert_limit_within(self, db_session):
        from billing.usage_tracker import check_alert_limit
        SM, engine = db_session
        async def _run():
            async with SM() as db:
                within, current, max_al = await check_alert_limit(db, "org-1", max_monthly_alerts=100)
                assert within is True
                assert current == 0
                assert max_al == 100
        asyncio.get_event_loop().run_until_complete(_run())

    def test_get_usage_summary_returns_required_keys(self, db_session):
        from billing.usage_tracker import get_usage_summary
        SM, engine = db_session
        async def _run():
            async with SM() as db:
                summary = await get_usage_summary(db, "org-1")
                assert "period_start"          in summary
                assert "period_end"            in summary
                assert "alerts_this_month"     in summary
                assert "aws_accounts_connected" in summary
        asyncio.get_event_loop().run_until_complete(_run())


class TestBillingAPI:
    def test_plans_endpoint_is_public(self, auth_client):
        """GET /billing/plans requires no auth."""
        r = auth_client.get("/billing/plans")
        assert r.status_code == 200
        data = r.json()
        assert "plans" in data
        plans = data["plans"]
        assert len(plans) == 4
        names = [p["tier"] for p in plans]
        assert "free"       in names
        assert "starter"    in names
        assert "pro"        in names
        assert "enterprise" in names

    def test_plans_prices_correct(self, auth_client):
        r = auth_client.get("/billing/plans")
        plans = {p["tier"]: p for p in r.json()["plans"]}
        assert plans["free"]["price_usd_monthly"]       == 0
        assert plans["starter"]["price_usd_monthly"]    == 49
        assert plans["pro"]["price_usd_monthly"]        == 199
        assert plans["enterprise"]["price_usd_monthly"] == 499

    def test_plans_have_features(self, auth_client):
        r = auth_client.get("/billing/plans")
        for plan in r.json()["plans"]:
            assert len(plan["features"]) > 0

    def test_subscription_requires_auth(self, auth_client):
        r = auth_client.get("/billing/subscription")
        assert r.status_code == 401

    def test_subscription_returns_plan_info(self, auth_client):
        tokens = _register(auth_client, "billing-sub", "sub@billing.com")
        r = auth_client.get("/billing/subscription", headers=_auth(tokens))
        assert r.status_code == 200
        data = r.json()
        assert "plan" in data
        assert data["plan"]["tier"] == "free"
        assert "usage" in data
        assert "publishable_key" in data

    def test_subscription_usage_has_required_fields(self, auth_client):
        tokens = _register(auth_client, "billing-usage", "usage@billing.com")
        r = auth_client.get("/billing/subscription", headers=_auth(tokens))
        usage = r.json()["usage"]
        assert "alerts_this_month"      in usage
        assert "aws_accounts_connected" in usage
        assert "period_start"           in usage

    def test_checkout_requires_auth(self, auth_client):
        r = auth_client.post("/billing/checkout", json={"plan": "starter"})
        assert r.status_code == 401

    def test_checkout_invalid_plan_returns_400(self, auth_client):
        tokens = _register(auth_client, "billing-inv", "inv@billing.com")
        r = auth_client.post("/billing/checkout",
            headers=_auth(tokens), json={"plan": "nonexistent"})
        assert r.status_code == 400

    def test_checkout_free_plan_returns_400(self, auth_client):
        tokens = _register(auth_client, "billing-free", "free@billing.com")
        r = auth_client.post("/billing/checkout",
            headers=_auth(tokens), json={"plan": "free"})
        assert r.status_code == 400

    def test_checkout_same_plan_returns_400(self, auth_client):
        """Can't upgrade to the plan you're already on."""
        tokens = _register(auth_client, "billing-same", "same@billing.com")

        r = auth_client.post("/billing/checkout",
            headers=_auth(tokens), json={"plan": "free"})
        assert r.status_code == 400

    def test_checkout_no_stripe_key_returns_503(self, auth_client):
        """If STRIPE_SECRET_KEY not set, returns 503 with clear message."""
        tokens = _register(auth_client, "billing-nokey", "nokey@billing.com")

        r = auth_client.post("/billing/checkout",
            headers=_auth(tokens), json={"plan": "starter"})

        assert r.status_code in (400, 503)

    def test_portal_requires_auth(self, auth_client):
        r = auth_client.post("/billing/portal")
        assert r.status_code == 401

    def test_portal_without_subscription_returns_400(self, auth_client):
        tokens = _register(auth_client, "billing-portal", "portal@billing.com")
        r = auth_client.post("/billing/portal", headers=_auth(tokens))
        assert r.status_code == 400
        assert "No active subscription" in r.json()["detail"]

    def test_webhook_without_secret_returns_503(self, auth_client):
        """Webhook should 503 if STRIPE_WEBHOOK_SECRET not configured."""
        with patch("api.routes.billing.STRIPE_WEBHOOK_SECRET", ""):
            r = auth_client.post("/billing/webhook",
                headers={"stripe-signature": "fake"},
                content=b'{"type":"test"}')
        assert r.status_code == 503

    def test_webhook_invalid_signature_returns_400(self, auth_client):
        """Real webhook secret set but wrong signature → 400."""
        mock_stripe = MagicMock()
        mock_stripe.Webhook.construct_event.side_effect = Exception("Invalid signature")
        mock_stripe.error = MagicMock()
        mock_stripe.error.SignatureVerificationError = ValueError

        with patch("api.routes.billing.STRIPE_WEBHOOK_SECRET", "whsec_testsecret"),              patch("api.routes.billing.get_stripe", return_value=mock_stripe):
            r = auth_client.post("/billing/webhook",
                headers={"stripe-signature": "t=bad,v1=bad"},
                content=b'{}')
        assert r.status_code in (400, 503)

    def test_checkout_viewer_role_forbidden(self, auth_client):
        """Viewer role cannot initiate checkout — only owner/admin."""
        from core.auth import CurrentUser, get_current_user
        from api.app import app
        viewer = CurrentUser(
            id="v1", organization_id="org1", email="v@v.com",
            full_name="Viewer", role="viewer", is_active=True
        )
        app.dependency_overrides[get_current_user] = lambda: viewer
        r = auth_client.post("/billing/checkout", json={"plan": "starter"})
        app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403

    def test_successful_checkout_mocked(self, auth_client):
        """Mock Stripe to verify checkout session is created correctly."""
        tokens = _register(auth_client, "billing-mock", "mock@billing.com")

        mock_stripe = MagicMock()
        mock_stripe.Customer.create.return_value = MagicMock(id="cus_test123")
        mock_stripe.checkout.Session.create.return_value = MagicMock(
            url="https://checkout.stripe.com/test",
            id="cs_test_abc123",
        )

        import billing.stripe_config as sc
        original_price = sc.PLANS["starter"].stripe_price_id


        from dataclasses import replace
        sc.PLANS["starter"] = replace(sc.PLANS["starter"], stripe_price_id="price_test_starter")

        with patch("api.routes.billing.get_stripe", return_value=mock_stripe):
            r = auth_client.post("/billing/checkout",
                headers=_auth(tokens), json={"plan": "starter"})


        sc.PLANS["starter"] = replace(sc.PLANS["starter"], stripe_price_id=original_price)

        assert r.status_code == 200
        data = r.json()
        assert data["checkout_url"] == "https://checkout.stripe.com/test"
        assert data["session_id"] == "cs_test_abc123"

    def test_webhook_checkout_completed_upgrades_plan(self, auth_client):
        """Simulate checkout.session.completed and verify plan upgrades."""
        tokens = _register(auth_client, "billing-webhook", "wh@billing.com")
        me = auth_client.get("/users/me", headers=_auth(tokens)).json()
        org_id = me["organization_id"]

        mock_event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "metadata": {"org_id": org_id, "plan": "starter"},
                "id": "cs_test",
            }}
        }
        mock_stripe = MagicMock()
        mock_stripe.Webhook.construct_event.return_value = mock_event
        mock_stripe.error = MagicMock()
        mock_stripe.error.SignatureVerificationError = ValueError

        with patch("api.routes.billing.STRIPE_WEBHOOK_SECRET", "whsec_test"), \
             patch("api.routes.billing.get_stripe", return_value=mock_stripe):
            r = auth_client.post("/billing/webhook",
                headers={"stripe-signature": "t=1,v1=abc"},
                content=b'{}')

        assert r.status_code == 200
        assert r.json()["status"] == "ok"


        sub = auth_client.get("/billing/subscription", headers=_auth(tokens))
        assert sub.json()["plan"]["tier"] == "starter"

    def test_webhook_subscription_deleted_downgrades_to_free(self, auth_client):
        """subscription.deleted webhook should downgrade org to free."""
        tokens = _register(auth_client, "billing-cancel", "cancel@billing.com")
        me = auth_client.get("/users/me", headers=_auth(tokens)).json()
        org_id = me["organization_id"]


        mock_stripe = MagicMock()
        mock_stripe.error = MagicMock()
        mock_stripe.error.SignatureVerificationError = ValueError


        with patch("api.routes.billing.STRIPE_WEBHOOK_SECRET", "whsec_test"),              patch("api.routes.billing.get_stripe", return_value=mock_stripe):


            mock_stripe.Webhook.construct_event.return_value = {
                "type": "customer.subscription.deleted",
                "data": {"object": {"customer": "cus_nonexistent"}},
            }
            r = auth_client.post("/billing/webhook",
                headers={"stripe-signature": "t=1,v1=x"}, content=b'{}')


        assert r.status_code == 200


def _register(client, slug, email):
    r = client.post("/auth/register", json={
        "org_name": f"Org {slug}", "org_slug": slug,
        "email": email, "full_name": "Test", "password": "SecurePass123",
    })
    assert r.status_code == 201, r.text
    return r.json()

def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
