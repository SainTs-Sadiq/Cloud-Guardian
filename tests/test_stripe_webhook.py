"""
Stripe webhook hardening: unbound-name safety, version-safe signature check,
and event-id dedupe so a replayed webhook does not re-apply changes.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from api.routes import billing


class _Req:
    def __init__(self, body=b"{}"):
        self._b = body

    async def body(self):
        return self._b


async def test_get_stripe_failure_returns_503_not_name_error():
    with patch.object(billing, "STRIPE_WEBHOOK_SECRET", "whsec_test"), \
         patch.object(billing, "get_stripe", side_effect=ValueError("no key")):
        with pytest.raises(HTTPException) as ei:
            await billing.stripe_webhook(_Req(), stripe_signature="t=1,v1=x", db=MagicMock())
    assert ei.value.status_code == 503


async def test_bad_signature_detected_by_name_not_stripe_error_attr():
    class SignatureVerificationError(Exception):
        pass

    fake = MagicMock()
    fake.Webhook.construct_event.side_effect = SignatureVerificationError("bad")
    # no stripe.error attribute on the fake module: the handler must still map it to 400
    del fake.error
    with patch.object(billing, "STRIPE_WEBHOOK_SECRET", "whsec_test"), \
         patch.object(billing, "get_stripe", return_value=fake):
        with pytest.raises(HTTPException) as ei:
            await billing.stripe_webhook(_Req(), stripe_signature="bad", db=MagicMock())
    assert ei.value.status_code == 400
    assert "signature" in ei.value.detail.lower()


async def test_replayed_event_id_is_not_reapplied():
    event = {"id": "evt_123", "type": "customer.subscription.deleted", "data": {"object": {}}}
    fake = MagicMock()
    fake.Webhook.construct_event.return_value = event

    seen = MagicMock()
    seen.scalar_one_or_none.return_value = object()  # already recorded
    db = MagicMock()
    db.execute = AsyncMock(return_value=seen)
    db.commit = AsyncMock()
    handler = AsyncMock()

    with patch.object(billing, "STRIPE_WEBHOOK_SECRET", "whsec_test"), \
         patch.object(billing, "get_stripe", return_value=fake), \
         patch.object(billing, "_handle_subscription_deleted", handler):
        out = await billing.stripe_webhook(_Req(), stripe_signature="ok", db=db)

    assert out["status"] == "duplicate"
    handler.assert_not_awaited()


async def test_new_event_id_is_processed_and_recorded():
    event = {"id": "evt_new", "type": "customer.subscription.deleted", "data": {"object": {}}}
    fake = MagicMock()
    fake.Webhook.construct_event.return_value = event

    seen = MagicMock()
    seen.scalar_one_or_none.return_value = None
    db = MagicMock()
    db.execute = AsyncMock(return_value=seen)
    db.commit = AsyncMock()
    db.add = MagicMock()
    handler = AsyncMock()

    with patch.object(billing, "STRIPE_WEBHOOK_SECRET", "whsec_test"), \
         patch.object(billing, "get_stripe", return_value=fake), \
         patch.object(billing, "_handle_subscription_deleted", handler):
        out = await billing.stripe_webhook(_Req(), stripe_signature="ok", db=db)

    assert out["status"] == "ok"
    handler.assert_awaited_once()
    db.add.assert_called_once()
    db.commit.assert_awaited()



def test_checkout_stripe_error_returns_generic_message(auth_client):
    """StripeError detail must never reach the client; the real error is logged server-side."""
    from stripe import StripeError
    from tests.test_auth_integration import auth_headers, register_and_login
    secret = "sk_live_LEAK_CANARY_should_never_reach_client"
    tokens = register_and_login(auth_client, "stripe-err", "stripe-err@test.com")
    from dataclasses import replace
    priced = dict(billing.PLANS)
    priced["starter"] = replace(billing.PLANS["starter"], stripe_price_id="price_test_123")
    with patch.object(billing, "get_stripe", side_effect=StripeError(secret)), \
         patch.object(billing, "PLANS", priced):
        r = auth_client.post("/billing/checkout", json={"plan": "starter"},
                             headers=auth_headers(tokens))
    assert r.status_code == 502
    assert r.json()["detail"] == "Payment provider error. Please try again later."
    assert secret not in r.text
