"""
Billing routes — Stripe Checkout, Customer Portal, Webhooks, and usage.

POST /billing/checkout          Create Stripe Checkout session (upgrade)
POST /billing/portal            Create Stripe Customer Portal session
POST /billing/webhook           Stripe webhook handler (no auth — uses signature)
GET  /billing/subscription      Current plan + usage for the authenticated org
GET  /billing/plans             All available plans (public — no auth required)
"""
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from billing.stripe_config import (
    PLANS, PRICE_ID_TO_PLAN, STRIPE_PUBLISHABLE_KEY,
    PlanTier, get_stripe,
)
import billing.stripe_config as _stripe_cfg

STRIPE_WEBHOOK_SECRET = _stripe_cfg.STRIPE_WEBHOOK_SECRET
from billing.usage_tracker import get_usage_summary, check_alert_limit
from core.auth import CurrentUser, get_current_user, require_role
from db.engine import get_db
from db.models.organization import Organization
from db.repositories.organization_repo import OrganizationRepository, PLAN_LIMITS

logger = logging.getLogger("cloud_guardian.api.billing")
router = APIRouter(prefix="/billing", tags=["Billing"])


FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")


class CheckoutRequest(BaseModel):
    plan: str

class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str

class PortalResponse(BaseModel):
    portal_url: str

class PlanInfo(BaseModel):
    tier: str
    display_name: str
    price_usd_monthly: int
    max_aws_accounts: int
    max_monthly_alerts: int
    features: list[str]
    stripe_price_id: str

class SubscriptionResponse(BaseModel):
    plan: PlanInfo
    stripe_customer_id: Optional[str]
    stripe_subscription_status: Optional[str]
    usage: dict
    publishable_key: str

class AllPlansResponse(BaseModel):
    plans: list[PlanInfo]


def _plan_info(tier: str) -> PlanInfo:
    p = PLANS[tier]
    return PlanInfo(
        tier=p.tier, display_name=p.display_name,
        price_usd_monthly=p.price_usd_monthly,
        max_aws_accounts=p.max_aws_accounts,
        max_monthly_alerts=p.max_monthly_alerts,
        features=p.features,
        stripe_price_id=p.stripe_price_id,
    )


async def _get_org(db: AsyncSession, org_id: str) -> Organization:
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


async def _ensure_stripe_customer(stripe, org: Organization, db: AsyncSession) -> str:
    """
    Get or create a Stripe Customer for the org.
    Stores the customer ID on the org record for future calls.
    """
    if org.stripe_customer_id:
        return org.stripe_customer_id

    customer = stripe.Customer.create(
        email=org.billing_email,
        name=org.name,
        metadata={"org_id": org.id, "org_slug": org.slug},
    )
    org.stripe_customer_id = customer.id
    await db.flush()
    await db.commit()
    logger.info(f"Created Stripe customer {customer.id} for org {org.slug}")
    return customer.id


@router.get("/plans", response_model=AllPlansResponse)
async def list_plans():
    """Return all available plans. Public — no auth required. Used for pricing page."""
    return AllPlansResponse(plans=[_plan_info(t) for t in PLANS])


@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current org's plan, Stripe subscription status, and usage for this billing period."""
    org = await _get_org(db, current_user.organization_id)
    usage = await get_usage_summary(db, current_user.organization_id)


    stripe_status = None
    if org.stripe_customer_id:
        try:
            stripe = get_stripe()
            subs = stripe.Subscription.list(customer=org.stripe_customer_id, limit=1)
            if subs.data:
                stripe_status = subs.data[0].status
        except Exception as e:
            logger.warning(f"Could not fetch Stripe subscription for org {org.id}: {e}")

    return SubscriptionResponse(
        plan=_plan_info(org.plan),
        stripe_customer_id=org.stripe_customer_id,
        stripe_subscription_status=stripe_status,
        usage=usage,
        publishable_key=STRIPE_PUBLISHABLE_KEY,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_session(
    body: CheckoutRequest,
    current_user: CurrentUser = Depends(require_role("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a Stripe Checkout session to upgrade the org's plan.

    Returns a checkout_url — redirect the user's browser to this URL.
    Stripe handles the payment form; on success it redirects back to
    FRONTEND_URL/billing/success?session_id=...

    Only owner and admin can initiate upgrades.
    """
    plan_key = body.plan.lower()
    if plan_key not in PLANS or plan_key == "free":
        raise HTTPException(status_code=400, detail=f"Invalid plan '{body.plan}'. Choose: starter, pro, enterprise")

    plan_config = PLANS[plan_key]
    if not plan_config.stripe_price_id:
        raise HTTPException(
            status_code=503,
            detail=f"Stripe Price ID for '{plan_key}' not configured. "
                   f"Set STRIPE_PRICE_{plan_key.upper()} in your .env file."
        )

    org = await _get_org(db, current_user.organization_id)


    current_plan_order = list(PLANS.keys())
    current_idx = current_plan_order.index(org.plan)
    target_idx  = current_plan_order.index(plan_key)
    if target_idx <= current_idx:
        raise HTTPException(
            status_code=400,
            detail=f"You're already on the {org.plan} plan. "
                   f"To downgrade, use the Customer Portal."
        )

    try:
        stripe = get_stripe()
        customer_id = await _ensure_stripe_customer(stripe, org, db)

        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode="subscription",
            line_items=[{"price": plan_config.stripe_price_id, "quantity": 1}],
            success_url=f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{FRONTEND_URL}/billing",
            metadata={
                "org_id":    org.id,
                "org_slug":  org.slug,
                "plan":      plan_key,
            },
            subscription_data={
                "metadata": {
                    "org_id": org.id,
                    "plan":   plan_key,
                }
            },
            allow_promotion_codes=True,
        )
        logger.info(f"Checkout session {session.id} created for org {org.slug} → {plan_key}")
        return CheckoutResponse(checkout_url=session.url, session_id=session.id)

    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Stripe checkout error for org {org.id}: {e}", exc_info=True)
        raise HTTPException(status_code=502, detail=f"Stripe error: {e}")


@router.post("/portal", response_model=PortalResponse)
async def create_customer_portal(
    current_user: CurrentUser = Depends(require_role("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a Stripe Customer Portal session for managing subscriptions,
    payment methods, invoices, and cancellation.
    """
    org = await _get_org(db, current_user.organization_id)

    if not org.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No active subscription found. Upgrade your plan first."
        )

    try:
        stripe = get_stripe()
        session = stripe.billing_portal.Session.create(
            customer=org.stripe_customer_id,
            return_url=f"{FRONTEND_URL}/billing",
        )
        return PortalResponse(portal_url=session.url)

    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Stripe portal error for org {org.id}: {e}", exc_info=True)
        raise HTTPException(status_code=502, detail=f"Stripe error: {e}")


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """
    Stripe webhook endpoint — receives real-time subscription events.

    IMPORTANT: This endpoint uses Stripe signature verification instead
    of JWT auth. Register it in the Stripe dashboard:
    Developers → Webhooks → Add endpoint → URL: https://yourdomain.com/billing/webhook

    Events handled:
      checkout.session.completed      → upgrade plan after successful payment
      customer.subscription.updated   → handle plan changes / reactivations
      customer.subscription.deleted   → downgrade to free on cancellation
      invoice.payment_failed          → notify org of payment failure
      invoice.payment_succeeded       → confirm subscription is healthy
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=503,
            detail="STRIPE_WEBHOOK_SECRET not configured. Set it in your .env file."
        )

    payload = await request.body()

    try:
        stripe = get_stripe()
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

    event_type = event["type"]
    logger.info(f"Stripe webhook received: {event_type}")

    try:
        if event_type == "checkout.session.completed":
            await _handle_checkout_completed(event["data"]["object"], db)

        elif event_type == "customer.subscription.updated":
            await _handle_subscription_updated(event["data"]["object"], db)

        elif event_type == "customer.subscription.deleted":
            await _handle_subscription_deleted(event["data"]["object"], db)

        elif event_type == "invoice.payment_failed":
            await _handle_payment_failed(event["data"]["object"], db)

        elif event_type == "invoice.payment_succeeded":
            logger.info(f"Payment succeeded for customer {event['data']['object'].get('customer')}")

        else:
            logger.debug(f"Unhandled Stripe event type: {event_type}")

    except Exception as e:
        logger.error(f"Error handling webhook {event_type}: {e}", exc_info=True)

        return {"status": "error_logged", "event": event_type}

    return {"status": "ok", "event": event_type}


async def _handle_checkout_completed(session: dict, db: AsyncSession):
    """Upgrade plan after successful Stripe Checkout payment."""
    org_id = session.get("metadata", {}).get("org_id")
    plan   = session.get("metadata", {}).get("plan")

    if not org_id or not plan:
        logger.warning(f"checkout.session.completed missing metadata: {session.get('id')}")
        return

    org = await db.get(Organization, org_id)
    if not org:
        logger.error(f"Org {org_id} not found during checkout completion")
        return

    repo = OrganizationRepository(db)
    await repo.update_plan(org_id, plan)
    await db.commit()
    logger.info(f"Upgraded org {org_id} ({org.slug}) to plan '{plan}' via checkout")


async def _handle_subscription_updated(subscription: dict, db: AsyncSession):
    """Handle plan changes from the Customer Portal."""
    customer_id = subscription.get("customer")
    status      = subscription.get("status")
    items       = subscription.get("items", {}).get("data", [])

    if not customer_id or not items:
        return


    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        logger.warning(f"No org found for Stripe customer {customer_id}")
        return


    price_id = items[0].get("price", {}).get("id", "")
    new_plan  = PRICE_ID_TO_PLAN.get(price_id)

    if new_plan and status in ("active", "trialing"):
        repo = OrganizationRepository(db)
        await repo.update_plan(org.id, new_plan)
        await db.commit()
        logger.info(f"Updated org {org.slug} plan to '{new_plan}' (subscription update, status={status})")

    elif status in ("past_due", "unpaid"):
        logger.warning(f"Subscription for org {org.slug} is {status} — payment attention needed")


async def _handle_subscription_deleted(subscription: dict, db: AsyncSession):
    """Downgrade to free when subscription is cancelled."""
    customer_id = subscription.get("customer")
    if not customer_id:
        return

    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        return

    repo = OrganizationRepository(db)
    await repo.update_plan(org.id, PlanTier.free)
    await db.commit()
    logger.info(f"Downgraded org {org.slug} to free (subscription cancelled)")


async def _handle_payment_failed(invoice: dict, db: AsyncSession):
    """Log payment failures. In production: send email notification."""
    customer_id = invoice.get("customer")
    attempt_count = invoice.get("attempt_count", 1)
    amount = invoice.get("amount_due", 0) / 100

    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    org_slug = org.slug if org else customer_id

    logger.warning(
        f"Payment failed for org {org_slug}: "
        f"${amount:.2f} (attempt {attempt_count}). "
        f"Invoice: {invoice.get('id')}"
    )

