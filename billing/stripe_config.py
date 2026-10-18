"""
Stripe configuration and plan → Price ID mapping.

After creating products in the Stripe dashboard, paste the Price IDs
into your .env file. The mapping here reads them from environment variables
so no real values are ever hardcoded.

.env variables required:
  STRIPE_SECRET_KEY        sk_test_... (or sk_live_... in production)
  STRIPE_PUBLISHABLE_KEY   pk_test_...
  STRIPE_WEBHOOK_SECRET    whsec_...
  STRIPE_PRICE_STARTER     price_...  ($49/mo)
  STRIPE_PRICE_PRO         price_...  ($199/mo)
  STRIPE_PRICE_ENTERPRISE  price_...  ($499/mo)
"""
import os
from dataclasses import dataclass
from enum import Enum


class PlanTier(str, Enum):
    free       = "free"
    starter    = "starter"
    pro        = "pro"
    enterprise = "enterprise"


@dataclass(frozen=True)
class PlanConfig:
    tier: PlanTier
    display_name: str
    price_usd_monthly: int
    stripe_price_id: str
    max_aws_accounts: int
    max_monthly_alerts: int
    features: list[str]


PLANS: dict[str, PlanConfig] = {
    PlanTier.free: PlanConfig(
        tier=PlanTier.free,
        display_name="Free",
        price_usd_monthly=0,
        stripe_price_id="",
        max_aws_accounts=1,
        max_monthly_alerts=100,
        features=[
            "1 AWS account",
            "100 alerts/month",
            "CloudTrail detection",
            "MITRE ATT&CK mapping",
            "7-day alert history",
        ],
    ),
    PlanTier.starter: PlanConfig(
        tier=PlanTier.starter,
        display_name="Starter",
        price_usd_monthly=49,
        stripe_price_id=os.environ.get("STRIPE_PRICE_STARTER", ""),
        max_aws_accounts=3,
        max_monthly_alerts=1_000,
        features=[
            "3 AWS accounts",
            "1,000 alerts/month",
            "CloudTrail + GuardDuty",
            "ML anomaly detection",
            "30-day alert history",
            "Email notifications",
            "SNS integration",
        ],
    ),
    PlanTier.pro: PlanConfig(
        tier=PlanTier.pro,
        display_name="Pro",
        price_usd_monthly=199,
        stripe_price_id=os.environ.get("STRIPE_PRICE_PRO", ""),
        max_aws_accounts=10,
        max_monthly_alerts=10_000,
        features=[
            "10 AWS accounts",
            "10,000 alerts/month",
            "All detection sources",
            "Auto-remediation",
            "90-day alert history",
            "Slack + PagerDuty",
            "API access",
            "Priority support",
        ],
    ),
    PlanTier.enterprise: PlanConfig(
        tier=PlanTier.enterprise,
        display_name="Enterprise",
        price_usd_monthly=499,
        stripe_price_id=os.environ.get("STRIPE_PRICE_ENTERPRISE", ""),
        max_aws_accounts=999,
        max_monthly_alerts=999_999,
        features=[
            "Unlimited AWS accounts",
            "Unlimited alerts",
            "Custom MITRE rules",
            "SOC 2 compliance reports",
            "Dedicated Slack channel",
            "SLA guarantee",
            "Custom integrations",
            "Audit log export",
        ],
    ),
}


def get_stripe():
    """Return configured stripe module. Raises ImportError if not installed."""
    import stripe as _stripe
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key:
        raise ValueError(
            "STRIPE_SECRET_KEY not set. Add it to your .env file.\n"
            "Get it from: https://dashboard.stripe.com/test/apikeys"
        )
    _stripe.api_key = key
    return _stripe


STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET  = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


PRICE_ID_TO_PLAN: dict[str, str] = {
    plan.stripe_price_id: tier
    for tier, plan in PLANS.items()
    if plan.stripe_price_id
}
