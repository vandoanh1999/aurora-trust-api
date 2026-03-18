"""
Aurora Trust Compliance API — Authentication & Billing Middleware
"""
import os
import time
import json
import hmac
import hashlib
import stripe
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any

import database as db

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# Stripe Price IDs (set these in your .env after creating products in Stripe Dashboard)
STRIPE_PRICES = {
    "starter":    os.getenv("STRIPE_PRICE_STARTER", ""),
    "business":   os.getenv("STRIPE_PRICE_BUSINESS", ""),
    "enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE", ""),
}

bearer_scheme = HTTPBearer(auto_error=False)


class AuthenticatedTenant:
    def __init__(self, row):
        self.id: str = row["id"]
        self.name: str = row["name"]
        self.email: str = row["email"]
        self.plan: str = row["plan"]
        self.calls_this_month: int = row["calls_this_month"]
        self.billing_cycle_start: int = row["billing_cycle_start"]


def get_current_tenant(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    request: Request = None,
) -> AuthenticatedTenant:
    """FastAPI dependency — validates Bearer API key and enforces plan limits."""
    api_key = None

    # Accept key from Authorization: Bearer <key> OR X-API-Key header
    if credentials and credentials.credentials:
        api_key = credentials.credentials
    elif request:
        api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Pass as 'Authorization: Bearer at_...' or 'X-API-Key: at_...'")

    row = db.get_tenant_by_key(api_key)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key.")

    tenant = AuthenticatedTenant(row)

    # Reset monthly counter if billing cycle rolled over (30 days)
    now = int(time.time())
    if now - tenant.billing_cycle_start >= 30 * 86400:
        db.reset_billing_cycle(tenant.id)
        tenant.calls_this_month = 0

    # Enforce plan limit
    limit = db.PLAN_LIMITS[tenant.plan]["monthly_calls"]
    if limit != -1 and tenant.calls_this_month >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Monthly call limit ({limit:,}) reached. Upgrade your plan at https://auroratrust.dev/billing"
        )

    # Increment usage
    db.increment_usage(tenant.id)
    return tenant


# ── Stripe Checkout ───────────────────────────────────────────────────────────

def create_checkout_session(tenant_id: str, tenant_email: str, plan: str, success_url: str, cancel_url: str) -> str:
    """Create a Stripe checkout session and return the URL."""
    price_id = STRIPE_PRICES.get(plan)
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan '{plan}'.")

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer_email=tenant_email,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"tenant_id": tenant_id, "plan": plan},
    )
    return session.url


def handle_stripe_webhook(payload: bytes, sig_header: str) -> Dict[str, Any]:
    """Verify and process Stripe webhook events."""
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Stripe webhook secret not configured.")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")

    evt_type = event["type"]
    data = event["data"]["object"]

    if evt_type == "checkout.session.completed":
        tenant_id = data["metadata"].get("tenant_id")
        plan = data["metadata"].get("plan")
        customer_id = data.get("customer")
        sub_id = data.get("subscription")
        if tenant_id and plan:
            db.upgrade_tenant_plan(tenant_id, plan, customer_id, sub_id)

    elif evt_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub_id = data["id"]
        # Downgrade to starter
        with db.get_db() as conn:
            conn.execute(
                "UPDATE tenants SET plan = 'starter' WHERE stripe_sub = ?", (sub_id,)
            )

    return {"received": True, "type": evt_type}
