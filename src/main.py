"""
╔══════════════════════════════════════════════════════════════╗
║         AURORA TRUST COMPLIANCE API  v1.0                   ║
║  AI Identity · Verifiable Credentials · Audit Trail · MPC   ║
║  EU AI Act Article 9/13 Compliance Infrastructure           ║
╚══════════════════════════════════════════════════════════════╝
"""
import os
import json
import time
from contextlib import asynccontextmanager
from typing import Optional, List, Any, Dict

from fastapi import FastAPI, Depends, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field, EmailStr

import database as db
from auth import get_current_tenant, AuthenticatedTenant, create_checkout_session, handle_stripe_webhook
from crypto import hmac_sign, hmac_verify, ThresholdScheme, ecc_sign, ecc_verify, generate_node_keypair

VC_SIGNING_KEY = os.getenv("VC_SIGNING_KEY", "aurora-trust-default-key-change-in-prod").encode()
BASE_URL = os.getenv("BASE_URL", "https://auroratrust.dev")

# ── App Lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield

app = FastAPI(
    title="Aurora Trust Compliance API",
    description="AI Identity, Verifiable Credentials, Audit Trail & MPC for EU AI Act compliance.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., description="Business email")
    plan: str = Field("starter", pattern="^(starter|business|enterprise)$")

class IssueCredentialRequest(BaseModel):
    subject_id: str = Field(..., description="Agent ID, model ID, or user DID this credential is about")
    credential_type: str = Field(..., description="e.g. AIModelCompliance, AuditClearance, TierCredential")
    claims: Dict[str, Any] = Field(..., description="Arbitrary claims included in the credential")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)

class VerifyCredentialRequest(BaseModel):
    credential_id: str
    payload: Dict[str, Any]
    signature: str

class AuditLogRequest(BaseModel):
    agent_id: str = Field(..., description="Unique identifier for the AI agent or model")
    action: str = Field(..., description="Action taken, e.g. 'inference', 'data_access', 'decision'")
    outcome: str = Field("success", pattern="^(success|failure|warning)$")
    metadata: Optional[Dict[str, Any]] = None

class ReputationUpdateRequest(BaseModel):
    agent_id: str
    feedback_score: float = Field(..., ge=0.0, le=1.0,
        description="Normalised score: 1.0 = perfect, 0.0 = failed")

class MPCCreateRequest(BaseModel):
    label: str = Field(..., description="Human-readable label for this signing scheme")
    k: int = Field(..., ge=2, le=10, description="Minimum shares required to sign")
    n: int = Field(..., ge=2, le=20, description="Total shares to generate")

class MPCSignRequest(BaseModel):
    scheme_id: str
    shares: List[str] = Field(..., description="At least k shares to reconstruct key and sign")
    message: str = Field(..., description="Message to sign (will be UTF-8 encoded)")

class CheckoutRequest(BaseModel):
    plan: str = Field(..., pattern="^(starter|business|enterprise)$")


# ── Public Endpoints ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Public"])
async def root():
    return HTMLResponse(content=open("/app/landing.html").read() if os.path.exists("/app/landing.html") else "<h1>Aurora Trust API</h1><p>Visit <a href='/docs'>/docs</a></p>")


@app.get("/health", tags=["Public"])
async def health():
    return {"status": "ok", "version": "1.0.0", "timestamp": int(time.time())}


@app.get("/plans", tags=["Public"])
async def list_plans():
    return {
        plan: {
            "price_usd_per_month": info["price_usd"],
            "monthly_api_calls":   info["monthly_calls"] if info["monthly_calls"] != -1 else "unlimited",
            "label": info["label"],
        }
        for plan, info in db.PLAN_LIMITS.items()
    }


@app.post("/register", tags=["Public"], status_code=201)
async def register(req: RegisterRequest):
    """Create a new tenant and receive your API key. **Keep it secret.**"""
    if req.plan not in db.PLAN_LIMITS:
        raise HTTPException(400, "Invalid plan.")
    existing = db.get_tenant_by_email(req.email)
    if existing:
        raise HTTPException(409, "Email already registered.")
    result = db.create_tenant(req.name, req.email, req.plan)
    return {
        "message": "Registration successful. Store your API key — it will not be shown again.",
        "api_key": result["api_key"],
        "tenant_id": result["id"],
        "plan": result["plan"],
        "docs": f"{BASE_URL}/docs",
    }


# ── Stripe Billing ────────────────────────────────────────────────────────────

@app.post("/billing/checkout", tags=["Billing"])
async def billing_checkout(req: CheckoutRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """Create a Stripe checkout session to upgrade plan."""
    if not os.getenv("STRIPE_SECRET_KEY"):
        raise HTTPException(503, "Billing not configured.")
    try:
        url = create_checkout_session(
            tenant_id=tenant.id,
            tenant_email=tenant.email,
            plan=req.plan,
            success_url=f"{BASE_URL}/billing/success",
            cancel_url=f"{BASE_URL}/billing/cancel",
        )
        return {"checkout_url": url}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/billing/webhook", tags=["Billing"], include_in_schema=False)
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Stripe webhook endpoint. Register this URL in your Stripe Dashboard."""
    payload = await request.body()
    result = handle_stripe_webhook(payload, stripe_signature)
    return result


# ── Verifiable Credentials ────────────────────────────────────────────────────

@app.post("/v1/credentials/issue", tags=["Credentials"])
async def issue_credential(req: IssueCredentialRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """
    Issue a signed Verifiable Credential for an AI agent or model.

    The credential payload is signed with HMAC-SHA256. Recipients can verify
    authenticity via `POST /v1/credentials/verify`.
    """
    now = int(time.time())
    expires_at = now + req.expires_in_days * 86400 if req.expires_in_days else None

    payload = {
        "issuer": f"aurora-trust:{tenant.id}",
        "issuanceDate": now,
        "expirationDate": expires_at,
        "type": req.credential_type,
        "credentialSubject": {
            "id": req.subject_id,
            **req.claims,
        },
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = hmac_sign(payload_bytes, VC_SIGNING_KEY)

    cred_id = db.save_credential(
        tenant_id=tenant.id,
        subject_id=req.subject_id,
        cred_type=req.credential_type,
        payload=payload,
        signature=signature,
        expires_at=expires_at,
    )

    return {
        "credential_id": cred_id,
        "credential": payload,
        "proof": {
            "type": "HmacSha256",
            "signature": signature,
            "verificationEndpoint": f"{BASE_URL}/v1/credentials/verify",
        },
    }


@app.post("/v1/credentials/verify", tags=["Credentials"])
async def verify_credential(req: VerifyCredentialRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """Verify the signature on a previously issued credential."""
    payload_bytes = json.dumps(req.payload, sort_keys=True).encode()
    valid = hmac_verify(payload_bytes, VC_SIGNING_KEY, req.signature)

    # Check revocation status
    row = db.get_credential(req.credential_id, tenant.id)
    revoked = row is None  # not found or revoked

    # Check expiry
    exp = req.payload.get("expirationDate")
    expired = (exp is not None and int(time.time()) > exp)

    return {
        "credential_id": req.credential_id,
        "signature_valid": valid,
        "revoked": revoked,
        "expired": expired,
        "valid": valid and not revoked and not expired,
    }


@app.get("/v1/credentials", tags=["Credentials"])
async def list_credentials(
    subject_id: Optional[str] = None,
    limit: int = 50,
    tenant: AuthenticatedTenant = Depends(get_current_tenant),
):
    rows = db.list_credentials(tenant.id, subject_id, limit)
    return [
        {
            "credential_id": r["id"],
            "subject_id": r["subject_id"],
            "type": r["cred_type"],
            "issued_at": r["issued_at"],
            "expires_at": r["expires_at"],
            "payload": json.loads(r["payload"]),
            "signature": r["signature"],
        }
        for r in rows
    ]


@app.delete("/v1/credentials/{credential_id}", tags=["Credentials"])
async def revoke_credential(credential_id: str, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """Revoke a credential — it will fail verification after this call."""
    success = db.revoke_credential(credential_id, tenant.id)
    if not success:
        raise HTTPException(404, "Credential not found.")
    return {"revoked": True, "credential_id": credential_id}


# ── Audit Trail ───────────────────────────────────────────────────────────────

@app.post("/v1/audit/log", tags=["Audit Trail"])
async def log_audit_event(
    req: AuditLogRequest,
    request: Request,
    tenant: AuthenticatedTenant = Depends(get_current_tenant),
):
    """
    Log an AI agent action for compliance audit trail.
    Immutable once written. Required by EU AI Act Article 12 (record-keeping).
    """
    ip = request.client.host if request.client else None
    event_id = db.save_audit_event(
        tenant_id=tenant.id,
        agent_id=req.agent_id,
        action=req.action,
        outcome=req.outcome,
        metadata=req.metadata,
        ip_address=ip,
    )
    return {"event_id": event_id, "logged_at": int(time.time())}


@app.get("/v1/audit/trail/{agent_id}", tags=["Audit Trail"])
async def get_audit_trail(
    agent_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 100,
    tenant: AuthenticatedTenant = Depends(get_current_tenant),
):
    """Retrieve the full audit trail for a specific AI agent."""
    rows = db.get_audit_trail(tenant.id, agent_id, from_ts, to_ts, limit)
    return [
        {
            "event_id": r["id"],
            "agent_id": r["agent_id"],
            "action": r["action"],
            "outcome": r["outcome"],
            "metadata": json.loads(r["metadata"]) if r["metadata"] else None,
            "ip_address": r["ip_address"],
            "timestamp": r["created_at"],
        }
        for r in rows
    ]


@app.get("/v1/audit/summary/{agent_id}", tags=["Audit Trail"])
async def get_audit_summary(
    agent_id: str,
    tenant: AuthenticatedTenant = Depends(get_current_tenant),
):
    """Aggregated compliance summary for an AI agent — suitable for regulatory reports."""
    summary = db.get_audit_summary(tenant.id, agent_id)
    rep = db.get_reputation(tenant.id, agent_id)
    return {
        "agent_id": agent_id,
        "total_events": summary.get("total", 0),
        "successes": summary.get("successes", 0),
        "failures": summary.get("failures", 0),
        "success_rate": round(summary.get("successes", 0) / max(summary.get("total", 1), 1), 4),
        "first_seen": summary.get("first_seen"),
        "last_seen": summary.get("last_seen"),
        "reputation_score": rep,
        "compliance_status": "compliant" if rep >= 0.6 else "review_required",
    }


# ── Reputation Engine ─────────────────────────────────────────────────────────

@app.post("/v1/reputation/update", tags=["Reputation"])
async def update_reputation(req: ReputationUpdateRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """
    Update an AI agent's reputation score using EMA smoothing.
    Score of 1.0 = perfect; 0.0 = consistently failing.
    """
    new_score = db.update_reputation(tenant.id, req.agent_id, req.feedback_score)
    return {
        "agent_id": req.agent_id,
        "new_score": new_score,
        "tier": "trusted" if new_score >= 0.75 else "stable" if new_score >= 0.5 else "probation",
    }


@app.get("/v1/reputation/{agent_id}", tags=["Reputation"])
async def get_reputation(agent_id: str, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    score = db.get_reputation(tenant.id, agent_id)
    return {
        "agent_id": agent_id,
        "score": score,
        "tier": "trusted" if score >= 0.75 else "stable" if score >= 0.5 else "probation",
        "description": {
            "trusted": "Agent consistently performs within compliance bounds.",
            "stable": "Agent performance is acceptable. Monitor closely.",
            "probation": "Agent requires human review before deployment.",
        }.get("trusted" if score >= 0.75 else "stable" if score >= 0.5 else "probation"),
    }


# ── MPC / Threshold Signatures ────────────────────────────────────────────────

@app.post("/v1/mpc/schemes", tags=["MPC Signing"])
async def create_mpc_scheme(req: MPCCreateRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """
    Create a (k, n) threshold signature scheme.
    Returns the public key and n shares. **Distribute shares securely — never store together.**
    This enables multi-party authorisation for high-risk AI actions.
    """
    if req.k > req.n:
        raise HTTPException(400, "k (threshold) cannot exceed n (total shares).")
    scheme = ThresholdScheme(req.k, req.n)
    scheme_id = db.save_mpc_scheme(
        tenant_id=tenant.id,
        label=req.label,
        k=req.k,
        n=req.n,
        public_key_pem=scheme.public_key_pem,
        shares=scheme.shares,
    )
    return {
        "scheme_id": scheme_id,
        "label": req.label,
        "k": req.k,
        "n": req.n,
        "public_key_pem": scheme.public_key_pem,
        "shares": scheme.shares,
        "warning": "Store each share with a different custodian. This is the only time shares are returned.",
    }


@app.post("/v1/mpc/sign", tags=["MPC Signing"])
async def mpc_threshold_sign(req: MPCSignRequest, tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """
    Sign a message using a quorum of k shares.
    Use this to authorize high-risk AI deployments or model updates with multi-party approval.
    """
    row = db.get_mpc_scheme(req.scheme_id, tenant.id)
    if not row:
        raise HTTPException(404, "MPC scheme not found.")

    k = row["k"]
    if len(req.shares) < k:
        raise HTTPException(400, f"Insufficient shares: need {k}, got {len(req.shares)}.")

    try:
        scheme = ThresholdScheme.__new__(ThresholdScheme)
        scheme.k = k
        scheme.n = row["n"]
        from Crypto.PublicKey import ECC
        scheme.public_key = ECC.import_key(row["public_key_pem"])
        scheme.shares = json.loads(row["shares_json"])

        message_bytes = req.message.encode("utf-8")
        signature = scheme.sign_with_quorum(req.shares, message_bytes)

        return {
            "scheme_id": req.scheme_id,
            "message": req.message,
            "signature": signature,
            "public_key_pem": row["public_key_pem"],
            "signed_at": int(time.time()),
        }
    except Exception as e:
        raise HTTPException(400, f"Signing failed: {str(e)}")


@app.post("/v1/mpc/verify", tags=["MPC Signing"])
async def mpc_verify_signature(
    scheme_id: str,
    message: str,
    signature: str,
    tenant: AuthenticatedTenant = Depends(get_current_tenant),
):
    """Verify a threshold signature against the scheme's public key."""
    row = db.get_mpc_scheme(scheme_id, tenant.id)
    if not row:
        raise HTTPException(404, "MPC scheme not found.")

    from Crypto.PublicKey import ECC
    pub = ECC.import_key(row["public_key_pem"])
    valid = ecc_verify(pub, message.encode("utf-8"), signature)
    return {"valid": valid, "scheme_id": scheme_id}


# ── Account ───────────────────────────────────────────────────────────────────

@app.get("/v1/account", tags=["Account"])
async def get_account(tenant: AuthenticatedTenant = Depends(get_current_tenant)):
    """View your current plan, usage, and limits."""
    plan_info = db.PLAN_LIMITS[tenant.plan]
    limit = plan_info["monthly_calls"]
    return {
        "name": tenant.name,
        "email": tenant.email,
        "plan": tenant.plan,
        "plan_label": plan_info["label"],
        "price_usd_per_month": plan_info["price_usd"],
        "calls_this_month": tenant.calls_this_month,
        "monthly_limit": limit if limit != -1 else "unlimited",
        "remaining": max(0, limit - tenant.calls_this_month) if limit != -1 else "unlimited",
    }
