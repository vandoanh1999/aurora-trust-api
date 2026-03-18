# Aurora Trust Compliance API

AI Identity · Verifiable Credentials · Audit Trail · Multi-Party Signing

A production-ready REST API for EU AI Act compliance infrastructure. Designed for fintech, healthcare, and any organisation operating high-risk AI systems under Annex III.

## What It Does

| Endpoint Group | Use Case | EU AI Act Coverage |
|---|---|---|
| `POST /v1/credentials/issue` | Cryptographically sign AI model deployments | Article 13 — Transparency |
| `POST /v1/audit/log` | Immutable log of every AI decision | Article 12 — Record-keeping |
| `GET /v1/audit/summary/:id` | Compliance summary report per agent | Article 9 — Risk management |
| `POST /v1/reputation/update` | Track AI agent performance over time | Article 9 — Monitoring |
| `POST /v1/mpc/schemes` | Multi-party authorization for model changes | Article 9 — Human oversight |

## Quick Start

Register for an API key:

```bash
curl -X POST https://auroratrust.dev/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","email":"cto@acme.com","plan":"starter"}'
```

Issue a Verifiable Credential for an AI model:

```bash
curl -X POST https://auroratrust.dev/v1/credentials/issue \
  -H "Authorization: Bearer at_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "fraud-model-v2",
    "credential_type": "AIModelCompliance",
    "claims": {"risk_level":"high","validated_by":"compliance-team"},
    "expires_in_days": 365
  }'
```

Log an AI decision:

```bash
curl -X POST https://auroratrust.dev/v1/audit/log \
  -H "Authorization: Bearer at_your_key" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"fraud-model-v2","action":"transaction_scored","outcome":"success"}'
```

## Pricing

| Plan | Price | API Calls/Month |
|---|---|---|
| Starter | $99/month | 10,000 |
| Business | $499/month | 100,000 |
| Enterprise | $1,999/month | Unlimited |

## Self-Hosting

```bash
git clone https://github.com/YOUR_USERNAME/aurora-trust-api
cd aurora-trust-api
cp .env.example .env
# Edit .env with your signing key
docker build -t aurora-trust .
docker run -p 8000:8000 --env-file .env aurora-trust
```

Full API documentation: https://auroratrust.dev/docs

## Architecture

Built on FastAPI + SQLite (zero-dependency persistence). Cryptographic layer uses ECC P-256 for signatures and Shamir's Secret Sharing over GF(p-256) for multi-party key management. No external cloud services required.

## License

Dual license: Source-available for self-hosted use. SaaS deployment requires a commercial license. Contact hello@auroratrust.dev.
