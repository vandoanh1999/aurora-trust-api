"""
Aurora Trust Compliance API — Database Layer
SQLite-backed, no external DB required. Zero cloud cost.
"""
import sqlite3
import hashlib
import secrets
import time
import json
import os
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

DB_PATH = os.getenv("DATABASE_PATH", "./aurora_trust.db")

PLAN_LIMITS = {
    "starter":    {"price_usd": 99,   "monthly_calls": 10_000,  "label": "Starter"},
    "business":   {"price_usd": 499,  "monthly_calls": 100_000, "label": "Business"},
    "enterprise": {"price_usd": 1999, "monthly_calls": -1,      "label": "Enterprise"},  # -1 = unlimited
}

# ── Connection ────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL,
            email            TEXT UNIQUE NOT NULL,
            api_key          TEXT UNIQUE NOT NULL,
            plan             TEXT NOT NULL DEFAULT 'starter',
            stripe_customer  TEXT,
            stripe_sub       TEXT,
            active           INTEGER NOT NULL DEFAULT 1,
            calls_this_month INTEGER NOT NULL DEFAULT 0,
            billing_cycle_start INTEGER NOT NULL,
            created_at       INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id             TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL REFERENCES tenants(id),
            subject_id     TEXT NOT NULL,
            cred_type      TEXT NOT NULL,
            payload        TEXT NOT NULL,
            signature      TEXT NOT NULL,
            issuer         TEXT NOT NULL DEFAULT 'aurora-trust-api-v1',
            issued_at      INTEGER NOT NULL,
            expires_at     INTEGER,
            revoked        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_cred_subject ON credentials(subject_id);
        CREATE INDEX IF NOT EXISTS idx_cred_tenant  ON credentials(tenant_id);

        CREATE TABLE IF NOT EXISTS audit_events (
            id         TEXT PRIMARY KEY,
            tenant_id  TEXT NOT NULL REFERENCES tenants(id),
            agent_id   TEXT NOT NULL,
            action     TEXT NOT NULL,
            outcome    TEXT NOT NULL DEFAULT 'success',
            metadata   TEXT,
            ip_address TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_audit_agent  ON audit_events(agent_id);
        CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_time   ON audit_events(created_at);

        CREATE TABLE IF NOT EXISTS reputation_scores (
            tenant_id  TEXT NOT NULL REFERENCES tenants(id),
            agent_id   TEXT NOT NULL,
            score      REAL NOT NULL DEFAULT 0.5,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, agent_id),
            FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS mpc_schemes (
            id            TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL REFERENCES tenants(id),
            label         TEXT NOT NULL,
            k             INTEGER NOT NULL,
            n             INTEGER NOT NULL,
            public_key_pem TEXT NOT NULL,
            shares_json   TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)
    print(f"[DB] Initialized: {DB_PATH}")


# ── API Key helpers ───────────────────────────────────────────────────────────

def generate_api_key() -> str:
    raw = secrets.token_hex(32)
    return f"at_{raw}"


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


# ── Tenant CRUD ───────────────────────────────────────────────────────────────

def create_tenant(name: str, email: str, plan: str = "starter") -> Dict[str, Any]:
    import uuid
    tenant_id = str(uuid.uuid4())
    api_key = generate_api_key()
    now = int(time.time())
    with get_db() as db:
        db.execute(
            """INSERT INTO tenants (id, name, email, api_key, plan, billing_cycle_start, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, name, email, api_key, plan, now, now)
        )
    return {"id": tenant_id, "api_key": api_key, "plan": plan}


def get_tenant_by_key(api_key: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM tenants WHERE api_key = ? AND active = 1", (api_key,)
        ).fetchone()


def get_tenant_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute("SELECT * FROM tenants WHERE email = ?", (email,)).fetchone()


def increment_usage(tenant_id: str):
    with get_db() as db:
        db.execute(
            "UPDATE tenants SET calls_this_month = calls_this_month + 1 WHERE id = ?",
            (tenant_id,)
        )


def reset_billing_cycle(tenant_id: str):
    now = int(time.time())
    with get_db() as db:
        db.execute(
            "UPDATE tenants SET calls_this_month = 0, billing_cycle_start = ? WHERE id = ?",
            (now, tenant_id)
        )


def upgrade_tenant_plan(tenant_id: str, plan: str, stripe_customer: str = None, stripe_sub: str = None):
    with get_db() as db:
        db.execute(
            "UPDATE tenants SET plan = ?, stripe_customer = ?, stripe_sub = ? WHERE id = ?",
            (plan, stripe_customer, stripe_sub, tenant_id)
        )


# ── Credential CRUD ───────────────────────────────────────────────────────────

def save_credential(tenant_id: str, subject_id: str, cred_type: str,
                    payload: dict, signature: str, expires_at: int = None) -> str:
    import uuid
    cred_id = str(uuid.uuid4())
    now = int(time.time())
    with get_db() as db:
        db.execute(
            """INSERT INTO credentials
               (id, tenant_id, subject_id, cred_type, payload, signature, issued_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (cred_id, tenant_id, subject_id, cred_type, json.dumps(payload), signature, now, expires_at)
        )
    return cred_id


def get_credential(cred_id: str, tenant_id: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM credentials WHERE id = ? AND tenant_id = ? AND revoked = 0",
            (cred_id, tenant_id)
        ).fetchone()


def list_credentials(tenant_id: str, subject_id: str = None, limit: int = 50) -> List[sqlite3.Row]:
    with get_db() as db:
        if subject_id:
            return db.execute(
                "SELECT * FROM credentials WHERE tenant_id = ? AND subject_id = ? AND revoked = 0 ORDER BY issued_at DESC LIMIT ?",
                (tenant_id, subject_id, limit)
            ).fetchall()
        return db.execute(
            "SELECT * FROM credentials WHERE tenant_id = ? AND revoked = 0 ORDER BY issued_at DESC LIMIT ?",
            (tenant_id, limit)
        ).fetchall()


def revoke_credential(cred_id: str, tenant_id: str) -> bool:
    with get_db() as db:
        cur = db.execute(
            "UPDATE credentials SET revoked = 1 WHERE id = ? AND tenant_id = ?",
            (cred_id, tenant_id)
        )
        return cur.rowcount > 0


# ── Audit CRUD ────────────────────────────────────────────────────────────────

def save_audit_event(tenant_id: str, agent_id: str, action: str,
                     outcome: str = "success", metadata: dict = None,
                     ip_address: str = None) -> str:
    import uuid
    event_id = str(uuid.uuid4())
    now = int(time.time())
    with get_db() as db:
        db.execute(
            """INSERT INTO audit_events
               (id, tenant_id, agent_id, action, outcome, metadata, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, tenant_id, agent_id, action, outcome,
             json.dumps(metadata) if metadata else None, ip_address, now)
        )
    return event_id


def get_audit_trail(tenant_id: str, agent_id: str,
                    from_ts: int = None, to_ts: int = None,
                    limit: int = 100) -> List[sqlite3.Row]:
    with get_db() as db:
        query = "SELECT * FROM audit_events WHERE tenant_id = ? AND agent_id = ?"
        params: list = [tenant_id, agent_id]
        if from_ts:
            query += " AND created_at >= ?"; params.append(from_ts)
        if to_ts:
            query += " AND created_at <= ?"; params.append(to_ts)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return db.execute(query, params).fetchall()


def get_audit_summary(tenant_id: str, agent_id: str) -> Dict[str, Any]:
    with get_db() as db:
        row = db.execute(
            """SELECT COUNT(*) as total,
                      SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) as successes,
                      SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) as failures,
                      MIN(created_at) as first_seen,
                      MAX(created_at) as last_seen
               FROM audit_events
               WHERE tenant_id = ? AND agent_id = ?""",
            (tenant_id, agent_id)
        ).fetchone()
        return dict(row) if row else {}


# ── Reputation CRUD ───────────────────────────────────────────────────────────

EMA_RATE = 0.1

def get_reputation(tenant_id: str, agent_id: str) -> float:
    with get_db() as db:
        row = db.execute(
            "SELECT score FROM reputation_scores WHERE tenant_id = ? AND agent_id = ?",
            (tenant_id, agent_id)
        ).fetchone()
        return float(row["score"]) if row else 0.5


def update_reputation(tenant_id: str, agent_id: str, feedback: float) -> float:
    feedback = max(0.0, min(1.0, feedback))
    old = get_reputation(tenant_id, agent_id)
    new_score = round((1 - EMA_RATE) * old + EMA_RATE * feedback, 6)
    now = int(time.time())
    with get_db() as db:
        db.execute(
            """INSERT INTO reputation_scores (tenant_id, agent_id, score, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(tenant_id, agent_id) DO UPDATE SET score=excluded.score, updated_at=excluded.updated_at""",
            (tenant_id, agent_id, new_score, now)
        )
    return new_score


# ── MPC Scheme CRUD ───────────────────────────────────────────────────────────

def save_mpc_scheme(tenant_id: str, label: str, k: int, n: int,
                    public_key_pem: str, shares: List[str]) -> str:
    import uuid
    scheme_id = str(uuid.uuid4())
    now = int(time.time())
    with get_db() as db:
        db.execute(
            """INSERT INTO mpc_schemes (id, tenant_id, label, k, n, public_key_pem, shares_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scheme_id, tenant_id, label, k, n, public_key_pem, json.dumps(shares), now)
        )
    return scheme_id


def get_mpc_scheme(scheme_id: str, tenant_id: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM mpc_schemes WHERE id = ? AND tenant_id = ?",
            (scheme_id, tenant_id)
        ).fetchone()
