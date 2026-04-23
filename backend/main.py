import os, json, hashlib, secrets, time, logging

# Vaultak security modules
try:
    from vaultak_pii import PIIMasker, PIIType
    HAS_PII = True
except ImportError:
    HAS_PII = False

try:
    from vaultak_siem import SIEMRouter, normalize_event
    _siem_router = SIEMRouter.from_env()
    HAS_SIEM = True
except ImportError:
    HAS_SIEM = False
    _siem_router = None

try:
    from vaultak_redteam import RedTeamEngine
    HAS_REDTEAM = True
except ImportError:
    HAS_REDTEAM = False

try:
    from vaultak_shadow_ai import ShadowAIDetector
    HAS_SHADOW_AI = True
except ImportError:
    HAS_SHADOW_AI = False
from typing import Any, Dict, Optional, List
import stripe

def send_welcome_email(email, key, name):
    pass  # TODO: implement welcome email
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICES = {
    "pro":        os.environ.get("STRIPE_PRICE_PRO", ""),
    "team":       os.environ.get("STRIPE_PRICE_TEAM", ""),
    "business":   os.environ.get("STRIPE_PRICE_BUSINESS", ""),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE", ""),
}

# Plan limits
PLAN_LIMITS = {
    "starter":    {"max_agents": 1,         "max_actions_per_month": 10_000},
    "pro":        {"max_agents": 5,         "max_actions_per_month": 100_000},
    "team":       {"max_agents": 15,        "max_actions_per_month": 500_000},
    "business":   {"max_agents": 50,        "max_actions_per_month": 2_000_000},
    "enterprise": {"max_agents": 999999,    "max_actions_per_month": 999999999},
}

def get_plan_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["starter"])
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Body, Request, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vaultak")

APP_VERSION = "0.5.1"

app = FastAPI(title="Vaultak API", version=APP_VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-change-me")

# ─── Database ─────────────────────────────────────────────────────────────────

def get_db():
    retries = 3
    conn = None
    for attempt in range(retries):
        try:
            conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
            break
        except Exception as e:
            if attempt == retries - 1:
                logger.error(f"Database connection failed after {retries} attempts: {e}")
                raise HTTPException(status_code=503, detail="Database unavailable")
            time.sleep(1)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS organizations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL DEFAULT 'starter',
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""")
            # Migrate existing orgs — add plan columns if missing
            cur.execute("""
                ALTER TABLE organizations
                ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'starter',
                ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
                ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT
            """)
            cur.execute("""CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_used TIMESTAMPTZ
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS agents (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                agent_id TEXT NOT NULL,
                name TEXT,
                kill_switch_mode TEXT DEFAULT 'alert',
                paused BOOLEAN DEFAULT FALSE,
                terminated BOOLEAN DEFAULT FALSE,
                baseline_actions INTEGER DEFAULT 0,
                avg_risk_score REAL DEFAULT 0.0,
                allowed_action_types JSONB DEFAULT NULL,
                allowed_resources JSONB DEFAULT NULL,
                blocked_resources JSONB DEFAULT '[]',
                max_actions_per_minute INTEGER DEFAULT 60,
                max_risk_score REAL DEFAULT 1.0,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(org_id, agent_id)
            )""")
            # Add permission profile columns to existing tables if missing
            for col, definition in [
                ("allowed_action_types", "JSONB DEFAULT NULL"),
                ("allowed_resources", "JSONB DEFAULT NULL"),
                ("blocked_resources", "JSONB DEFAULT '[]'"),
                ("max_actions_per_minute", "INTEGER DEFAULT 60"),
                ("max_risk_score", "REAL DEFAULT 1.0"),
            ]:
                cur.execute(f"""
                    ALTER TABLE agents ADD COLUMN IF NOT EXISTS {col} {definition}
                """)
            cur.execute("""CREATE TABLE IF NOT EXISTS actions (
                id BIGSERIAL PRIMARY KEY,
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                agent_id TEXT NOT NULL,
                session_id TEXT,
                action_type TEXT,
                resource TEXT,
                payload JSONB,
                snapshot JSONB,
                risk_score REAL,
                risk_breakdown JSONB,
                flagged BOOLEAN DEFAULT FALSE,
                flag_reason TEXT,
                kill_switch_mode TEXT,
                rolled_back BOOLEAN DEFAULT FALSE,
                rollback_at TIMESTAMPTZ,
                rollback_reason TEXT,
                timestamp TIMESTAMPTZ DEFAULT NOW()
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id BIGSERIAL PRIMARY KEY,
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                agent_id TEXT,
                action_id BIGINT,
                level TEXT,
                message TEXT,
                acknowledged BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS rollback_log (
                id BIGSERIAL PRIMARY KEY,
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                agent_id TEXT NOT NULL,
                action_ids BIGINT[],
                reason TEXT,
                initiated_by TEXT DEFAULT 'system',
                status TEXT DEFAULT 'completed',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""")
            conn.commit()
            cur.execute("""CREATE TABLE IF NOT EXISTS policies (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                action_type TEXT,
                resource_pattern TEXT,
                effect TEXT NOT NULL DEFAULT 'block',
                max_risk_score REAL,
                time_start INTEGER,
                time_end INTEGER,
                days_allowed TEXT[],
                priority INTEGER DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""")
            conn.commit()
    logger.info("Database initialized successfully")

@app.on_event("startup")
def startup():
    init_db()

# ─── Risk Scoring Engine ───────────────────────────────────────────────────────

# Dimension 1: Action type risk weights
ACTION_TYPE_RISK = {
    "file_delete": 0.95,
    "database_drop": 0.95,
    "system_command": 0.90,
    "permission_change": 0.85,
    "database_write": 0.80,
    "file_write": 0.75,
    "api_call_external": 0.70,
    "database_read": 0.30,
    "file_read": 0.20,
    "api_call_internal": 0.25,
    "log": 0.05,
}

# Dimension 2: Resource sensitivity
SENSITIVE_RESOURCE_PATTERNS = [
    ("prod", 0.90), ("production", 0.90), ("/etc/", 0.90), ("/root/", 0.85),
    ("password", 0.85), ("secret", 0.85), ("credential", 0.85), ("token", 0.80),
    ("admin", 0.80), ("users", 0.75), ("payment", 0.85), ("billing", 0.80),
    ("config", 0.65), ("database", 0.70), ("db", 0.65), ("backup", 0.70),
    ("staging", 0.40), ("test", 0.20), ("dev", 0.20), ("log", 0.15),
]

def score_action_type(action_type: str) -> float:
    if not action_type:
        return 0.5
    return ACTION_TYPE_RISK.get(action_type.lower(), 0.5)

def score_resource_sensitivity(resource: str) -> float:
    if not resource:
        return 0.3
    resource_lower = resource.lower()
    for pattern, score in SENSITIVE_RESOURCE_PATTERNS:
        if pattern in resource_lower:
            return score
    return 0.3

def score_blast_radius(payload: dict) -> float:
    if not payload:
        return 0.2
    score = 0.2
    payload_str = json.dumps(payload).lower()
    # Large data operations
    if any(k in payload_str for k in ["*", "all", "bulk", "batch", "truncate", "drop"]):
        score += 0.4
    if any(k in payload_str for k in ["where", "filter", "limit"]):
        score -= 0.1
    # Payload size as proxy for blast radius
    payload_size = len(payload_str)
    if payload_size > 10000:
        score += 0.3
    elif payload_size > 1000:
        score += 0.15
    return min(max(score, 0.0), 1.0)

def score_behavioral_deviation(agent_id: str, action_type: str, org_id: str, db) -> float:
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT action_type, COUNT(*) as freq
                FROM actions
                WHERE org_id = %s AND agent_id = %s
                AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY action_type
            """, (org_id, agent_id))
            history = {r["action_type"]: r["freq"] for r in cur.fetchall()}
        if not history:
            return 0.3  # New agent, moderate baseline
        total = sum(history.values())
        action_freq = history.get(action_type, 0)
        if action_freq == 0:
            return 0.7  # Never done this before — suspicious
        ratio = action_freq / total
        if ratio < 0.05:
            return 0.6  # Rare action
        elif ratio < 0.20:
            return 0.4
        else:
            return 0.2  # Common action for this agent
    except Exception:
        return 0.3

def score_time_pattern(timestamp: Optional[datetime] = None) -> float:
    now = timestamp or datetime.now(timezone.utc)
    hour = now.hour
    weekday = now.weekday()  # 0=Monday, 6=Sunday
    # Weekend activity
    if weekday >= 5:
        return 0.65
    # Off-hours (before 7am or after 10pm UTC)
    if hour < 7 or hour > 22:
        return 0.60
    # Business hours
    if 9 <= hour <= 17:
        return 0.15
    return 0.30

def compute_risk_score(
    action_type: str,
    resource: str,
    payload: dict,
    agent_id: str,
    org_id: str,
    db,
    provided_score: Optional[float] = None
) -> tuple[float, dict]:
    """Compute weighted 5-dimension risk score."""
    # If SDK provides a score, blend it with our engine (60% ours, 40% SDK)
    d1 = score_action_type(action_type)
    d2 = score_resource_sensitivity(resource)
    d3 = score_blast_radius(payload)
    d4 = score_behavioral_deviation(agent_id, action_type, org_id, db)
    d5 = score_time_pattern()

    # Weighted combination
    weights = {"action_type": 0.30, "resource_sensitivity": 0.25,
               "blast_radius": 0.20, "behavioral_deviation": 0.15, "time_pattern": 0.10}

    engine_score = (
        d1 * weights["action_type"] +
        d2 * weights["resource_sensitivity"] +
        d3 * weights["blast_radius"] +
        d4 * weights["behavioral_deviation"] +
        d5 * weights["time_pattern"]
    )

    final_score = engine_score
    if provided_score is not None:
        final_score = (engine_score * 0.6) + (provided_score * 0.4)

    breakdown = {
        "action_type": round(d1, 3),
        "resource_sensitivity": round(d2, 3),
        "blast_radius": round(d3, 3),
        "behavioral_deviation": round(d4, 3),
        "time_pattern": round(d5, 3),
        "engine_score": round(engine_score, 3),
        "final_score": round(final_score, 3),
        "weights": weights
    }

    return round(final_score, 4), breakdown

# ─── Auth ─────────────────────────────────────────────────────────────────────

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def get_org(x_api_key: Optional[str] = Header(None), db=Depends(get_db)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE api_keys SET last_used = NOW() WHERE key_hash = %s RETURNING org_id", (hash_key(x_api_key),))
            row = cur.fetchone()
            db.commit()
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return str(row["org_id"])

def require_admin(x_admin_key: Optional[str] = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required")

# ─── Models ───────────────────────────────────────────────────────────────────

class OrgCreate(BaseModel):
    name: str
    slug: str

class ActionLog(BaseModel):
    agent_id: str
    agent_name: Optional[str] = None
    session_id: Optional[str] = None
    allowed_action_types: Optional[list] = None
    allowed_resources: Optional[list] = None
    blocked_resources: Optional[list] = None
    max_actions_per_minute: Optional[int] = None
    max_risk_score: Optional[float] = None
    action_type: Optional[str] = None
    resource: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    snapshot: Optional[Dict[str, Any]] = None  # State snapshot BEFORE action (for rollback)
    risk_score: Optional[float] = None
    flagged: Optional[bool] = False
    flag_reason: Optional[str] = None
    kill_switch_mode: Optional[str] = "alert"

class AgentUpdate(BaseModel):
    paused: Optional[bool] = None
    kill_switch_mode: Optional[str] = None

class RollbackRequest(BaseModel):
    agent_id: str
    n_actions: Optional[int] = 1
    reason: Optional[str] = "manual"
    initiated_by: Optional[str] = "user"

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        db_status = "ok"
    except Exception:
        db_status = "error"
    return {"status": "ok", "version": "0.3.0", "database": db_status}

@app.post("/admin/orgs")
def create_org(body: OrgCreate, db=Depends(get_db), _=Depends(require_admin)):
    with db.cursor() as cur:
        cur.execute("INSERT INTO organizations (name, slug) VALUES (%s, %s) RETURNING id, name, slug, created_at", (body.name, body.slug))
        org = dict(cur.fetchone())
        db.commit()
    return org

@app.get("/admin/orgs")
def list_orgs(db=Depends(get_db), _=Depends(require_admin)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM organizations ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

@app.post("/admin/orgs/{org_id}/keys")
def create_api_key(org_id: str, name: str = "default", db=Depends(get_db), _=Depends(require_admin)):
    raw_key = f"vtk_{secrets.token_urlsafe(32)}"
    with db.cursor() as cur:
        cur.execute("INSERT INTO api_keys (org_id, key_hash, key_prefix, name) VALUES (%s, %s, %s, %s)", (org_id, hash_key(raw_key), raw_key[:12], name))
        db.commit()
    return {"api_key": raw_key, "prefix": raw_key[:12], "warning": "Save this key - it won't be shown again"}

@app.post("/api/actions")
def log_action(body: ActionLog, org_id: str = Depends(get_org), db=Depends(get_db)):
    # Check plan limits
    with db.cursor() as cur:
        cur.execute("SELECT plan FROM organizations WHERE id = %s", (org_id,))
        row = cur.fetchone()
        plan = row["plan"] if row else "starter"
        limits = get_plan_limits(plan)

        # Check monthly action limit
        cur.execute("""
            SELECT COUNT(*) as action_count FROM actions
            WHERE org_id = %s AND timestamp >= date_trunc('month', NOW())
        """, (org_id,))
        action_count = cur.fetchone()["action_count"] or 0
        if action_count >= limits["max_actions_per_month"]:
            return {"error": "monthly_action_limit_reached", "plan": plan,
                    "limit": limits["max_actions_per_month"],
                    "message": f"Monthly action limit reached for {plan} plan. Please upgrade."}

        # Check agent limit
        cur.execute("SELECT COUNT(DISTINCT agent_id) as agent_count FROM agents WHERE org_id = %s", (org_id,))
        agent_count = cur.fetchone()["agent_count"] or 0
        cur.execute("SELECT id FROM agents WHERE org_id = %s AND agent_id = %s", (org_id, body.agent_id))
        existing = cur.fetchone()
        if not existing and agent_count >= limits["max_agents"]:
            return {"error": "agent_limit_reached", "plan": plan,
                    "limit": limits["max_agents"],
                    "message": f"Agent limit reached for {plan} plan ({limits['max_agents']} agents). Please upgrade."}
    try:
        # ── Auto PII masking ──────────────────────────────────────────────
        if HAS_PII:
            try:
                masker = PIIMasker()
                if body.resource:
                    result = masker.mask(body.resource)
                    if result.pii_found:
                        body.resource = result.masked_text
                if body.payload:
                    for k, v in body.payload.items():
                        if isinstance(v, str):
                            r = masker.mask(v)
                            if r.pii_found:
                                body.payload[k] = r.masked_text
            except Exception:
                pass

        # ── Auto Shadow AI detection ──────────────────────────────────────
        if HAS_SHADOW_AI and body.resource:
            try:
                detector = ShadowAIDetector()
                shadow_result = detector.scan_text(body.resource)
                if getattr(shadow_result, "detected", False):
                    body.flag_reason = (body.flag_reason or "") + " [Shadow AI detected]"
                    body.flagged = True
            except Exception:
                pass

        # ── Compute risk score using 5-dimension engine ───────────────────
        final_score, breakdown = compute_risk_score(
            action_type=body.action_type or "",
            resource=body.resource or "",
            payload=body.payload or {},
            agent_id=body.agent_id,
            org_id=org_id,
            db=db,
            provided_score=body.risk_score
        )

        # Auto-flag based on engine score
        auto_flagged = final_score >= 0.30
        flagged = body.flagged or auto_flagged
        flag_reason = body.flag_reason
        if auto_flagged and not flag_reason:
            flag_reason = f"Risk score {final_score:.2f} exceeds threshold (top dimension: {max(breakdown, key=lambda k: breakdown[k] if isinstance(breakdown[k], float) else 0)})"

        with db.cursor() as cur:
            # Upsert agent
            cur.execute("""
                INSERT INTO agents (org_id, agent_id, name, kill_switch_mode)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (org_id, agent_id) DO UPDATE
                SET name = EXCLUDED.name, updated_at = NOW()
            """, (org_id, body.agent_id, body.agent_name or body.agent_id, body.kill_switch_mode))

            # Log action with snapshot for rollback
            cur.execute("""
                INSERT INTO actions (org_id, agent_id, session_id, action_type, resource,
                    payload, snapshot, risk_score, risk_breakdown, flagged, flag_reason,
                    kill_switch_mode, rolled_back)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE)
                RETURNING id
            """, (
                org_id, body.agent_id, body.session_id, body.action_type, body.resource,
                json.dumps(body.payload or {}),
                json.dumps(body.snapshot or {}),
                final_score,
                json.dumps(breakdown),
                flagged, flag_reason,
                body.kill_switch_mode
            ))
            action_id = cur.fetchone()["id"]

            # Create alert if flagged
            if flagged:
                level = "critical" if final_score >= 0.85 else "high" if final_score >= 0.60 else "medium"
                cur.execute("""
                    INSERT INTO alerts (org_id, agent_id, action_id, level, message)
                    VALUES (%s, %s, %s, %s, %s)
                """, (org_id, body.agent_id, action_id, level,
                      f"{body.action_type or 'Action'} on {body.resource or 'unknown'} — risk {final_score:.2f}"))

            # Auto-pause agent if in PAUSE mode and high risk
            if body.kill_switch_mode == "PAUSE" and final_score >= 0.60:
                cur.execute("""
                    UPDATE agents SET paused = TRUE, updated_at = NOW()
                    WHERE org_id = %s AND agent_id = %s
                """, (org_id, body.agent_id))

            # Auto-rollback if in ROLLBACK mode and critical risk
            if body.kill_switch_mode == "ROLLBACK" and final_score >= 0.85:
                cur.execute("""
                    UPDATE actions SET rolled_back = TRUE, rollback_at = NOW(),
                    rollback_reason = 'auto-rollback: critical risk score'
                    WHERE id = %s
                """, (action_id,))
                cur.execute("""
                    INSERT INTO rollback_log (org_id, agent_id, action_ids, reason, initiated_by)
                    VALUES (%s, %s, %s, %s, %s)
                """, (org_id, body.agent_id, [action_id], "auto-rollback: critical risk score", "system"))

            db.commit()

        # Emit to SIEM if configured
        if HAS_SIEM and _siem_router:
            try:
                _siem_router.route({
                    "agent_id":    body.agent_id,
                    "action_type": body.action_type,
                    "resource":    body.resource,
                    "risk_score":  final_score,
                    "decision":    "flag" if flagged else "allow",
                    "reason":      flag_reason or "",
                    "mode":        body.kill_switch_mode,
                    "session_id":  body.session_id,
                    "org_id":      org_id,
                })
            except Exception:
                pass

        # Determine decision for SDK response
        score_100 = int(final_score * 100)
        if score_100 >= 85:
            decision = "ROLLBACK"
        elif score_100 >= 60:
            decision = "PAUSE"
        elif score_100 >= 30:
            decision = "ALERT"
        else:
            decision = "ALLOW"

        return {
            "logged": True,
            "action_id": action_id,
            "risk_score": final_score,
            "risk_breakdown": breakdown,
            "flagged": flagged,
            "flag_reason": flag_reason,
            "decision": decision,
        }
    except HTTPException:
        raise

class AgentProfile(BaseModel):
    allowed_action_types: Optional[list] = None
    allowed_resources: Optional[list] = None
    blocked_resources: Optional[list] = None
    max_actions_per_minute: Optional[int] = None
    max_risk_score: Optional[float] = None

@app.patch("/api/agents/{agent_id}/profile")
def update_agent_profile(agent_id: str, profile: AgentProfile, org_id: str = Depends(get_org), db=Depends(get_db)):
    """Update an agent permission profile — define what the agent is allowed to do."""
    import json as _json
    with db.cursor() as cur:
        cur.execute("""
            UPDATE agents SET
                allowed_action_types = COALESCE(%s::jsonb, allowed_action_types),
                allowed_resources = COALESCE(%s::jsonb, allowed_resources),
                blocked_resources = COALESCE(%s::jsonb, blocked_resources),
                max_actions_per_minute = COALESCE(%s, max_actions_per_minute),
                max_risk_score = COALESCE(%s, max_risk_score),
                updated_at = NOW()
            WHERE org_id = %s AND agent_id = %s
            RETURNING *
        """, (
            _json.dumps(profile.allowed_action_types) if profile.allowed_action_types is not None else None,
            _json.dumps(profile.allowed_resources) if profile.allowed_resources is not None else None,
            _json.dumps(profile.blocked_resources) if profile.blocked_resources is not None else None,
            profile.max_actions_per_minute,
            profile.max_risk_score,
            org_id, agent_id
        ))
        agent = cur.fetchone()
        db.commit()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return dict(agent)

@app.post("/api/rollback")
def rollback_actions(body: RollbackRequest, org_id: str = Depends(get_org), db=Depends(get_db)):
    """Roll back the last N actions for an agent."""
    try:
        with db.cursor() as cur:
            # Get last N non-rolled-back actions with their snapshots
            cur.execute("""
                SELECT id, action_type, resource, payload, snapshot, timestamp
                FROM actions
                WHERE org_id = %s AND agent_id = %s AND rolled_back = FALSE
                ORDER BY timestamp DESC
                LIMIT %s
            """, (org_id, body.agent_id, body.n_actions))
            actions = [dict(r) for r in cur.fetchall()]

            if not actions:
                return {"rolled_back": 0, "message": "No actions to roll back"}

            action_ids = [a["id"] for a in actions]

            # Mark actions as rolled back
            cur.execute("""
                UPDATE actions
                SET rolled_back = TRUE, rollback_at = NOW(), rollback_reason = %s
                WHERE id = ANY(%s)
            """, (body.reason, action_ids))

            # Log rollback event
            cur.execute("""
                INSERT INTO rollback_log (org_id, agent_id, action_ids, reason, initiated_by)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (org_id, body.agent_id, action_ids, body.reason, body.initiated_by))
            rollback_id = cur.fetchone()["id"]

            # Create alert for rollback
            cur.execute("""
                INSERT INTO alerts (org_id, agent_id, level, message)
                VALUES (%s, %s, 'high', %s)
            """, (org_id, body.agent_id,
                  f"Rollback executed: {len(action_ids)} action(s) reversed. Reason: {body.reason}"))

            # Pause the agent after rollback
            cur.execute("""
                UPDATE agents SET paused = TRUE, updated_at = NOW()
                WHERE org_id = %s AND agent_id = %s
            """, (org_id, body.agent_id))

            db.commit()

        return {
            "rolled_back": len(action_ids),
            "rollback_id": rollback_id,
            "action_ids": action_ids,
            "snapshots_available": [a for a in actions if a.get("snapshot") and a["snapshot"] != "{}"],
            "message": f"Successfully rolled back {len(action_ids)} action(s). Agent paused."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        raise HTTPException(status_code=500, detail="Rollback failed")

@app.get("/api/rollback/history")
def get_rollback_history(agent_id: Optional[str] = None, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        if agent_id:
            cur.execute("SELECT * FROM rollback_log WHERE org_id = %s AND agent_id = %s ORDER BY created_at DESC LIMIT 50", (org_id, agent_id))
        else:
            cur.execute("SELECT * FROM rollback_log WHERE org_id = %s ORDER BY created_at DESC LIMIT 50", (org_id,))
        return [dict(r) for r in cur.fetchall()]

@app.get("/api/actions")
def get_actions(limit: int = 50, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM actions WHERE org_id = %s ORDER BY timestamp DESC LIMIT %s", (org_id, limit))
        return [dict(r) for r in cur.fetchall()]


@app.post("/api/agents")
def create_agent(body: dict, org_id: str = Depends(get_org), db=Depends(get_db)):
    """Manually register an agent — for SDK users who manage agents via dashboard."""
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name is required")
    with db.cursor() as cur:
        # Check plan limit
        cur.execute("SELECT plan FROM organizations WHERE id = %s", (org_id,))
        row = cur.fetchone()
        plan = row["plan"] if row else "starter"
        limits = get_plan_limits(plan)
        cur.execute("SELECT COUNT(DISTINCT agent_id) as cnt FROM agents WHERE org_id = %s", (org_id,))
        count = cur.fetchone()["cnt"] or 0
        if count >= limits["max_agents"]:
            raise HTTPException(
                status_code=403,
                detail=f"Agent limit reached for {plan} plan ({limits['max_agents']} agent{'s' if limits['max_agents'] != 1 else ''}). Please upgrade."
            )
        # Check duplicate
        agent_id = body.get("agent_id") or name.lower().replace(" ", "-")
        cur.execute("SELECT id FROM agents WHERE org_id = %s AND agent_id = %s", (org_id, agent_id))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="An agent with this ID already exists")
        cur.execute("""
            INSERT INTO agents (org_id, agent_id, name, kill_switch_mode)
            VALUES (%s, %s, %s, 'alert')
            RETURNING id, agent_id, name, kill_switch_mode, paused, created_at
        """, (org_id, agent_id, name))
        agent = dict(cur.fetchone())
        db.commit()
    return agent

@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: str, org_id: str = Depends(get_org), db=Depends(get_db)):
    """Delete a registered agent."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM agents WHERE agent_id = %s AND org_id = %s RETURNING id", (agent_id, org_id))
        deleted = cur.fetchone()
        db.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"deleted": True}

@app.get("/api/agents")
def get_agents(org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT a.*,
                COUNT(ac.id) as total_actions,
                COUNT(ac.id) FILTER (WHERE ac.flagged) as flagged_actions,
                COUNT(ac.id) FILTER (WHERE ac.rolled_back) as rolled_back_actions,
                MAX(ac.timestamp) as last_seen,
                AVG(ac.risk_score) as avg_risk_score
            FROM agents a
            LEFT JOIN actions ac ON ac.agent_id = a.agent_id AND ac.org_id = a.org_id
            WHERE a.org_id = %s
            GROUP BY a.id
            ORDER BY a.created_at DESC
        """, (org_id,))
        return [dict(r) for r in cur.fetchall()]

@app.patch("/api/agents/{agent_id}")
def update_agent(agent_id: str, body: AgentUpdate, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        if body.paused is not None:
            cur.execute("UPDATE agents SET paused = %s, updated_at = NOW() WHERE org_id = %s AND agent_id = %s", (body.paused, org_id, agent_id))
        if body.kill_switch_mode is not None:
            cur.execute("UPDATE agents SET kill_switch_mode = %s, updated_at = NOW() WHERE org_id = %s AND agent_id = %s", (body.kill_switch_mode, org_id, agent_id))
        db.commit()
    return {"updated": True}

@app.get("/api/risk/score")
def score_action(action_type: str, resource: str = "", org_id: str = Depends(get_org), db=Depends(get_db)):
    """Preview risk score for an action before executing it."""
    score, breakdown = compute_risk_score(action_type, resource, {}, "preview", org_id, db)
    return {"risk_score": score, "breakdown": breakdown, "would_flag": score >= 0.65}

@app.get("/api/alerts")
def get_alerts(acknowledged: Optional[bool] = None, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        query = "SELECT * FROM alerts WHERE org_id = %s"
        params = [org_id]
        if acknowledged is not None:
            query += " AND acknowledged = %s"
            params.append(acknowledged)
        query += " ORDER BY created_at DESC LIMIT 100"
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]

@app.patch("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("UPDATE alerts SET acknowledged = TRUE WHERE id = %s AND org_id = %s", (alert_id, org_id))
        db.commit()
    return {"acknowledged": True}

@app.post("/api/keys/regenerate")
def regenerate_api_key(org_id: str = Depends(get_org), db=Depends(get_db)):
    """Regenerate the org's API key — invalidates the old one immediately."""
    import secrets, hashlib
    new_key = "vtk_" + secrets.token_urlsafe(32)
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    with db.cursor() as cur:
        cur.execute(
            "UPDATE api_keys SET key_hash = %s, key_prefix = %s WHERE org_id = %s",
            (new_hash, new_key[:12], org_id)
        )
    db.commit()
    return {"api_key": new_key, "prefix": new_key[:12]}

@app.get("/api/org/plan")
def get_org_plan(org_id: str = Depends(get_org), db=Depends(get_db)):
    """Return the org's current plan and usage stats."""
    with db.cursor() as cur:
        cur.execute("SELECT plan FROM organizations WHERE id = %s", (org_id,))
        row = cur.fetchone()
        plan = row["plan"] if row else "starter"

        # Count active agents this month
        cur.execute("""
            SELECT COUNT(DISTINCT agent_id) as agent_count
            FROM agents WHERE org_id = %s
        """, (org_id,))
        agent_count = cur.fetchone()["agent_count"] or 0

        # Count actions this month
        cur.execute("""
            SELECT COUNT(*) as action_count
            FROM actions
            WHERE org_id = %s
            AND timestamp >= date_trunc('month', NOW())
        """, (org_id,))
        action_count = cur.fetchone()["action_count"] or 0

    limits = get_plan_limits(plan)
    return {
        "plan": plan,
        "agent_count": agent_count,
        "action_count": action_count,
        "max_agents": limits["max_agents"],
        "max_actions_per_month": limits["max_actions_per_month"],
        "agents_remaining": max(0, limits["max_agents"] - agent_count),
        "can_add_agent": agent_count < limits["max_agents"],
    }

@app.get("/api/stats")
def get_stats(org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as c FROM agents WHERE org_id = %s", (org_id,))
        total_agents = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM agents WHERE org_id = %s AND paused = TRUE", (org_id,))
        paused_agents = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM actions WHERE org_id = %s", (org_id,))
        total_actions = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM actions WHERE org_id = %s AND flagged = TRUE", (org_id,))
        flagged_actions = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM actions WHERE org_id = %s AND rolled_back = TRUE", (org_id,))
        rolled_back_actions = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM alerts WHERE org_id = %s AND acknowledged = FALSE", (org_id,))
        active_alerts = cur.fetchone()["c"]
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE risk_score >= 0.80) as critical,
                COUNT(*) FILTER (WHERE risk_score >= 0.65 AND risk_score < 0.80) as high,
                COUNT(*) FILTER (WHERE risk_score >= 0.40 AND risk_score < 0.65) as medium,
                COUNT(*) FILTER (WHERE risk_score < 0.40) as low
            FROM actions WHERE org_id = %s
        """, (org_id,))
        dist = dict(cur.fetchone())
    return {
        "total_agents": total_agents,
        "paused_agents": paused_agents,
        "total_actions": total_actions,
        "flagged_actions": flagged_actions,
        "rolled_back_actions": rolled_back_actions,
        "active_alerts": active_alerts,
        "risk_distribution": {k: (v or 0) for k, v in dist.items()}
    }

@app.get("/")
def serve_landing():
    version = APP_VERSION
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            html = f.read()
        html = html.replace("Vaultak · v0.5.1", f"Vaultak · v{version}")
        return HTMLResponse(content=html)

@app.get("/scan", response_class=HTMLResponse)
def serve_scan():
    scan_path = os.path.join(os.path.dirname(__file__), "scan.html")
    if os.path.exists(scan_path):
        with open(scan_path, "r") as f:
            html = f.read()
        return HTMLResponse(content=html)
    return HTMLResponse(content="Not found", status_code=404)
    return {"status": "ok", "service": "Vaultak API", "version": version}

@app.post("/api/onboard")
def onboard_user(
    x_clerk_user_id: Optional[str] = Header(None),
    x_user_email: Optional[str] = Header(None),
    db=Depends(get_db)
):
    if not x_clerk_user_id:
        raise HTTPException(status_code=401, detail="Missing user ID")
    slug = x_clerk_user_id.replace("user_", "")[:20]
    name = x_user_email.split("@")[0] if x_user_email else slug
    with db.cursor() as cur:
        cur.execute("SELECT id FROM organizations WHERE slug = %s", (slug,))
        existing = cur.fetchone()
        if existing:
            cur.execute("SELECT key_value FROM api_keys WHERE org_id = %s", (str(existing["id"]),))
            key = cur.fetchone()
            if key and key.get("key_value"):
                return {"org_id": str(existing["id"]), "already_exists": False, "api_key": key["key_value"]}
            raw_key = f"vtk_{secrets.token_urlsafe(32)}"
            cur.execute("UPDATE api_keys SET key_hash = %s, key_prefix = %s, key_value = %s WHERE org_id = %s", (hash_key(raw_key), raw_key[:12], raw_key, str(existing["id"])))
            db.commit()
            return {"org_id": str(existing["id"]), "already_exists": False, "api_key": raw_key}
        cur.execute("INSERT INTO organizations (name, slug) VALUES (%s, %s) RETURNING id", (name, slug))
        org_id = str(cur.fetchone()["id"])
        raw_key = f"vtk_{secrets.token_urlsafe(32)}"
        cur.execute("INSERT INTO api_keys (org_id, key_hash, key_prefix, name) VALUES (%s, %s, %s, %s)", (org_id, hash_key(raw_key), raw_key[:12], "default"))
        db.commit()
    if x_user_email:
        import threading
        threading.Thread(target=send_welcome_email, args=(x_user_email, raw_key, name), daemon=True).start()
    return {"org_id": org_id, "api_key": raw_key, "already_exists": False}

@app.get("/api/usage")
def get_usage(org_id: str = Depends(get_org), db=Depends(get_db)):
    """Get usage metrics for the current organization."""
    with db.cursor() as cur:
        # Total actions
        cur.execute("SELECT COUNT(*) as total FROM actions WHERE org_id = %s", (org_id,))
        total_actions = cur.fetchone()["total"]

        # Actions today
        cur.execute("SELECT COUNT(*) as total FROM actions WHERE org_id = %s AND timestamp >= NOW() - INTERVAL '24 hours'", (org_id,))
        actions_today = cur.fetchone()["total"]

        # Actions this week
        cur.execute("SELECT COUNT(*) as total FROM actions WHERE org_id = %s AND timestamp >= NOW() - INTERVAL '7 days'", (org_id,))
        actions_week = cur.fetchone()["total"]

        # Actions this month
        cur.execute("SELECT COUNT(*) as total FROM actions WHERE org_id = %s AND timestamp >= NOW() - INTERVAL '30 days'", (org_id,))
        actions_month = cur.fetchone()["total"]

        # Total agents
        cur.execute("SELECT COUNT(*) as total FROM agents WHERE org_id = %s", (org_id,))
        total_agents = cur.fetchone()["total"]

        # Total alerts
        cur.execute("SELECT COUNT(*) as total FROM alerts WHERE org_id = %s", (org_id,))
        total_alerts = cur.fetchone()["total"]

        # Flagged actions
        cur.execute("SELECT COUNT(*) as total FROM actions WHERE org_id = %s AND flagged = TRUE", (org_id,))
        flagged_actions = cur.fetchone()["total"]

        # Actions by day for last 7 days
        cur.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as count
            FROM actions WHERE org_id = %s AND timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(timestamp) ORDER BY day ASC
        """, (org_id,))
        daily = [{"day": str(r["day"]), "count": r["count"]} for r in cur.fetchall()]

        # Top agents by action count
        cur.execute("""
            SELECT agent_id, COUNT(*) as count FROM actions
            WHERE org_id = %s GROUP BY agent_id ORDER BY count DESC LIMIT 5
        """, (org_id,))
        top_agents = [{"agent_id": r["agent_id"], "count": r["count"]} for r in cur.fetchall()]

    return {
        "total_actions": total_actions,
        "actions_today": actions_today,
        "actions_this_week": actions_week,
        "actions_this_month": actions_month,
        "total_agents": total_agents,
        "total_alerts": total_alerts,
        "flagged_actions": flagged_actions,
        "flagged_rate": round(flagged_actions / total_actions, 3) if total_actions > 0 else 0,
        "daily_breakdown": daily,
        "top_agents": top_agents,
    }

@app.get("/status", response_class=HTMLResponse)
def status_page(db=Depends(get_db)):
    """Public status page for Vaultak services."""
    import time
    services = []

    # Check database
    try:
        with db.cursor() as cur:
            cur.execute("SELECT 1")
        services.append({"name": "Database", "status": "operational", "latency": None})
    except Exception as e:
        services.append({"name": "Database", "status": "degraded", "latency": None})

    # Check API
    services.append({"name": "API", "status": "operational", "latency": None})
    services.append({"name": "Dashboard", "status": "operational", "latency": None})
    services.append({"name": "SDK", "status": "operational", "latency": None})

    all_operational = all(s["status"] == "operational" for s in services)
    overall = "All Systems Operational" if all_operational else "Partial Outage"
    overall_color = "#4ade80" if all_operational else "#ff9500"
    overall_bg = "rgba(74,222,128,0.12)" if all_operational else "rgba(255,149,0,0.12)"

    rows = ""
    for s in services:
        color = "#4ade80" if s["status"] == "operational" else "#ff9500"
        rows += f"""
        <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 0;border-bottom:1px solid rgba(255,255,255,0.07)">
          <span style="font-size:14px;color:#ede9e4">{s["name"]}</span>
          <span style="font-size:12px;font-family:monospace;color:{color};background:rgba(255,255,255,0.05);padding:4px 12px;border-radius:20px;border:1px solid {color}40">{s["status"].upper()}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>Vaultak Status</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}}
    body::before{{content:'';position:fixed;top:-20%;left:-10%;width:65%;height:65%;background:radial-gradient(ellipse,rgba(99,88,255,0.15) 0%,transparent 70%);pointer-events:none;z-index:0}}
    .container{{max-width:640px;margin:0 auto;position:relative;z-index:1}}
    .brand{{font-size:20px;font-weight:700;color:#fff;margin-bottom:40px}}
    .overall{{background:{overall_bg};border:1px solid {overall_color}40;border-radius:12px;padding:20px 24px;margin-bottom:32px;display:flex;align-items:center;gap:12px}}
    .dot{{width:10px;height:10px;border-radius:50%;background:{overall_color};box-shadow:0 0 8px {overall_color}}}
    .overall-text{{font-size:16px;font-weight:600;color:{overall_color}}}
    .card{{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:14px;padding:24px;margin-bottom:24px}}
    .card-title{{font-size:11px;font-family:'JetBrains Mono',monospace;letter-spacing:.12em;color:#44414f;text-transform:uppercase;margin-bottom:4px}}
    .updated{{font-size:11px;color:#44414f;font-family:monospace;margin-top:32px;text-align:center}}
    a{{color:#a89fe0;text-decoration:none}}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="overall">
      <div class="dot"></div>
      <span class="overall-text">{overall}</span>
    </div>
    <div class="card">
      <div class="card-title">Services</div>
      {rows}
    </div>
    <div class="updated">Last updated: {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())} · <a href="https://vaultak.com">vaultak.com</a></div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)

@app.get("/security", response_class=HTMLResponse)
def security_page():
    """Public security documentation page."""
    html = """<!DOCTYPE html>
<html>
<head>
  <title>Security — Vaultak</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}
    body::before{content:'';position:fixed;top:-20%;left:-10%;width:65%;height:65%;background:radial-gradient(ellipse,rgba(99,88,255,0.15) 0%,transparent 70%);pointer-events:none;z-index:0}
    .container{max-width:720px;margin:0 auto;position:relative;z-index:1}
    .brand{font-size:20px;font-weight:700;color:#fff;margin-bottom:8px}
    .nav{font-size:13px;color:#8a8695;margin-bottom:48px}
    .nav a{color:#a89fe0;text-decoration:none}
    h1{font-size:32px;font-weight:700;color:#fff;margin-bottom:12px;letter-spacing:-.5px}
    .subtitle{font-size:16px;color:#8a8695;margin-bottom:48px;line-height:1.6}
    .section{margin-bottom:40px}
    .section-title{font-size:18px;font-weight:600;color:#fff;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.08)}
    .card{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:12px;padding:20px 24px;margin-bottom:12px}
    .card-title{font-size:14px;font-weight:600;color:#fff;margin-bottom:6px}
    .card-desc{font-size:13px;color:#8a8695;line-height:1.6}
    .badge{display:inline-flex;align-items:center;padding:4px 12px;border-radius:20px;font-size:11px;font-family:monospace;font-weight:600;letter-spacing:.06em;border:1px solid;margin-bottom:16px}
    .badge-green{background:rgba(74,222,128,.1);color:#4ade80;border-color:rgba(74,222,128,.25)}
    .badge-yellow{background:rgba(245,197,24,.1);color:#f5c518;border-color:rgba(245,197,24,.25)}
    .contact{background:rgba(99,88,255,0.08);border:1px solid rgba(99,88,255,0.2);border-radius:12px;padding:24px;margin-top:40px}
    .contact-title{font-size:16px;font-weight:600;color:#fff;margin-bottom:8px}
    .contact-desc{font-size:13px;color:#8a8695;margin-bottom:16px}
    a.btn{background:#fff;color:#000;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="nav"><a href="https://vaultak.com">Home</a> · <a href="https://docs.vaultak.com">Docs</a> · Security</div>
    <h1>Security</h1>
    <p class="subtitle">How Vaultak protects your data and your agents.</p>

    <div class="section">
      <div class="section-title">Data Security</div>
      <div class="card">
        <div class="card-title">API Key Hashing</div>
        <div class="card-desc">API keys are never stored in plaintext. We store only a SHA-256 hash of each key. Once generated, the full key is shown once and never retrievable — not even by Vaultak staff.</div>
      </div>
      <div class="card">
        <div class="card-title">Data Encryption</div>
        <div class="card-desc">All data is encrypted in transit using TLS 1.2+. Database connections use SSL. Sensitive fields are never logged.</div>
      </div>
      <div class="card">
        <div class="card-title">Data Isolation</div>
        <div class="card-desc">Every organization's data is fully isolated. All database queries are scoped to your organization ID — it is impossible to access another organization's agents, actions, or alerts.</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Infrastructure</div>
      <div class="card">
        <div class="card-title">Hosting</div>
        <div class="card-desc">Vaultak runs on Railway (backend) and Vercel (dashboard), both SOC 2 Type II certified providers. Database is hosted on Railway's managed PostgreSQL with automated backups.</div>
      </div>
      <div class="card">
        <div class="card-title">Rate Limiting</div>
        <div class="card-desc">All API endpoints are rate limited to 100 requests per 60 seconds per API key. Exceeding this limit returns a 429 response with a Retry-After header.</div>
      </div>
      <div class="card">
        <div class="card-title">Authentication</div>
        <div class="card-desc">User authentication is handled by Clerk, a SOC 2 Type II certified identity provider. Vaultak never stores passwords. API keys use prefix-based identification with hash verification.</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Compliance</div>
      <div class="badge badge-yellow">SOC 2 — In Progress</div>
      <div class="card">
        <div class="card-title">SOC 2 Type II</div>
        <div class="card-desc">Vaultak is currently working toward SOC 2 Type II certification. We follow SOC 2 security principles including access controls, encryption, monitoring, and incident response procedures.</div>
      </div>
      <div class="card">
        <div class="card-title">GDPR</div>
        <div class="card-desc">Vaultak processes only the data necessary to provide the service. Users can request deletion of their data at any time by contacting security@vaultak.com.</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Responsible Disclosure</div>
      <div class="card">
        <div class="card-title">Vulnerability Reporting</div>
        <div class="card-desc">If you discover a security vulnerability in Vaultak, please report it to security@vaultak.com. We will respond within 48 hours and work with you to resolve the issue responsibly. We do not pursue legal action against researchers who act in good faith.</div>
      </div>
    </div>

    <div class="contact">
      <div class="contact-title">Security Contact</div>
      <div class="contact-desc">For security inquiries, vulnerability reports, or compliance documentation requests, contact our security team directly.</div>
      <a href="mailto:security@vaultak.com" class="btn">security@vaultak.com</a>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>Privacy Policy — Vaultak</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}
    .container{max-width:720px;margin:0 auto}
    .brand{font-size:20px;font-weight:700;color:#fff;margin-bottom:8px}
    .nav{font-size:13px;color:#8a8695;margin-bottom:48px}
    .nav a{color:#a89fe0;text-decoration:none}
    h1{font-size:32px;font-weight:700;color:#fff;margin-bottom:8px}
    .date{font-size:13px;color:#8a8695;margin-bottom:40px}
    h2{font-size:18px;font-weight:600;color:#fff;margin:32px 0 12px}
    p{font-size:14px;color:#8a8695;line-height:1.8;margin-bottom:12px}
    ul{padding-left:20px;margin-bottom:12px}
    li{font-size:14px;color:#8a8695;line-height:1.8;margin-bottom:6px}
    a{color:#a89fe0}
    .contact{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:12px;padding:24px;margin-top:40px}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="nav"><a href="https://vaultak.com">Home</a> · Privacy Policy</div>
    <h1>Privacy Policy</h1>
    <div class="date">Effective date: April 7, 2026</div>

    <p>Vaultak ("we", "our", or "us") operates the Vaultak platform, including vaultak.com, app.vaultak.com, and the Vaultak SDK. This Privacy Policy explains how we collect, use, and protect your information.</p>

    <h2>Information We Collect</h2>
    <ul>
      <li><strong>Account information:</strong> Email address and name when you sign up.</li>
      <li><strong>Agent data:</strong> Actions, risk scores, alerts, and audit logs generated by your AI agents.</li>
      <li><strong>Usage data:</strong> API request counts, timestamps, and error logs.</li>
      <li><strong>Authentication data:</strong> Handled by Clerk. We never store passwords.</li>
    </ul>

    <h2>How We Use Your Information</h2>
    <ul>
      <li>To provide and improve the Vaultak service</li>
      <li>To send transactional emails (API keys, alerts, account notifications)</li>
      <li>To detect abuse and enforce rate limits</li>
      <li>To generate anonymized usage statistics</li>
    </ul>

    <h2>Data Storage and Security</h2>
    <p>Your data is stored in a managed PostgreSQL database hosted on Railway in the EU (europe-west4). All data is encrypted in transit using TLS 1.2+. API keys are stored as SHA-256 hashes and are never recoverable in plaintext.</p>

    <h2>Data Sharing</h2>
    <p>We do not sell your data. We share data only with the following service providers who help us operate the platform:</p>
    <ul>
      <li>Railway — infrastructure hosting</li>
      <li>Vercel — dashboard hosting</li>
      <li>Clerk — user authentication</li>
      <li>Resend — transactional email</li>
    </ul>

    <h2>Data Retention</h2>
    <p>We retain your data for as long as your account is active. You may request deletion of your account and all associated data at any time by contacting privacy@vaultak.com. We will process deletion requests within 30 days.</p>

    <h2>Your Rights</h2>
    <p>Depending on your location, you may have the right to access, correct, or delete your personal data. To exercise these rights, contact privacy@vaultak.com.</p>

    <h2>Cookies</h2>
    <p>Vaultak uses only essential cookies required for authentication. We do not use tracking or advertising cookies.</p>

    <h2>Changes to This Policy</h2>
    <p>We may update this policy from time to time. We will notify you of significant changes by email or by posting a notice on our website.</p>

    <div class="contact">
      <strong style="color:#fff">Contact</strong>
      <p style="margin-top:8px">For privacy-related questions, contact us at <a href="mailto:privacy@vaultak.com">privacy@vaultak.com</a></p>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>Terms of Service — Vaultak</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}
    .container{max-width:720px;margin:0 auto}
    .brand{font-size:20px;font-weight:700;color:#fff;margin-bottom:8px}
    .nav{font-size:13px;color:#8a8695;margin-bottom:48px}
    .nav a{color:#a89fe0;text-decoration:none}
    h1{font-size:32px;font-weight:700;color:#fff;margin-bottom:8px}
    .date{font-size:13px;color:#8a8695;margin-bottom:40px}
    h2{font-size:18px;font-weight:600;color:#fff;margin:32px 0 12px}
    p{font-size:14px;color:#8a8695;line-height:1.8;margin-bottom:12px}
    ul{padding-left:20px;margin-bottom:12px}
    li{font-size:14px;color:#8a8695;line-height:1.8;margin-bottom:6px}
    a{color:#a89fe0}
    .contact{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:12px;padding:24px;margin-top:40px}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="nav"><a href="https://vaultak.com">Home</a> · Terms of Service</div>
    <h1>Terms of Service</h1>
    <div class="date">Effective date: April 7, 2026</div>

    <p>By accessing or using Vaultak, you agree to be bound by these Terms of Service. If you do not agree, do not use the service.</p>

    <h2>1. The Service</h2>
    <p>Vaultak provides a runtime security platform for AI agents, including an SDK, REST API, and web dashboard. We reserve the right to modify or discontinue the service at any time with reasonable notice.</p>

    <h2>2. Your Account</h2>
    <ul>
      <li>You must provide accurate information when creating an account.</li>
      <li>You are responsible for maintaining the security of your API keys.</li>
      <li>You must notify us immediately of any unauthorized use of your account.</li>
      <li>You must be at least 18 years old to use this service.</li>
    </ul>

    <h2>3. Acceptable Use</h2>
    <p>You agree not to:</p>
    <ul>
      <li>Use the service to monitor agents performing illegal activities</li>
      <li>Attempt to reverse engineer or circumvent security measures</li>
      <li>Share your API keys publicly or with unauthorized parties</li>
      <li>Use the service in ways that could harm Vaultak or other users</li>
      <li>Exceed rate limits in ways intended to degrade service for others</li>
    </ul>

    <h2>4. Data</h2>
    <p>You retain ownership of all data you submit to Vaultak. By using the service, you grant us a limited license to process your data solely to provide the service. See our Privacy Policy for details on how we handle your data.</p>

    <h2>5. API Keys</h2>
    <p>API keys are shown once upon creation and are your responsibility to store securely. Vaultak cannot recover lost API keys. You may generate a new key at any time from your dashboard, which will invalidate the previous key.</p>

    <h2>6. Service Availability</h2>
    <p>We strive for high availability but do not guarantee uninterrupted service. We are not liable for any losses resulting from service downtime or data loss.</p>

    <h2>7. Limitation of Liability</h2>
    <p>To the maximum extent permitted by law, Vaultak shall not be liable for any indirect, incidental, special, or consequential damages arising from your use of the service. Our total liability shall not exceed the amount you paid us in the 12 months preceding the claim.</p>

    <h2>8. Termination</h2>
    <p>We may suspend or terminate your account if you violate these terms. You may cancel your account at any time by contacting support@vaultak.com.</p>

    <h2>9. Changes to Terms</h2>
    <p>We may update these terms from time to time. Continued use of the service after changes constitutes acceptance of the new terms.</p>

    <h2>10. Governing Law</h2>
    <p>These terms are governed by the laws of the State of Oregon, United States, without regard to conflict of law principles.</p>

    <div class="contact">
      <strong style="color:#fff">Questions?</strong>
      <p style="margin-top:8px">Contact us at <a href="mailto:support@vaultak.com">support@vaultak.com</a></p>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/about", response_class=HTMLResponse)
def about_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>About — Vaultak</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}
    body::before{content:'';position:fixed;top:-20%;left:-10%;width:65%;height:65%;background:radial-gradient(ellipse,rgba(99,88,255,0.15) 0%,transparent 70%);pointer-events:none;z-index:0}
    .container{max-width:720px;margin:0 auto;position:relative;z-index:1}
    .brand{font-size:20px;font-weight:700;color:#fff;margin-bottom:8px}
    .nav{font-size:13px;color:#8a8695;margin-bottom:48px}
    .nav a{color:#a89fe0;text-decoration:none}
    h1{font-size:40px;font-weight:700;color:#fff;margin-bottom:16px;letter-spacing:-.5px;line-height:1.1}
    .subtitle{font-size:18px;color:#8a8695;margin-bottom:48px;line-height:1.6}
    h2{font-size:20px;font-weight:600;color:#fff;margin:40px 0 12px}
    p{font-size:15px;color:#8a8695;line-height:1.8;margin-bottom:16px}
    .card{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:12px;padding:24px;margin-bottom:16px}
    .card-title{font-size:16px;font-weight:600;color:#fff;margin-bottom:8px}
    .card-desc{font-size:14px;color:#8a8695;line-height:1.7}
    .cta{display:flex;gap:12px;margin-top:40px}
    .btn-primary{background:#fff;color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px}
    .btn-secondary{background:transparent;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px;border:1px solid rgba(255,255,255,0.2)}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="nav"><a href="https://vaultak.com">Home</a> · About</div>

    <h1>Runtime security for the age of autonomous AI</h1>
    <p class="subtitle">Vaultak was built because AI agents are being deployed into production systems with no governance layer — and the tools to fix that didn't exist.</p>

    <h2>The problem we're solving</h2>
    <p>AI agents are different from traditional software. They don't follow a fixed execution path — they reason, plan, and act autonomously. A single misconfigured agent can delete files, exfiltrate data, or make thousands of irreversible API calls before anyone notices.</p>
    <p>Existing security tools protect the perimeter. Firewalls, WAFs, and IAM systems guard the edges of your infrastructure — but they have no visibility into what happens inside once an agent has access. Vaultak fills that gap.</p>

    <h2>What we built</h2>
    <div class="card">
      <div class="card-title">Behavioral monitoring</div>
      <div class="card-desc">Every action an agent takes is intercepted, scored across five risk dimensions, and logged in real time. Anomalies are detected automatically as agents deviate from their learned baseline.</div>
    </div>
    <div class="card">
      <div class="card-title">Permission profiles</div>
      <div class="card-desc">Developers declare exactly what an agent is allowed to do — which action types, which resources, at what rate. Anything outside those boundaries is blocked before it executes.</div>
    </div>
    <div class="card">
      <div class="card-title">Automatic rollback</div>
      <div class="card-desc">When a violation is detected, Vaultak can automatically reverse the last N agent actions and pause the agent for human review. No other tool does this.</div>
    </div>

    <h2>Our mission</h2>
    <p>We believe autonomous AI systems need the same governance infrastructure as any other critical system. Our mission is to make deploying AI agents safe — without slowing down the developers building them.</p>

    <div class="cta">
      <a href="https://app.vaultak.com" class="btn-primary">Get started free</a>
      <a href="https://docs.vaultak.com" class="btn-secondary">Read the docs</a>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/pricing", response_class=HTMLResponse)
def pricing_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>Pricing — Vaultak</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#060609;color:#ede9e4;font-family:Inter,sans-serif;min-height:100vh;padding:40px 20px}
    body::before{content:'';position:fixed;top:-20%;left:-10%;width:65%;height:65%;background:radial-gradient(ellipse,rgba(99,88,255,0.15) 0%,transparent 70%);pointer-events:none;z-index:0}
    .container{max-width:960px;margin:0 auto;position:relative;z-index:1}
    .brand{font-size:20px;font-weight:700;color:#fff;margin-bottom:8px}
    .nav{font-size:13px;color:#8a8695;margin-bottom:48px}
    .nav a{color:#a89fe0;text-decoration:none}
    h1{font-size:40px;font-weight:700;color:#fff;margin-bottom:12px;text-align:center;letter-spacing:-.5px}
    .subtitle{font-size:16px;color:#8a8695;margin-bottom:56px;text-align:center;line-height:1.6}
    .plans{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:48px}
    .plan{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:16px;padding:32px;position:relative}
    .plan.featured{border-color:rgba(255,255,255,0.25);background:rgba(255,255,255,0.08)}
    .plan-badge{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:#fff;color:#000;font-size:11px;font-weight:700;padding:4px 14px;border-radius:20px;white-space:nowrap}
    .plan-name{font-size:14px;font-weight:600;color:#8a8695;margin-bottom:8px;text-transform:uppercase;letter-spacing:.1em}
    .plan-price{font-size:40px;font-weight:700;color:#fff;margin-bottom:4px;letter-spacing:-1px}
    .plan-price span{font-size:16px;font-weight:400;color:#8a8695}
    .plan-desc{font-size:13px;color:#8a8695;margin-bottom:24px;line-height:1.6}
    .plan-features{list-style:none;margin-bottom:28px}
    .plan-features li{font-size:13px;color:#ede9e4;padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.05);display:flex;align-items:center;gap:8px}
    .plan-features li:last-child{border-bottom:none}
    .check{color:#4ade80;font-size:14px}
    .plan-btn{display:block;text-align:center;padding:11px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;transition:all .15s}
    .plan-btn-light{background:#fff;color:#000}
    .plan-btn-light:hover{background:#e5e5e5}
    .plan-btn-outline{background:transparent;color:#fff;border:1px solid rgba(255,255,255,0.2)}
    .plan-btn-outline:hover{border-color:rgba(255,255,255,0.4)}
    .faq{max-width:640px;margin:0 auto}
    .faq h2{font-size:24px;font-weight:600;color:#fff;margin-bottom:24px;text-align:center}
    .faq-item{border-bottom:1px solid rgba(255,255,255,0.07);padding:20px 0}
    .faq-q{font-size:15px;font-weight:500;color:#fff;margin-bottom:8px}
    .faq-a{font-size:14px;color:#8a8695;line-height:1.7}
    @media(max-width:1100px){.plans{grid-template-columns:repeat(2,1fr) !important}} @media(max-width:640px){.plans{grid-template-columns:1fr !important}}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Vaultak</div>
    <div class="nav"><a href="https://vaultak.com">Home</a> · Pricing</div>

    <h1>Simple, transparent pricing</h1>
    <p class="subtitle">Start free. Scale as your agents do.</p>

    <p style="text-align:center;font-size:13px;color:#555;margin-bottom:16px;font-style:italic;">Every competitor charges enterprise contract pricing starting at $50,000/year.<br>Vaultak is the only AI agent security platform with transparent self-serve pricing.</p>
    <p style="text-align:center;font-size:13px;color:#8a8695;margin-bottom:40px;">All plans include the Vaultak SDK and Sentry desktop app for Mac, Windows, and Linux.</p>

    <div class="plans" style="grid-template-columns:repeat(5,1fr);gap:12px;">

      <div class="plan">
        <div class="plan-name">Starter</div>
        <div class="plan-price" style="font-size:30px;">$0<span>/mo</span></div>
        <div class="plan-desc">For anyone getting started with AI agent monitoring.</div>
        <ul class="plan-features">
          <li><span class="check">&#10003;</span> 1 agent</li>
          <li><span class="check">&#10003;</span> 10,000 actions/mo</li>
          <li><span class="check">&#10003;</span> 7-day audit log</li>
          <li><span class="check">&#10003;</span> ALERT mode only</li>
          <li><span class="check">&#10003;</span> Dashboard access</li>
          <li><span class="check">&#10003;</span> Community support</li>
        </ul>
        <a href="https://app.vaultak.com" class="plan-btn plan-btn-outline">Get started free</a>
      </div>

      <div class="plan">
        <div class="plan-name">Pro</div>
        <div class="plan-price" style="font-size:30px;">$49<span>/mo</span></div>
        <div class="plan-desc">For individuals running agents in production.</div>
        <ul class="plan-features">
          <li><span class="check">&#10003;</span> Up to 5 agents</li>
          <li><span class="check">&#10003;</span> 100,000 actions/mo</li>
          <li><span class="check">&#10003;</span> 30-day audit log</li>
          <li><span class="check">&#10003;</span> ALERT, PAUSE, ROLLBACK</li>
          <li><span class="check">&#10003;</span> Policy engine</li>
          <li><span class="check">&#10003;</span> Email support</li>
        </ul>
        <a href="https://app.vaultak.com?view=billing" class="plan-btn plan-btn-outline">Get started</a>
      </div>

      <div class="plan featured">
        <div class="plan-badge">Most popular</div>
        <div class="plan-name">Team</div>
        <div class="plan-price" style="font-size:30px;">$99<span>/mo</span></div>
        <div class="plan-desc">For teams managing multiple agents.</div>
        <ul class="plan-features">
          <li><span class="check">&#10003;</span> Up to 15 agents</li>
          <li><span class="check">&#10003;</span> 500,000 actions/mo</li>
          <li><span class="check">&#10003;</span> 90-day audit log</li>
          <li><span class="check">&#10003;</span> Everything in Pro</li>
          <li><span class="check">&#10003;</span> PII masking</li>
          <li><span class="check">&#10003;</span> Priority support</li>
        </ul>
        <a href="https://app.vaultak.com?view=billing" class="plan-btn plan-btn-light">Get started</a>
      </div>

      <div class="plan">
        <div class="plan-name">Business</div>
        <div class="plan-price" style="font-size:30px;">$299<span>/mo</span></div>
        <div class="plan-desc">For companies with compliance and security requirements.</div>
        <ul class="plan-features">
          <li><span class="check">&#10003;</span> Up to 50 agents</li>
          <li><span class="check">&#10003;</span> 2,000,000 actions/mo</li>
          <li><span class="check">&#10003;</span> 1-year audit log</li>
          <li><span class="check">&#10003;</span> Everything in Team</li>
          <li><span class="check">&#10003;</span> SIEM integration</li>
          <li><span class="check">&#10003;</span> Shadow AI detection</li>
          <li><span class="check">&#10003;</span> SLA guarantee</li>
        </ul>
        <a href="https://app.vaultak.com?view=billing" class="plan-btn plan-btn-outline">Get started</a>
      </div>

      <div class="plan">
        <div class="plan-name">Enterprise</div>
        <div class="plan-price" style="font-size:24px;">From $999<span>/mo</span></div>
        <div class="plan-desc">For large organizations with advanced security needs.</div>
        <ul class="plan-features">
          <li><span class="check">&#10003;</span> Unlimited agents</li>
          <li><span class="check">&#10003;</span> Unlimited actions</li>
          <li><span class="check">&#10003;</span> Unlimited audit log</li>
          <li><span class="check">&#10003;</span> Everything in Business</li>
          <li><span class="check">&#10003;</span> On-premises deployment</li>
          <li><span class="check">&#10003;</span> SSO / SAML</li>
          <li><span class="check">&#10003;</span> Dedicated support</li>
          <li><span class="check">&#10003;</span> Custom contract</li>
        </ul>
        <a href="mailto:sales@vaultak.com" class="plan-btn plan-btn-outline">Contact sales</a>
      </div>

    </div>

    <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:14px;padding:28px 32px;margin-bottom:48px;">
      <div style="font-size:11px;font-family:monospace;color:#555;letter-spacing:.1em;margin-bottom:16px;">HOW VAULTAK COMPARES</div>
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:0;font-size:13px;">
        <div style="color:#555;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.05);">Capability</div>
        <div style="color:#fff;font-weight:600;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.05);text-align:center;">Vaultak</div>
        <div style="color:#555;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.05);text-align:center;">Others</div>
        <div style="color:#8a8695;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">Transparent pricing</div>
        <div style="color:#4ade80;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">Yes</div>
        <div style="color:#f87171;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">No</div>
        <div style="color:#8a8695;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">Self-serve signup</div>
        <div style="color:#4ade80;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">Yes</div>
        <div style="color:#f87171;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">Demo required</div>
        <div style="color:#8a8695;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">Automatic rollback</div>
        <div style="color:#4ade80;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">Yes</div>
        <div style="color:#f87171;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">No</div>
        <div style="color:#8a8695;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);">Zero-code daemon</div>
        <div style="color:#4ade80;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">Yes</div>
        <div style="color:#f87171;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:center;">No</div>
        <div style="color:#8a8695;padding:8px 0;">Starting price</div>
        <div style="color:#4ade80;padding:8px 12px;text-align:center;">$0 free</div>
        <div style="color:#555;padding:8px 12px;text-align:center;">$50K+/year</div>
      </div>
    </div>

    <div class="faq">
      <h2>Frequently asked questions</h2>
      <div class="faq-item">
        <div class="faq-q">What counts as an action?</div>
        <div class="faq-a">An action is any event logged by a Vaultak-monitored agent — a file write, API call, database query, and so on. Each event intercepted by Vaultak Core or Vaultak Sentry counts as one action.</div>
      </div>
      <div class="faq-item">
        <div class="faq-q">Can I upgrade or downgrade at any time?</div>
        <div class="faq-a">Yes. Upgrades take effect immediately. Downgrades take effect at the start of the next billing cycle.</div>
      </div>
      <div class="faq-item">
        <div class="faq-q">Do paid plans include a free trial?</div>
        <div class="faq-a">Yes. Pro, Team, and Business all include a 14-day free trial with no credit card required.</div>
      </div>
      <div class="faq-item">
        <div class="faq-q">What happens if I exceed my action limit?</div>
        <div class="faq-a">You will be notified at 80% of your limit. If you exceed it, monitoring continues and you will be prompted to upgrade. We never silently drop events.</div>
      </div>
      <div class="faq-item">
        <div class="faq-q">Why is Vaultak so much cheaper than enterprise alternatives?</div>
        <div class="faq-a">Most enterprise AI security platforms are built for long procurement cycles with six-figure annual commitments. Vaultak is built for developers and security teams who need governance now, not after a 90-day sales cycle. You get the same runtime security capabilities at a fraction of the cost.</div>
      </div>
      <div class="faq-item">
        <div class="faq-q">Is on-premises deployment available?</div>
        <div class="faq-a">Yes. On-premises deployment via Docker Compose or Kubernetes is available on the Enterprise plan. Your data never leaves your infrastructure.</div>
      </div>
    </div>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/blog", response_class=HTMLResponse)
def blog_index():
    with open(os.path.join(os.path.dirname(__file__), "blog_index.html")) as f:
        return f.read()

@app.get("/blog/how-to-score-your-ai-agent-security-risk")
def blog_agent_risk_score():
    return FileResponse("blog_how-to-score-your-ai-agent-security-risk.html")

@app.get("/blog/how-to-monitor-ai-agents-in-production")
def blog_monitor_agents():
    return FileResponse("blog_how-to-monitor-ai-agents-in-production.html")

@app.get("/ba9df925e5dd46ed97752cbf9a77d459.txt")
def indexnow_key():
    return PlainTextResponse("ba9df925e5dd46ed97752cbf9a77d459")

@app.get("/sitemap.xml")
def sitemap():
    from fastapi.responses import Response
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://vaultak.com/</loc><priority>1.0</priority></url>
  <url><loc>https://vaultak.com/scan</loc><priority>0.95</priority></url>
  <url><loc>https://vaultak.com/pricing</loc><priority>0.9</priority></url>
  <url><loc>https://vaultak.com/about</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/security</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/status</loc><priority>0.7</priority></url>
  <url><loc>https://vaultak.com/privacy</loc><priority>0.6</priority></url>
  <url><loc>https://vaultak.com/terms</loc><priority>0.6</priority></url>
  <url><loc>https://vaultak.com/blog</loc><priority>0.9</priority></url>
  <url><loc>https://vaultak.com/download</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/ai-agent-hipaa-soc2-compliance</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/ai-agent-policy-enforcement</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/ai-agent-security-best-practices</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/ai-agent-what-happens-when-rogue</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-add-access-control-ai-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-add-guardrails-to-claude-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-add-kill-switch-ai-agent</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-audit-ai-agent-actions</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-deploy-ai-agents-safely</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-enforce-least-privilege-ai-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-limit-ai-agent-capabilities</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-monitor-ai-agent-actions</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-prevent-ai-agent-data-deletion</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-prevent-ai-agent-sensitive-data-access</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-prevent-prompt-injection-ai-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-roll-back-ai-agent-damage</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-secure-autogpt-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-secure-crewai-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-secure-langchain-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-secure-langgraph-agents</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-secure-openai-assistants</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/how-to-test-ai-agent-security</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/what-is-ai-agent-runtime-security</loc><priority>0.8</priority></url>
  <url><loc>https://vaultak.com/blog/why-your-ai-agent-needs-a-kill-switch</loc><priority>0.8</priority></url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")

@app.get("/favicon.svg")
def serve_favicon():
    favicon_path = os.path.join(os.path.dirname(__file__), "favicon.svg")
    return FileResponse(favicon_path, media_type="image/svg+xml")

# ─── PII Masking Endpoints ───────────────────────────────────────────────────

class PIIMaskRequest(BaseModel):
    text: str
    strategy: Optional[str] = "partial"
    disabled_types: Optional[List[str]] = []

@app.post("/api/pii/mask")
def mask_pii(body: PIIMaskRequest, org_id: str = Depends(get_org)):
    """Mask PII in text before it reaches an agent or is returned to a user."""
    if not HAS_PII:
        raise HTTPException(status_code=503, detail="PII module not available")
    if not body.text:
        raise HTTPException(status_code=400, detail="text is required")
    try:
        disabled = []
        for t in (body.disabled_types or []):
            try:
                disabled.append(PIIType(t))
            except ValueError:
                pass
        masker = PIIMasker(strategy=body.strategy or "partial", disabled_types=disabled)
        result = masker.mask(body.text)
        return {
            "masked":      result.masked,
            "pii_found":   result.pii_found,
            "risk_score":  result.risk_score,
            "detections": [
                {"type": m.pii_type.value, "confidence": m.confidence}
                for m in result.matches
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/pii/scan")
def scan_pii(body: PIIMaskRequest, org_id: str = Depends(get_org)):
    """Scan text for PII without masking. Returns detection report only."""
    if not HAS_PII:
        raise HTTPException(status_code=503, detail="PII module not available")
    try:
        masker = PIIMasker()
        result = masker.mask(body.text or "")
        return {
            "pii_found":  result.pii_found,
            "risk_score": result.risk_score,
            "count":      len(result.matches),
            "types":      list(set(m.pii_type.value for m in result.matches)),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─── SIEM Endpoints ───────────────────────────────────────────────────────────

class SIEMWebhookConfig(BaseModel):
    url: str
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

@app.get("/api/siem/status")
def siem_status(org_id: str = Depends(get_org)):
    """Return SIEM router status and connector stats."""
    if not HAS_SIEM or not _siem_router:
        return {"enabled": False, "connectors": []}
    return {
        "enabled":    True,
        "connectors": [c.name for c in _siem_router.connectors],
        "stats":      _siem_router.stats(),
    }

@app.post("/api/siem/test")
def siem_test(org_id: str = Depends(get_org)):
    """Send a test event to all configured SIEM connectors."""
    if not HAS_SIEM or not _siem_router:
        raise HTTPException(status_code=503, detail="No SIEM connectors configured")
    test_event = {
        "agent_id":    "test-agent",
        "action_type": "siem_test",
        "resource":    "vaultak.siem.test",
        "risk_score":  0.1,
        "decision":    "allow",
        "reason":      "SIEM connectivity test",
        "org_id":      org_id,
    }
    _siem_router.route(test_event)
    return {"sent": True, "connectors": len(_siem_router.connectors)}

# ─── Policy Engine ─────────────────────────────────────────────────────────────

import fnmatch
from datetime import datetime, timezone

class PolicyCheck(BaseModel):
    agent_id: str
    action_type: str
    resource: Optional[str] = ""
    payload: Optional[Dict[str, Any]] = None

class PolicyCreate(BaseModel):
    name: str
    action_type: Optional[str] = None
    resource_pattern: Optional[str] = None
    effect: str = "block"
    max_risk_score: Optional[float] = None
    time_start: Optional[int] = None
    time_end: Optional[int] = None
    days_allowed: Optional[List[str]] = None
    priority: int = 0

def evaluate_policies(policies: list, action_type: str, resource: str, risk_score: float) -> dict:
    """Evaluate all policies and return the highest priority matching one."""
    now = datetime.now(timezone.utc)
    current_hour = now.hour
    current_day = now.strftime("%A").lower()

    matched_policies = []

    for policy in policies:
        if not policy.get("enabled"):
            continue

        # Check action_type match
        if policy.get("action_type"):
            if not fnmatch.fnmatch(action_type.lower(), policy["action_type"].lower()):
                continue

        # Check resource pattern match
        if policy.get("resource_pattern"):
            if not fnmatch.fnmatch((resource or "").lower(), policy["resource_pattern"].lower()):
                continue

        # Check time window
        if policy.get("time_start") is not None and policy.get("time_end") is not None:
            if not (policy["time_start"] <= current_hour < policy["time_end"]):
                continue

        # Check days allowed
        if policy.get("days_allowed"):
            if current_day not in [d.lower() for d in policy["days_allowed"]]:
                continue

        # Check max risk score
        if policy.get("max_risk_score") is not None:
            if risk_score > policy["max_risk_score"]:
                matched_policies.append(policy)
                continue

        matched_policies.append(policy)

    if not matched_policies:
        return {"decision": "allow", "policy": None, "reason": "No matching policies"}

    # Sort by priority (highest first)
    matched_policies.sort(key=lambda p: p.get("priority", 0), reverse=True)
    top = matched_policies[0]

    return {
        "decision": top["effect"],
        "policy": top,
        "reason": f"Policy '{top['name']}' matched (effect: {top['effect']})"
    }

@app.post("/api/check")
def check_action(body: PolicyCheck, org_id: str = Depends(get_org), db=Depends(get_db)):
    """Pre-execution check — call this BEFORE running an agent action."""
    try:
        # Compute risk score first
        risk_score, breakdown = compute_risk_score(
            action_type=body.action_type,
            resource=body.resource or "",
            payload=body.payload or {},
            agent_id=body.agent_id,
            org_id=org_id,
            db=db
        )

        # Check if agent is paused
        with db.cursor() as cur:
            cur.execute("SELECT paused, terminated, kill_switch_mode FROM agents WHERE org_id = %s AND agent_id = %s", (org_id, body.agent_id))
            agent = cur.fetchone()

        if agent:
            if agent["terminated"]:
                return {"decision": "block", "reason": "Agent is terminated", "risk_score": risk_score, "risk_breakdown": breakdown}
            if agent["paused"]:
                return {"decision": "block", "reason": "Agent is paused", "risk_score": risk_score, "risk_breakdown": breakdown}

            # Enforce permission profile
            import fnmatch, json as _json

            # Check allowed action types
            allowed_action_types = agent.get("allowed_action_types")
            if allowed_action_types:
                if isinstance(allowed_action_types, str):
                    allowed_action_types = _json.loads(allowed_action_types)
                if body.action_type not in allowed_action_types:
                    return {"decision": "block", "reason": f"Action type '{body.action_type}' not in agent allowlist", "risk_score": risk_score, "risk_breakdown": breakdown}

            # Check allowed resources (glob)
            allowed_resources = agent.get("allowed_resources")
            if allowed_resources:
                if isinstance(allowed_resources, str):
                    allowed_resources = _json.loads(allowed_resources)
                if body.resource and not any(fnmatch.fnmatch(body.resource, p) for p in allowed_resources):
                    return {"decision": "block", "reason": f"Resource '{body.resource}' not in agent allowlist", "risk_score": risk_score, "risk_breakdown": breakdown}

            # Check blocked resources (glob)
            blocked_resources = agent.get("blocked_resources") or []
            if isinstance(blocked_resources, str):
                blocked_resources = _json.loads(blocked_resources)
            if body.resource and any(fnmatch.fnmatch(body.resource, p) for p in blocked_resources):
                return {"decision": "block", "reason": f"Resource '{body.resource}' is blocked for this agent", "risk_score": risk_score, "risk_breakdown": breakdown}

            # Check max risk score
            max_risk_score = agent.get("max_risk_score") or 1.0
            if risk_score > max_risk_score:
                return {"decision": "block", "reason": f"Risk score {risk_score:.2f} exceeds agent max {max_risk_score:.2f}", "risk_score": risk_score, "risk_breakdown": breakdown}

        # Load org policies
        with db.cursor() as cur:
            cur.execute("SELECT * FROM policies WHERE org_id = %s AND enabled = TRUE ORDER BY priority DESC", (org_id,))
            policies = [dict(r) for r in cur.fetchall()]

        # Evaluate policies
        result = evaluate_policies(policies, body.action_type, body.resource or "", risk_score)

        # Auto-block critical risk even without explicit policy
        if risk_score >= 0.90 and result["decision"] == "allow":
            result = {
                "decision": "block",
                "policy": None,
                "reason": f"Auto-blocked: critical risk score {risk_score:.2f}"
            }

        return {
            "decision": result["decision"],
            "reason": result["reason"],
            "risk_score": risk_score,
            "risk_breakdown": breakdown,
            "policy_matched": result["policy"]["name"] if result["policy"] else None,
            "agent_id": body.agent_id,
            "action_type": body.action_type,
            "resource": body.resource
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Policy check error: {e}")
        raise HTTPException(status_code=500, detail="Policy check failed")

@app.get("/api/policies")
def get_policies(org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM policies WHERE org_id = %s ORDER BY priority DESC, created_at DESC", (org_id,))
        return [dict(r) for r in cur.fetchall()]

@app.post("/api/policies")
def create_policy(body: PolicyCreate, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO policies (org_id, name, action_type, resource_pattern, effect,
                max_risk_score, time_start, time_end, days_allowed, priority)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (org_id, body.name, body.action_type, body.resource_pattern, body.effect,
              body.max_risk_score, body.time_start, body.time_end,
              body.days_allowed, body.priority))
        policy = dict(cur.fetchone())
        db.commit()
    return policy

@app.patch("/api/policies/{policy_id}")
def update_policy(policy_id: str, enabled: bool, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("UPDATE policies SET enabled = %s WHERE id = %s AND org_id = %s", (enabled, policy_id, org_id))
        db.commit()
    return {"updated": True}

@app.delete("/api/policies/{policy_id}")
def delete_policy(policy_id: str, org_id: str = Depends(get_org), db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("DELETE FROM policies WHERE id = %s AND org_id = %s", (policy_id, org_id))
        db.commit()
    return {"deleted": True}


# ─── MCP HTTP Endpoint (Smithery / Remote MCP) ────────────────────────────────

from fastapi.responses import StreamingResponse
import asyncio

MCP_TOOLS = [
    {
        "name": "vaultak_risk_score",
        "description": "Score an AI agent's risk level across 5 security dimensions: action type, resource sensitivity, blast radius, behavioral deviation, and time pattern. Returns a 0-100 composite score, risk tier (LOW/MODERATE/HIGH/CRITICAL), per-dimension breakdown, and Vaultak policy recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_description": {"type": "string", "description": "What the agent does — its purpose, workflow, and behaviors."},
                "capabilities": {"type": "array", "items": {"type": "string"}, "description": "List of tools/capabilities the agent has access to."}
            },
            "required": ["agent_description"]
        }
    },
    {
        "name": "vaultak_policy_check",
        "description": "Check whether a specific agent action should be ALLOWED or BLOCKED based on Vaultak's policy engine. Evaluates action/resource pairs against policies using priority-based matching.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "The action the agent wants to perform (delete, write, execute, send_email...)."},
                "resource": {"type": "string", "description": "The resource being acted upon (production_db, s3://bucket/, smtp_server...)."},
                "policies": {"type": "array", "items": {"type": "object"}, "description": "List of Vaultak policy objects to evaluate against.", "default": []}
            },
            "required": ["action", "resource"]
        }
    },
    {
        "name": "vaultak_get_policy_templates",
        "description": "Get ready-to-use Vaultak policy templates for common AI agent security scenarios: database protection, file system limits, API rate limiting, PII protection, production safeguards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario": {"type": "string", "enum": ["database_protection", "file_system_limits", "api_rate_limiting", "pii_protection", "production_safeguards", "all"]}
            },
            "required": ["scenario"]
        }
    }
]

RISK_WEIGHTS = {"action_type": 0.25, "resource_sensitivity": 0.25, "blast_radius": 0.20, "behavioral_deviation": 0.15, "time_pattern": 0.15}

def _score_agent(description: str, capabilities: list) -> dict:
    text = (description + " " + " ".join(capabilities)).lower()
    def count(kws): return sum(1 for w in kws if w in text)
    a = min(100, count(["delete","drop","truncate","destroy","remove"])*25 + count(["write","insert","update","execute","deploy"])*15 + count(["send","email","publish"])*10)
    r = min(100, count(["production","prod_"])*25 + count(["password","secret","credential","token","private key"])*30 + count(["pii","personal data","payment","credit card"])*25 + count(["s3","bucket","filesystem"])*15)
    b = min(100, count(["all users","all records","bulk","batch","global","system-wide"])*30 + count(["mass","every record","without limit"])*35)
    d = min(100, count(["unrestricted","unlimited","bypass","override","autonomous","self-modifying"])*35)
    t = min(100, count(["scheduled","cron","background","always on","24/7","continuous"])*20 + 10)
    composite = min(100, round(a*0.25 + r*0.25 + b*0.20 + d*0.15 + t*0.15))
    tiers = [(0,30,"LOW","Agent operates within acceptable boundaries."),(30,60,"MODERATE","Risk factors present — review recommended."),(60,80,"HIGH","Significant risk — policy enforcement advised."),(80,101,"CRITICAL","Severe risk — immediate enforcement required.")]
    tier, desc = next(((lb,ld) for lo,hi,lb,ld in tiers if lo <= composite < hi), ("LOW",""))
    recs = []
    if a >= 25: recs.append("Restrict destructive actions via Vaultak action-type policies.")
    if r >= 20: recs.append("Block agent access to credentials and production resources.")
    if b >= 20: recs.append("Cap bulk operations to limit blast radius.")
    if d >= 20: recs.append("Enable behavioral deviation monitoring.")
    if composite >= 60: recs.append("Enable Vaultak auto-pause threshold.")
    if composite >= 80: recs.append("Enable Vaultak rollback engine.")
    if not recs: recs.append("Risk profile acceptable. Add Vaultak monitoring for visibility.")
    recs.append("Install: pip install vaultak | Docs: docs.vaultak.com")
    return {"composite_score": composite, "risk_tier": tier, "tier_description": desc,
            "dimensions": {"action_type": a, "resource_sensitivity": r, "blast_radius": b, "behavioral_deviation": d, "time_pattern": t},
            "recommendations": recs}

def _handle_mcp_request(body: dict) -> dict:
    method = body.get("method", "")
    req_id = body.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "vaultak-mcp", "version": APP_VERSION}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
    if method == "tools/call":
        params = body.get("params", {})
        tool = params.get("name", "")
        args = params.get("arguments", {})
        if tool == "vaultak_risk_score":
            result = _score_agent(args.get("agent_description", ""), args.get("capabilities", []))
            text = f"VAULTAK RISK ASSESSMENT\n\nScore: {result['composite_score']}/100 — {result['risk_tier']}\n{result['tier_description']}\n\nDIMENSIONS\n" + "\n".join(f"  {k}: {v}/100" for k,v in result['dimensions'].items()) + "\n\nRECOMMENDATIONS\n" + "\n".join(f"  • {r}" for r in result['recommendations']) + "\n\nPowered by Vaultak — vaultak.com"
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}}
        if tool == "vaultak_policy_check":
            import fnmatch
            action = args.get("action", "").lower()
            resource = args.get("resource", "").lower()
            policies = args.get("policies", [])
            matched = next((p for p in sorted(policies, key=lambda x: x.get("priority", 50)) if fnmatch.fnmatch(action, p.get("action","*").lower()) and fnmatch.fnmatch(resource, p.get("resource","*").lower())), None)
            decision = matched.get("effect", "allow").upper() if matched else "ALLOW"
            reason = matched.get("description", "No matching policy — default allow.") if matched else "No matching policy found."
            text = f"VAULTAK POLICY DECISION\n\nAction: {action}\nResource: {resource}\nDecision: {decision}\nReason: {reason}\n\nManage policies: app.vaultak.com\nPowered by Vaultak — vaultak.com"
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}}
        if tool == "vaultak_get_policy_templates":
            templates = {
                "database_protection": [{"name":"block-delete-prod","action":"delete","resource":"prod*","effect":"deny","priority":1},{"name":"allow-read","action":"read","resource":"*","effect":"allow","priority":10}],
                "pii_protection": [{"name":"block-pii-export","action":"export","resource":"*users*","effect":"deny","priority":1},{"name":"block-pii-send","action":"send","resource":"*personal*","effect":"deny","priority":1}],
                "production_safeguards": [{"name":"block-prod-delete","action":"delete","resource":"prod_*","effect":"deny","priority":1},{"name":"block-prod-deploy","action":"deploy","resource":"prod_*","effect":"deny","priority":1}],
                "file_system_limits": [{"name":"block-system-files","action":"*","resource":"/etc/*","effect":"deny","priority":1},{"name":"allow-tmp","action":"write","resource":"/tmp/*","effect":"allow","priority":20}],
                "api_rate_limiting": [{"name":"block-payment-api","action":"*","resource":"*payment*","effect":"deny","priority":1}],
            }
            selected = templates if args.get("scenario") == "all" else {args.get("scenario"): templates.get(args.get("scenario"), [])}
            text = f"VAULTAK POLICY TEMPLATES\n\n{json.dumps(selected, indent=2)}\n\nAdd to dashboard: app.vaultak.com\nPowered by Vaultak — vaultak.com"
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool}"}}
    if method == "notifications/initialized":
        return None
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

@app.post("/mcp")
async def mcp_endpoint(request: dict):
    response = _handle_mcp_request(request)
    if response is None:
        return {}
    return response

@app.get("/mcp")
async def mcp_get():
    return {"service": "vaultak-mcp", "version": APP_VERSION, "tools": [t["name"] for t in MCP_TOOLS], "docs": "docs.vaultak.com"}


@app.get("/blog/ai-agent-policy-enforcement", response_class=HTMLResponse)
def serve_blog_ai_agent_policy_enforcement():
    p = os.path.join(os.path.dirname(__file__), "blog_ai-agent-policy-enforcement.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/ai-agent-security-best-practices", response_class=HTMLResponse)
def serve_blog_ai_agent_security_best_practices():
    p = os.path.join(os.path.dirname(__file__), "blog_ai-agent-security-best-practices.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/ai-agent-what-happens-when-rogue", response_class=HTMLResponse)
def serve_blog_ai_agent_what_happens_when_rogue():
    p = os.path.join(os.path.dirname(__file__), "blog_ai-agent-what-happens-when-rogue.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-add-access-control-ai-agents", response_class=HTMLResponse)
def serve_blog_how_to_add_access_control_ai_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-add-access-control-ai-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-add-guardrails-to-claude-agents", response_class=HTMLResponse)
def serve_blog_how_to_add_guardrails_to_claude_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-add-guardrails-to-claude-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-add-kill-switch-ai-agent", response_class=HTMLResponse)
def serve_blog_how_to_add_kill_switch_ai_agent():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-add-kill-switch-ai-agent.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-audit-ai-agent-actions", response_class=HTMLResponse)
def serve_blog_how_to_audit_ai_agent_actions():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-audit-ai-agent-actions.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-deploy-ai-agents-safely", response_class=HTMLResponse)
def serve_blog_how_to_deploy_ai_agents_safely():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-deploy-ai-agents-safely.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-enforce-least-privilege-ai-agents", response_class=HTMLResponse)
def serve_blog_how_to_enforce_least_privilege_ai_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-enforce-least-privilege-ai-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-limit-ai-agent-capabilities", response_class=HTMLResponse)
def serve_blog_how_to_limit_ai_agent_capabilities():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-limit-ai-agent-capabilities.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-monitor-ai-agent-actions", response_class=HTMLResponse)
def serve_blog_how_to_monitor_ai_agent_actions():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-monitor-ai-agent-actions.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-prevent-ai-agent-data-deletion", response_class=HTMLResponse)
def serve_blog_how_to_prevent_ai_agent_data_deletion():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-prevent-ai-agent-data-deletion.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-prevent-ai-agent-sensitive-data-access", response_class=HTMLResponse)
def serve_blog_how_to_prevent_ai_agent_sensitive_data_access():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-prevent-ai-agent-sensitive-data-access.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-prevent-prompt-injection-ai-agents", response_class=HTMLResponse)
def serve_blog_how_to_prevent_prompt_injection_ai_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-prevent-prompt-injection-ai-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-roll-back-ai-agent-damage", response_class=HTMLResponse)
def serve_blog_how_to_roll_back_ai_agent_damage():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-roll-back-ai-agent-damage.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-secure-langchain-agents", response_class=HTMLResponse)
def serve_blog_how_to_secure_langchain_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-secure-langchain-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-secure-autogpt-agents", response_class=HTMLResponse)
def serve_blog_how_to_secure_autogpt_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-secure-autogpt-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-secure-crewai-agents", response_class=HTMLResponse)
def serve_blog_how_to_secure_crewai_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-secure-crewai-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-secure-langgraph-agents", response_class=HTMLResponse)
def serve_blog_how_to_secure_langgraph_agents():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-secure-langgraph-agents.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-secure-openai-assistants", response_class=HTMLResponse)
def serve_blog_how_to_secure_openai_assistants():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-secure-openai-assistants.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/blog/how-to-test-ai-agent-security", response_class=HTMLResponse)
def serve_blog_how_to_test_ai_agent_security():
    p = os.path.join(os.path.dirname(__file__), "blog_how-to-test-ai-agent-security.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

@app.get("/download", response_class=HTMLResponse)
def serve_download():
    p = os.path.join(os.path.dirname(__file__), "download.html")
    return HTMLResponse(content=open(p).read()) if os.path.exists(p) else HTMLResponse("Not found", 404)

# ─── Stripe Billing ───────────────────────────────────────────────────────────
PRICE_MAP = {
    "pro":        os.environ.get("STRIPE_PRICE_PRO",        "price_1TLEhERUosaN5vQcNkrKtxHq"),
    "team":       os.environ.get("STRIPE_PRICE_TEAM",       "price_1TLEhCRUosaN5vQcBRQAcQgw"),
    "business":   os.environ.get("STRIPE_PRICE_BUSINESS",   "price_1TLEhBRUosaN5vQcdHkvAcCk"),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE", "price_1TLEhDRUosaN5vQc8D5tLFLH"),
}

@app.post("/api/billing/checkout")
def create_checkout(request: Request, plan: str = Body(..., embed=True), org_id: str = Depends(get_org), db=Depends(get_db)):
    price_id = PRICE_MAP.get(plan)
    if not price_id:
        raise HTTPException(status_code=400, detail="Invalid plan")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url="https://app.vaultak.com?view=billing&success=1",
            cancel_url="https://app.vaultak.com?view=billing",
            metadata={"org_id": org_id},
        )
        return {"checkout_url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/billing/portal")
def billing_portal(org_id: str = Depends(get_org), db=Depends(get_db)):
    try:
        with db.cursor() as cur:
            cur.execute("SELECT stripe_customer_id FROM organizations WHERE id = %s", (org_id,))
            row = cur.fetchone()
        if not row or not row.get("stripe_customer_id"):
            raise HTTPException(status_code=404, detail="No billing account found")
        session = stripe.billing_portal.Session.create(
            customer=row["stripe_customer_id"],
            return_url="https://app.vaultak.com?view=billing",
        )
        return {"portal_url": session.url}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request, db=Depends(get_db)):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, secret)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")
    if event["type"] == "checkout.session.completed":
        s = event["data"]["object"]
        org_id = s.get("metadata", {}).get("org_id")
        customer_id = s.get("customer")
        subscription_id = s.get("subscription")
        if org_id:
            # Determine plan from line items metadata
            plan = "starter"
            price_id = None
            try:
                items = s.get("line_items", {}).get("data", [])
                if items:
                    price_id = items[0]["price"]["id"]
                else:
                    # Fall back to metadata
                    price_id = s.get("metadata", {}).get("price_id")
                if price_id:
                    plan = {v: k for k, v in PRICE_MAP.items()}.get(price_id, "starter")
            except Exception:
                pass
            with db.cursor() as cur:
                cur.execute("""UPDATE organizations
                               SET stripe_customer_id=%s, stripe_subscription_id=%s, plan=%s
                               WHERE id=%s""",
                            (customer_id, subscription_id, plan, org_id))
            db.commit()
    elif event["type"] in ("customer.subscription.updated", "customer.subscription.deleted"):
        sub = event["data"]["object"]
        status = sub.get("status")
        customer_id = sub.get("customer")
        plan = "starter"
        if status == "active":
            price_id = sub["items"]["data"][0]["price"]["id"] if sub.get("items") else None
            plan = {v: k for k, v in PRICE_MAP.items()}.get(price_id, "starter")
        with db.cursor() as cur:
            cur.execute("UPDATE organizations SET plan=%s WHERE stripe_customer_id=%s", (plan, customer_id))
        db.commit()
    return {"received": True}

# ─── Claude MCP Connector ─────────────────────────────────────────────────────
MCP_TOOLS = [
    {"name":"get_agents","description":"List all AI agents monitored by Vaultak, including status and risk scores.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"get_alerts","description":"Get active unacknowledged security alerts from Vaultak.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"get_risk_summary","description":"Get risk distribution and key security metrics from your Vaultak dashboard.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"acknowledge_alert","description":"Acknowledge a security alert by ID.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"alert_id":{"type":"string"}},"required":["api_key","alert_id"]}},
    {"name":"pause_agent","description":"Pause an AI agent to stop it from executing further actions.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"agent_id":{"type":"string"}},"required":["api_key","agent_id"]}},
    {"name":"resume_agent","description":"Resume a paused AI agent.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"agent_id":{"type":"string"}},"required":["api_key","agent_id"]}},
]

def mcp_handle_tool(name: str, inputs: dict, db):
    api_key = inputs.get("api_key", "")
    if not api_key.startswith("vtk_"):
        return {"error": "Invalid API key"}
    with db.cursor() as cur:
        cur.execute("SELECT org_id FROM api_keys WHERE key_value = %s", (api_key,))
        row = cur.fetchone()
    if not row:
        return {"error": "API key not found"}
    org_id = str(row["org_id"])

    if name == "get_agents":
        with db.cursor() as cur:
            cur.execute("SELECT agent_id, name, paused, avg_risk_score, updated_at FROM agents WHERE org_id = %s", (org_id,))
            agents = cur.fetchall()
        return {"agents": [{"id": a["agent_id"], "name": a["name"], "status": "paused" if a["paused"] else "active", "avg_risk_score": round(float(a["avg_risk_score"] or 0), 2), "last_seen": str(a["updated_at"])} for a in agents], "total": len(agents)}

    elif name == "get_alerts":
        with db.cursor() as cur:
            cur.execute("SELECT id, message, level, agent_id, created_at FROM alerts WHERE org_id = %s AND acknowledged = false ORDER BY created_at DESC LIMIT 20", (org_id,))
            alerts = cur.fetchall()
        return {"alerts": [{"id": str(a["id"]), "message": a["message"], "severity": a["level"], "agent_id": a["agent_id"], "created_at": str(a["created_at"])} for a in alerts], "total": len(alerts)}

    elif name == "get_risk_summary":
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE flagged) as flagged, COUNT(*) FILTER (WHERE risk_score >= 0.75) as critical, COUNT(*) FILTER (WHERE risk_score >= 0.5 AND risk_score < 0.75) as high, COUNT(*) FILTER (WHERE risk_score >= 0.25 AND risk_score < 0.5) as medium, COUNT(*) FILTER (WHERE risk_score < 0.25) as low FROM actions WHERE org_id = %s", (org_id,))
            s = cur.fetchone()
        return {"total_actions": s["total"], "flagged_actions": s["flagged"], "risk_distribution": {"critical": s["critical"], "high": s["high"], "medium": s["medium"], "low": s["low"]}}

    elif name == "acknowledge_alert":
        alert_id = inputs.get("alert_id")
        with db.cursor() as cur:
            cur.execute("UPDATE alerts SET acknowledged = true WHERE id = %s AND org_id = %s", (alert_id, org_id))
        db.commit()
        return {"acknowledged": True, "alert_id": alert_id}

    elif name == "pause_agent":
        agent_id = inputs.get("agent_id")
        with db.cursor() as cur:
            cur.execute("UPDATE agents SET paused = true WHERE agent_id = %s AND org_id = %s", (agent_id, org_id))
        db.commit()
        return {"paused": True, "agent_id": agent_id}

    elif name == "resume_agent":
        agent_id = inputs.get("agent_id")
        with db.cursor() as cur:
            cur.execute("UPDATE agents SET paused = false WHERE agent_id = %s AND org_id = %s", (agent_id, org_id))
        db.commit()
        return {"resumed": True, "agent_id": agent_id}

    return {"error": f"Unknown tool: {name}"}

@app.get("/mcp")
def mcp_info():
    return {"name": "vaultak", "version": "1.0.0", "description": "Runtime security for AI agents — monitor, control and secure your AI agents.", "tools": MCP_TOOLS}

@app.post("/mcp")
async def mcp_endpoint(request: Request, db=Depends(get_db)):
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
    elif method == "tools/call":
        name = params.get("name")
        inputs = params.get("arguments", {})
        result = mcp_handle_tool(name, inputs, db)
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}}
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


# ─── Claude MCP Connector ─────────────────────────────────────────────────────
MCP_TOOLS = [
    {"name":"get_agents","description":"List all AI agents monitored by Vaultak, including status and risk scores.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"get_alerts","description":"Get active unacknowledged security alerts from Vaultak.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"get_risk_summary","description":"Get risk distribution and key security metrics from your Vaultak dashboard.","input_schema":{"type":"object","properties":{"api_key":{"type":"string","description":"Your Vaultak API key (starts with vtk_)"}},"required":["api_key"]}},
    {"name":"acknowledge_alert","description":"Acknowledge a security alert by ID.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"alert_id":{"type":"string"}},"required":["api_key","alert_id"]}},
    {"name":"pause_agent","description":"Pause an AI agent to stop it from executing further actions.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"agent_id":{"type":"string"}},"required":["api_key","agent_id"]}},
    {"name":"resume_agent","description":"Resume a paused AI agent.","input_schema":{"type":"object","properties":{"api_key":{"type":"string"},"agent_id":{"type":"string"}},"required":["api_key","agent_id"]}},
]

def mcp_handle_tool(name, inputs, db):
    api_key = inputs.get("api_key", "")
    if not api_key.startswith("vtk_"):
        return {"error": "Invalid API key"}
    with db.cursor() as cur:
        cur.execute("SELECT org_id FROM api_keys WHERE key_value = %s", (api_key,))
        row = cur.fetchone()
    if not row:
        return {"error": "API key not found"}
    org_id = str(row["org_id"])
    if name == "get_agents":
        with db.cursor() as cur:
            cur.execute("SELECT agent_id, name, paused, avg_risk_score, updated_at FROM agents WHERE org_id = %s", (org_id,))
            agents = cur.fetchall()
        return {"agents": [{"id": a["agent_id"], "name": a["name"], "status": "paused" if a["paused"] else "active", "avg_risk_score": round(float(a["avg_risk_score"] or 0), 2), "last_seen": str(a["updated_at"])} for a in agents], "total": len(agents)}
    elif name == "get_alerts":
        with db.cursor() as cur:
            cur.execute("SELECT id, message, level, agent_id, created_at FROM alerts WHERE org_id = %s AND acknowledged = false ORDER BY created_at DESC LIMIT 20", (org_id,))
            alerts = cur.fetchall()
        return {"alerts": [{"id": str(a["id"]), "message": a["message"], "severity": a["level"], "agent_id": a["agent_id"], "created_at": str(a["created_at"])} for a in alerts], "total": len(alerts)}
    elif name == "get_risk_summary":
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE flagged) as flagged, COUNT(*) FILTER (WHERE risk_score >= 0.75) as critical, COUNT(*) FILTER (WHERE risk_score >= 0.5 AND risk_score < 0.75) as high, COUNT(*) FILTER (WHERE risk_score >= 0.25 AND risk_score < 0.5) as medium, COUNT(*) FILTER (WHERE risk_score < 0.25) as low FROM actions WHERE org_id = %s", (org_id,))
            s = cur.fetchone()
        return {"total_actions": s["total"], "flagged_actions": s["flagged"], "risk_distribution": {"critical": s["critical"], "high": s["high"], "medium": s["medium"], "low": s["low"]}}
    elif name == "acknowledge_alert":
        alert_id = inputs.get("alert_id")
        with db.cursor() as cur:
            cur.execute("UPDATE alerts SET acknowledged = true WHERE id = %s AND org_id = %s", (alert_id, org_id))
        db.commit()
        return {"acknowledged": True, "alert_id": alert_id}
    elif name == "pause_agent":
        agent_id = inputs.get("agent_id")
        with db.cursor() as cur:
            cur.execute("UPDATE agents SET paused = true WHERE agent_id = %s AND org_id = %s", (agent_id, org_id))
        db.commit()
        return {"paused": True, "agent_id": agent_id}
    elif name == "resume_agent":
        agent_id = inputs.get("agent_id")
        with db.cursor() as cur:
            cur.execute("UPDATE agents SET paused = false WHERE agent_id = %s AND org_id = %s", (agent_id, org_id))
        db.commit()
        return {"resumed": True, "agent_id": agent_id}
    return {"error": f"Unknown tool: {name}"}

@app.get("/mcp")
def mcp_info():
    return {"name": "vaultak", "version": "1.0.0", "description": "Runtime security for AI agents.", "tools": MCP_TOOLS}

@app.post("/mcp")
async def mcp_endpoint(request: Request, db=Depends(get_db)):
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
    elif method == "tools/call":
        name = params.get("name")
        inputs = params.get("arguments", {})
        result = mcp_handle_tool(name, inputs, db)
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}}
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
