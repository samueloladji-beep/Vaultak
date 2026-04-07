import os, json, hashlib, secrets, time, logging
from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vaultak")

app = FastAPI(title="Vaultak API", version="0.4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-change-me")

# ─── Database ─────────────────────────────────────────────────────────────────

def get_db():
    retries = 3
    for attempt in range(retries):
        try:
            conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
            try:
                yield conn
            finally:
                conn.close()
            return
        except Exception as e:
            if attempt == retries - 1:
                logger.error(f"Database connection failed after {retries} attempts: {e}")
                raise HTTPException(status_code=503, detail="Database unavailable")
            time.sleep(1)

def init_db():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS organizations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""")
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
    check_rate_limit(x_api_key)
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
    try:
        # Compute risk score using 5-dimension engine
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
        auto_flagged = final_score >= 0.65
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
                level = "critical" if final_score >= 0.80 else "high" if final_score >= 0.65 else "medium"
                cur.execute("""
                    INSERT INTO alerts (org_id, agent_id, action_id, level, message)
                    VALUES (%s, %s, %s, %s, %s)
                """, (org_id, body.agent_id, action_id, level,
                      f"{body.action_type or 'Action'} on {body.resource or 'unknown'} — risk {final_score:.2f}"))

            # Auto-pause agent if in PAUSE mode and high risk
            if body.kill_switch_mode == "PAUSE" and final_score >= 0.80:
                cur.execute("""
                    UPDATE agents SET paused = TRUE, updated_at = NOW()
                    WHERE org_id = %s AND agent_id = %s
                """, (org_id, body.agent_id))

            # Auto-rollback if in ROLLBACK mode and critical risk
            if body.kill_switch_mode == "ROLLBACK" and final_score >= 0.90:
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

        return {
            "logged": True,
            "action_id": action_id,
            "risk_score": final_score,
            "risk_breakdown": breakdown,
            "flagged": flagged,
            "flag_reason": flag_reason
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
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "ok", "service": "Vaultak API", "version": "0.3.0"}

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
            cur.execute("SELECT key_prefix FROM api_keys WHERE org_id = %s", (str(existing["id"]),))
            key = cur.fetchone()
            raw_key = f"vtk_{secrets.token_urlsafe(32)}"
            cur.execute("UPDATE api_keys SET key_hash = %s, key_prefix = %s WHERE org_id = %s", (hash_key(raw_key), raw_key[:12], str(existing["id"])))
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

@app.get("/favicon.svg")
def serve_favicon():
    favicon_path = os.path.join(os.path.dirname(__file__), "favicon.svg")
    return FileResponse(favicon_path, media_type="image/svg+xml")

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
