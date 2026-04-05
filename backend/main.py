import os, json, uuid, hashlib, secrets
from typing import Any, Dict, List, Optional
import psycopg
import psycopg.extras
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Vaultak API", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin-change-me")

def get_db():
    conn = psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = psycopg.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS organizations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS api_keys (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, key_hash TEXT UNIQUE NOT NULL, key_prefix TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), last_used TIMESTAMPTZ)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS agents (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, agent_id TEXT NOT NULL, name TEXT, kill_switch_mode TEXT DEFAULT 'alert', paused BOOLEAN DEFAULT FALSE, terminated BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(org_id, agent_id))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS actions (id BIGSERIAL PRIMARY KEY, org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, agent_id TEXT NOT NULL, session_id TEXT, action_type TEXT, resource TEXT, payload JSONB, risk_score REAL, flagged BOOLEAN DEFAULT FALSE, flag_reason TEXT, kill_switch_mode TEXT, rolled_back BOOLEAN DEFAULT FALSE, timestamp TIMESTAMPTZ DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS alerts (id BIGSERIAL PRIMARY KEY, org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, agent_id TEXT, action_id BIGINT, level TEXT, message TEXT, acknowledged BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW())""")
    conn.commit()
    cur.close()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def get_org(x_api_key: Optional[str] = Header(None), db=Depends(get_db)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    key_hash = hash_key(x_api_key)
    cur = db.cursor()
    cur.execute("UPDATE api_keys SET last_used = NOW() WHERE key_hash = %s RETURNING org_id", (key_hash,))
    row = cur.fetchone()
    db.commit()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return str(row["org_id"])

def require_admin(x_admin_key: Optional[str] = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required")

class OrgCreate(BaseModel):
    name: str
    slug: str

class ActionLog(BaseModel):
    agent_id: str
    agent_name: Optional[str] = None
    session_id: Optional[str] = None
    action_type: Optional[str] = None
    resource: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    risk_score: Optional[float] = 0.0
    flagged: Optional[bool] = False
    flag_reason: Optional[str] = None
    kill_switch_mode: Optional[str] = "alert"
    rolled_back: Optional[bool] = False

class AgentUpdate(BaseModel):
    paused: Optional[bool] = None
    kill_switch_mode: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}

@app.post("/admin/orgs")
def create_org(body: OrgCreate, db=Depends(get_db), _=Depends(require_admin)):
    cur = db.cursor()
    cur.execute("INSERT INTO organizations (name, slug) VALUES (%s, %s) RETURNING id, name, slug, created_at", (body.name, body.slug))
    org = dict(cur.fetchone())
    db.commit()
    return org

@app.get("/admin/orgs")
def list_orgs(db=Depends(get_db), _=Depends(require_admin)):
    cur = db.cursor()
    cur.execute("SELECT * FROM organizations ORDER BY created_at DESC")
    return [dict(r) for r in cur.fetchall()]

@app.post("/admin/orgs/{org_id}/keys")
def create_api_key(org_id: str, name: str = "default", db=Depends(get_db), _=Depends(require_admin)):
    raw_key = f"vtk_{secrets.token_urlsafe(32)}"
    key_hash = hash_key(raw_key)
    key_prefix = raw_key[:12]
    cur = db.cursor()
    cur.execute("INSERT INTO api_keys (org_id, key_hash, key_prefix, name) VALUES (%s, %s, %s, %s) RETURNING id", (org_id, key_hash, key_prefix, name))
    db.commit()
    return {"api_key": raw_key, "prefix": key_prefix, "warning": "Save this key — it won't be shown again"}

@app.post("/api/actions")
def log_action(body: ActionLog, org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("INSERT INTO agents (org_id, agent_id, name, kill_switch_mode) VALUES (%s, %s, %s, %s) ON CONFLICT (org_id, agent_id) DO UPDATE SET name = EXCLUDED.name, updated_at = NOW()", (org_id, body.agent_id, body.agent_name or body.agent_id, body.kill_switch_mode))
    cur.execute("INSERT INTO actions (org_id, agent_id, session_id, action_type, resource, payload, risk_score, flagged, flag_reason, kill_switch_mode, rolled_back) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id", (org_id, body.agent_id, body.session_id, body.action_type, body.resource, json.dumps(body.payload or {}), body.risk_score, body.flagged, body.flag_reason, body.kill_switch_mode, body.rolled_back))
    action_id = cur.fetchone()["id"]
    if body.flagged:
        level = "critical" if (body.risk_score or 0) >= 0.75 else "high" if (body.risk_score or 0) >= 0.5 else "medium"
        cur.execute("INSERT INTO alerts (org_id, agent_id, action_id, level, message) VALUES (%s, %s, %s, %s, %s)", (org_id, body.agent_id, action_id, level, f"{body.action_type or 'Action'} on {body.resource or 'unknown'} — risk {body.risk_score:.2f}"))
    db.commit()
    return {"logged": True, "action_id": action_id}

@app.get("/api/actions")
def get_actions(limit: int = 50, org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM actions WHERE org_id = %s ORDER BY timestamp DESC LIMIT %s", (org_id, limit))
    return [dict(r) for r in cur.fetchall()]

@app.get("/api/agents")
def get_agents(org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("""SELECT a.*, COUNT(ac.id) as total_actions, COUNT(ac.id) FILTER (WHERE ac.flagged) as flagged_actions, MAX(ac.timestamp) as last_seen, AVG(ac.risk_score) as avg_risk_score FROM agents a LEFT JOIN actions ac ON ac.agent_id = a.agent_id AND ac.org_id = a.org_id WHERE a.org_id = %s GROUP BY a.id ORDER BY a.created_at DESC""", (org_id,))
    return [dict(r) for r in cur.fetchall()]

@app.patch("/api/agents/{agent_id}")
def update_agent(agent_id: str, body: AgentUpdate, org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
    if body.paused is not None:
        cur.execute("UPDATE agents SET paused = %s, updated_at = NOW() WHERE org_id = %s AND agent_id = %s", (body.paused, org_id, agent_id))
    if body.kill_switch_mode is not None:
        cur.execute("UPDATE agents SET kill_switch_mode = %s, updated_at = NOW() WHERE org_id = %s AND agent_id = %s", (body.kill_switch_mode, org_id, agent_id))
    db.commit()
    return {"updated": True}

@app.get("/api/alerts")
def get_alerts(acknowledged: Optional[bool] = None, org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
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
    cur = db.cursor()
    cur.execute("UPDATE alerts SET acknowledged = TRUE WHERE id = %s AND org_id = %s", (alert_id, org_id))
    db.commit()
    return {"acknowledged": True}

@app.get("/api/stats")
def get_stats(org_id: str = Depends(get_org), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) as c FROM agents WHERE org_id = %s", (org_id,))
    total_agents = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM agents WHERE org_id = %s AND paused = TRUE", (org_id,))
    paused_agents = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM actions WHERE org_id = %s", (org_id,))
    total_actions = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM actions WHERE org_id = %s AND flagged = TRUE", (org_id,))
    flagged_actions = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM alerts WHERE org_id = %s AND acknowledged = FALSE", (org_id,))
    active_alerts = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) FILTER (WHERE risk_score >= 0.75) as critical, COUNT(*) FILTER (WHERE risk_score >= 0.5 AND risk_score < 0.75) as high, COUNT(*) FILTER (WHERE risk_score >= 0.25 AND risk_score < 0.5) as medium, COUNT(*) FILTER (WHERE risk_score < 0.25) as low FROM actions WHERE org_id = %s", (org_id,))
    dist = dict(cur.fetchone())
    return {"total_agents": total_agents, "paused_agents": paused_agents, "total_actions": total_actions, "flagged_actions": flagged_actions, "active_alerts": active_alerts, "risk_distribution": {k: (v or 0) for k, v in dist.items()}}
