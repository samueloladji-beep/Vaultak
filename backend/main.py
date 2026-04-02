from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime
import sqlite3, json, uuid, os

app = FastAPI(title="AgentBreaker API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DB_PATH = os.environ.get("DB_PATH", "agentbreaker.db")
API_KEY = os.environ.get("AGENTBREAKER_API_KEY", "dev-key-change-me")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY, name TEXT, kill_switch_mode TEXT DEFAULT 'alert', paused INTEGER DEFAULT 0, terminated INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT UNIQUE, agent_id TEXT, session_id TEXT, action_type TEXT, resource TEXT, payload TEXT, risk_score REAL, flagged INTEGER, flag_reason TEXT, rolled_back INTEGER, timestamp TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, action_id TEXT, level TEXT, message TEXT, acknowledged INTEGER DEFAULT 0, created_at TEXT)")
    conn.commit()
    conn.close()

init_db()

def verify_api_key(x_api_key: str = Header(default="")):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

class ActionPayload(BaseModel):
    agent_id: str
    action_id: Optional[str] = None
    session_id: Optional[str] = None
    action_type: str
    resource: str
    payload: Dict[str, Any] = {}
    risk_score: float = 0.0
    flagged: bool = False
    flag_reason: Optional[str] = None
    rolled_back: bool = False
    timestamp: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}

@app.get("/api/stats")
def get_stats(db=Depends(get_db), _=Depends(verify_api_key)):
    total_agents = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    total_actions = db.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
    flagged_actions = db.execute("SELECT COUNT(*) FROM actions WHERE flagged = 1").fetchone()[0]
    active_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
    return {"total_agents": total_agents, "total_actions": total_actions, "flagged_actions": flagged_actions, "active_alerts": active_alerts}

@app.post("/api/actions")
def ingest_action(body: ActionPayload, db=Depends(get_db), _=Depends(verify_api_key)):
    action_id = body.action_id or str(uuid.uuid4())
    timestamp = body.timestamp or datetime.utcnow().isoformat()
    existing = db.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (body.agent_id,)).fetchone()
    if not existing:
        now = datetime.utcnow().isoformat()
        db.execute("INSERT INTO agents (agent_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", (body.agent_id, body.agent_id, now, now))
    db.execute("INSERT OR IGNORE INTO actions (action_id, agent_id, session_id, action_type, resource, payload, risk_score, flagged, flag_reason, rolled_back, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (action_id, body.agent_id, body.session_id, body.action_type, body.resource, json.dumps(body.payload), body.risk_score, 1 if body.flagged else 0, body.flag_reason, 1 if body.rolled_back else 0, timestamp))
    if body.flagged:
        level = "critical" if body.risk_score >= 0.75 else "high" if body.risk_score >= 0.5 else "medium"
        db.execute("INSERT INTO alerts (agent_id, action_id, level, message, created_at) VALUES (?, ?, ?, ?, ?)", (body.agent_id, action_id, level, body.flag_reason or "Anomalous behavior detected", datetime.utcnow().isoformat()))
    db.commit()
    return {"action_id": action_id, "ingested": True}

@app.get("/api/agents")
def list_agents(db=Depends(get_db), _=Depends(verify_api_key)):
    rows = db.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/alerts")
def list_alerts(db=Depends(get_db), _=Depends(verify_api_key)):
    rows = db.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]

from fastapi.responses import FileResponse
import os

@app.get("/")
def landing():
    index_path = os.path.join(os.path.dirname(__file__), "..", "index.html")
    return FileResponse(index_path)
