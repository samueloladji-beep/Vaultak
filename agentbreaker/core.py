import json
import logging
import threading
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Deque, Dict, Generator, List, Optional
import urllib.request

from .exceptions import AgentPausedError, AgentTerminatedError, BehaviorViolationError
from .models import ActionLog, ActionType, AgentConfig, AlertLevel, BehaviorProfile, KillSwitchMode
from .scorer import score_action, score_to_alert_level
from .rollback import FileSnapshot

logger = logging.getLogger("vaultak")

# Default thresholds (0-100 scale)
DEFAULT_ALERT_THRESHOLD = 30
DEFAULT_PAUSE_THRESHOLD = 60
DEFAULT_ROLLBACK_THRESHOLD = 85


class VaultakMonitor:
    """
    Active monitor instance created by vt.monitor().
    Handles auto-interception and enforcement.
    """

    def __init__(
        self,
        agent_id: str,
        api_key: str,
        api_endpoint: str,
        alert_threshold: int,
        pause_threshold: int,
        rollback_threshold: int,
        allowed_resources: Optional[List[str]],
        blocked_resources: List[str],
        max_actions_per_minute: int,
    ):
        self.agent_id = agent_id
        self._api_key = api_key
        self._api_endpoint = api_endpoint
        self._alert_threshold = alert_threshold
        self._pause_threshold = pause_threshold
        self._rollback_threshold = rollback_threshold
        self._allowed_resources = allowed_resources
        self._blocked_resources = blocked_resources
        self._max_actions_per_minute = max_actions_per_minute
        self._session_id = str(uuid.uuid4())
        self._action_history: Deque[ActionLog] = deque(maxlen=1000)
        self._action_times: Deque[datetime] = deque(maxlen=1000)
        self._file_snapshot = FileSnapshot()
        self._paused = False
        self._lock = threading.Lock()

    def _register_file_snapshot(self, path: str, content: bytes):
        self._file_snapshot._snapshots[path] = content

    def _register_db_snapshot(self, dsn: str, sql: str, conn):
        """Store db connection for rollback via transaction."""
        if not hasattr(self, "_db_connections"):
            self._db_connections = {}
        key = id(conn)
        if key not in self._db_connections:
            self._db_connections[key] = {"conn": conn, "dsn": dsn, "sqls": []}
        self._db_connections[key]["sqls"].append(sql)

    def _intercept(self, action_type: str, resource: str, payload: dict) -> str:
        """
        Called by interceptors for every action.
        Returns: "ALLOW", "BLOCK", "PAUSE", "ROLLBACK"
        """
        if self._paused:
            return "BLOCK"

        # Rate limiting
        now = datetime.utcnow()
        with self._lock:
            recent = [t for t in self._action_times if (now - t).total_seconds() < 60]
            if len(recent) >= self._max_actions_per_minute:
                self._send_action(action_type, resource, payload, score=90, decision="BLOCK")
                return "BLOCK"

        # Policy checks
        if self._blocked_resources:
            import fnmatch
            for pattern in self._blocked_resources:
                if fnmatch.fnmatch(resource, pattern) or pattern in resource:
                    self._send_action(action_type, resource, payload, score=95, decision="BLOCK")
                    return "BLOCK"

        if self._allowed_resources:
            import fnmatch
            allowed = any(
                fnmatch.fnmatch(resource, p) or resource.startswith(p.rstrip("*"))
                for p in self._allowed_resources
            )
            if not allowed:
                self._send_action(action_type, resource, payload, score=80, decision="BLOCK")
                return "BLOCK"

        # Risk scoring
        score = self._compute_score(action_type, resource)

        # Determine response
        if score >= self._rollback_threshold:
            self._send_action(action_type, resource, payload, score=score, decision="ROLLBACK")
            self._execute_rollback()
            self._paused = True
            raise AgentPausedError(
                agent_id=self.agent_id,
                reason=f"Risk score {score} exceeded rollback threshold {self._rollback_threshold}. State restored."
            )
        elif score >= self._pause_threshold:
            self._send_action(action_type, resource, payload, score=score, decision="PAUSE")
            self._paused = True
            raise AgentPausedError(
                agent_id=self.agent_id,
                reason=f"Risk score {score} exceeded pause threshold {self._pause_threshold}. Awaiting review."
            )
        elif score >= self._alert_threshold:
            self._send_action(action_type, resource, payload, score=score, decision="ALERT")
        else:
            self._send_action(action_type, resource, payload, score=score, decision="ALLOW")

        with self._lock:
            self._action_times.append(now)

        return "ALLOW"

    def _compute_score(self, action_type: str, resource: str) -> int:
        """Simple risk scoring on 0-100 scale."""
        score = 0

        # Action type risk
        action_scores = {
            "file_write": 40, "file_read": 10, "delete": 75,
            "api_call": 35, "execute": 60, "database_write": 50,
            "database_read": 15, "custom": 30,
        }
        score += action_scores.get(action_type, 30)

        # Resource sensitivity
        sensitive_patterns = ["prod", "production", "secret", ".env", "password", "key", "token", "credential"]
        if any(p in resource.lower() for p in sensitive_patterns):
            score += 30

        # Cap at 100
        return min(score, 100)

    def _execute_rollback(self):
        """Restore all snapshotted files and rollback database transactions."""
        # File rollback
        results = self._file_snapshot.restore_all()
        for path, success in results:
            if success:
                logger.info(f"Rolled back file: {path}")
            else:
                logger.error(f"File rollback failed: {path}")

        # Database rollback
        if hasattr(self, "_db_connections"):
            for key, info in self._db_connections.items():
                try:
                    conn = info["conn"]
                    conn.rollback()
                    logger.info(f"Rolled back database transaction: {info['dsn']}")
                except Exception as e:
                    logger.error(f"Database rollback failed: {e}")
            self._db_connections.clear()

    def _send_action(self, action_type: str, resource: str, payload: dict, score: int, decision: str):
        """Send action to backend asynchronously."""
        data = json.dumps({
            "agent_id": self.agent_id,
            "session_id": self._session_id,
            "action_type": action_type,
            "resource": resource,
            "payload": payload,
            "risk_score": score / 100.0,
            "decision": decision,
            "timestamp": datetime.utcnow().isoformat(),
        }).encode("utf-8")

        def _post():
            try:
                req = urllib.request.Request(
                    f"{self._api_endpoint}/api/actions",
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self._api_key,
                    },
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception as e:
                logger.debug(f"Backend send failed: {e}")

        threading.Thread(target=_post, daemon=True).start()

    def approve(self):
        """Resume a paused agent."""
        self._paused = False
        logger.info(f"Agent {self.agent_id} approved and resumed.")

    def get_audit_trail(self):
        return list(self._action_history)
