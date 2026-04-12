from .exceptions import AgentPausedError, AgentTerminatedError, BehaviorViolationError
from .models import ActionType, KillSwitchMode, AlertLevel

__version__ = "0.6.1"

import os as _os


class Vaultak:
    """
    Vaultak runtime security SDK.

    Usage:
        from vaultak import Vaultak

        vt = Vaultak(api_key="vtk_...")

        with vt.monitor("my-agent"):
            agent.run()  # All file I/O, HTTP calls, subprocesses auto-monitored
    """

    def __init__(
        self,
        api_key: str = None,
        agent_id: str = "default",
        alert_threshold: int = 30,
        pause_threshold: int = 60,
        rollback_threshold: int = 85,
        allowed_resources=None,
        blocked_resources=None,
        max_actions_per_minute: int = 60,
        api_endpoint: str = "https://vaultak.com",
    ):
        self._api_key = api_key or _os.environ.get("VAULTAK_API_KEY", "")
        self._agent_id = agent_id
        self._alert_threshold = alert_threshold
        self._pause_threshold = pause_threshold
        self._rollback_threshold = rollback_threshold
        self._allowed_resources = allowed_resources
        self._blocked_resources = blocked_resources or []
        self._max_actions_per_minute = max_actions_per_minute
        self._api_endpoint = api_endpoint

    def monitor(self, agent_id: str = None):
        """
        Context manager that automatically monitors all agent actions.
        Auto-intercepts: file I/O, HTTP requests, subprocess calls.
        """
        from contextlib import contextmanager
        from .core import VaultakMonitor
        from .interceptor import install_all, uninstall_all

        @contextmanager
        def _monitor():
            aid = agent_id or self._agent_id
            m = VaultakMonitor(
                agent_id=aid,
                api_key=self._api_key,
                api_endpoint=self._api_endpoint,
                alert_threshold=self._alert_threshold,
                pause_threshold=self._pause_threshold,
                rollback_threshold=self._rollback_threshold,
                allowed_resources=self._allowed_resources,
                blocked_resources=self._blocked_resources,
                max_actions_per_minute=self._max_actions_per_minute,
            )
            install_all(m)
            try:
                yield m
            finally:
                uninstall_all()

        return _monitor()

    def check(self, action_type: str, resource: str, agent_id: str = None) -> dict:
        """
        Pre-execution risk check. Returns decision before action runs.

        Returns:
            {"allowed": bool, "score": int, "decision": str}
        """
        import urllib.request, json
        try:
            data = json.dumps({
                "agent_id": agent_id or self._agent_id,
                "action_type": action_type,
                "resource": resource,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self._api_endpoint}/api/check",
                data=data,
                headers={"Content-Type": "application/json", "x-api-key": self._api_key},
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=3)
            result = json.loads(resp.read())
            return {
                "allowed": result.get("decision") not in ("BLOCK", "ROLLBACK"),
                "score": result.get("risk_score", 0),
                "decision": result.get("decision", "ALLOW"),
            }
        except Exception:
            return {"allowed": True, "score": 0, "decision": "ALLOW"}

    def log_action(self, action_type: str, resource: str, agent_id: str = None, payload: dict = None):
        """Manually log a single action."""
        import json, threading, urllib.request, uuid
        from datetime import datetime
        data = json.dumps({
            "agent_id": agent_id or self._agent_id,
            "action_type": action_type,
            "resource": resource,
            "payload": payload or {},
            "session_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
        }).encode("utf-8")
        def _post():
            try:
                req = urllib.request.Request(
                    f"{self._api_endpoint}/api/actions",
                    data=data,
                    headers={"Content-Type": "application/json", "x-api-key": self._api_key},
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_post, daemon=True).start()


__all__ = [
    "Vaultak",
    "ActionType",
    "KillSwitchMode",
    "AlertLevel",
    "AgentPausedError",
    "AgentTerminatedError",
    "BehaviorViolationError",
]
