"""
Vaultak Shadow AI Detection Module
Detects when data is being sent to unsanctioned AI services
without IT or security team approval.

What it detects:
  - Direct API calls to unsanctioned AI providers
  - Browser-based AI tool usage via DNS/network monitoring
  - AI service tokens/keys being used in outbound requests
  - Data leakage to consumer AI services (ChatGPT, Claude.ai, etc.)

Two detection modes:
  1. Network monitor — watches outbound connections (Linux/Mac)
  2. Proxy mode — sits as an HTTP proxy, inspects all traffic
"""

import os
import re
import json
import time
import socket
import logging
import threading
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

logger = logging.getLogger("vaultak-shadow-ai")

VERSION = "0.1.0"

# ── Sanctioned vs unsanctioned AI services ────────────────────────────────────

# Services that are commonly unsanctioned in enterprise environments
SHADOW_AI_HOSTS = {
    # Consumer ChatGPT
    "chat.openai.com":          {"service": "ChatGPT",          "risk": "high",   "category": "consumer_llm"},
    "chatgpt.com":              {"service": "ChatGPT",          "risk": "high",   "category": "consumer_llm"},
    # Claude.ai consumer
    "claude.ai":                {"service": "Claude.ai",         "risk": "high",   "category": "consumer_llm"},
    # Google Gemini consumer
    "gemini.google.com":        {"service": "Google Gemini",     "risk": "high",   "category": "consumer_llm"},
    "bard.google.com":          {"service": "Google Bard",       "risk": "high",   "category": "consumer_llm"},
    # Microsoft Copilot consumer
    "copilot.microsoft.com":    {"service": "MS Copilot",        "risk": "medium", "category": "consumer_llm"},
    "bing.com":                 {"service": "Bing AI",           "risk": "medium", "category": "consumer_llm"},
    # Meta AI
    "meta.ai":                  {"service": "Meta AI",           "risk": "high",   "category": "consumer_llm"},
    # Perplexity
    "perplexity.ai":            {"service": "Perplexity",        "risk": "medium", "category": "consumer_llm"},
    # You.com
    "you.com":                  {"service": "You.com AI",        "risk": "medium", "category": "consumer_llm"},
    # Character AI
    "character.ai":             {"service": "Character.AI",      "risk": "high",   "category": "consumer_llm"},
    "beta.character.ai":        {"service": "Character.AI",      "risk": "high",   "category": "consumer_llm"},
    # Poe
    "poe.com":                  {"service": "Poe",               "risk": "high",   "category": "consumer_llm"},
    # Replicate
    "replicate.com":            {"service": "Replicate",         "risk": "medium", "category": "model_api"},
    # Together AI
    "api.together.xyz":         {"service": "Together AI",       "risk": "medium", "category": "model_api"},
    # Cohere consumer
    "dashboard.cohere.com":     {"service": "Cohere Dashboard",  "risk": "medium", "category": "consumer_llm"},
    # Hugging Face inference
    "huggingface.co":           {"service": "HuggingFace",       "risk": "low",    "category": "model_api"},
    # AI writing tools
    "jasper.ai":                {"service": "Jasper AI",         "risk": "high",   "category": "ai_writing"},
    "copy.ai":                  {"service": "Copy.ai",           "risk": "high",   "category": "ai_writing"},
    "writesonic.com":           {"service": "Writesonic",        "risk": "high",   "category": "ai_writing"},
    "grammarly.com":            {"service": "Grammarly",         "risk": "low",    "category": "ai_writing"},
    # AI coding (potentially unsanctioned)
    "cursor.sh":                {"service": "Cursor",            "risk": "medium", "category": "ai_coding"},
    "codeium.com":              {"service": "Codeium",           "risk": "medium", "category": "ai_coding"},
    "tabnine.com":              {"service": "Tabnine",           "risk": "low",    "category": "ai_coding"},
}

# Sanctioned AI API hosts (approved for production use)
SANCTIONED_API_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.groq.com",
}

# Patterns that indicate AI API usage in HTTP requests
AI_API_PATTERNS = [
    re.compile(r'openai\.com/v\d+/(chat/)?completions', re.I),
    re.compile(r'anthropic\.com/v\d+/messages', re.I),
    re.compile(r'Authorization:\s*Bearer\s+sk-[A-Za-z0-9\-_]+', re.I),
    re.compile(r'"model"\s*:\s*"(gpt-|claude-|gemini-|llama-|mistral)', re.I),
    re.compile(r'"messages"\s*:\s*\[', re.I),
    re.compile(r'"prompt"\s*:\s*"[^"]{50,}"', re.I),
]


@dataclass
class ShadowAIEvent:
    timestamp:   str
    host:        str
    service:     str
    risk:        str
    category:    str
    source:      str       # "network" or "proxy"
    process:     str = ""
    user:        str = ""
    url:         str = ""
    data_size:   int = 0
    sanctioned:  bool = False

    def to_dict(self):
        return {
            "timestamp":  self.timestamp,
            "host":       self.host,
            "service":    self.service,
            "risk":       self.risk,
            "category":   self.category,
            "source":     self.source,
            "process":    self.process,
            "sanctioned": self.sanctioned,
        }


# ── DNS / Network monitor ─────────────────────────────────────────────────────

class NetworkMonitor:
    """
    Monitors outbound network connections for AI service usage.
    Works by periodically scanning active connections via psutil.
    """

    def __init__(self, on_detection, sanctioned_hosts: set = None):
        self.on_detection    = on_detection
        self.sanctioned      = sanctioned_hosts or SANCTIONED_API_HOSTS
        self.seen            = set()
        self.running         = False
        self._thread         = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True)
        self._thread.start()
        logger.info("Shadow AI network monitor started")

    def stop(self):
        self.running = False

    def _run(self):
        try:
            import psutil
            HAS_PSUTIL = True
        except ImportError:
            logger.warning("psutil not available — network monitoring disabled")
            return

        while self.running:
            try:
                for conn in psutil.net_connections(kind="tcp"):
                    if not conn.raddr or not conn.raddr.ip:
                        continue
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if port not in (80, 443, 8080, 8443):
                        continue

                    key = (ip, port)
                    if key in self.seen:
                        continue
                    self.seen.add(key)

                    # Reverse DNS lookup
                    try:
                        hostname = socket.gethostbyaddr(ip)[0].lower()
                    except Exception:
                        hostname = ip

                    self._check_host(hostname, conn)

            except Exception as e:
                logger.debug(f"Network scan error: {e}")

            time.sleep(2.0)

    def _check_host(self, hostname: str, conn):
        # Check exact match
        for shadow_host, info in SHADOW_AI_HOSTS.items():
            if shadow_host in hostname or hostname in shadow_host:
                sanctioned = any(s in hostname for s in self.sanctioned)
                event = ShadowAIEvent(
                    timestamp  = datetime.now(timezone.utc).isoformat(),
                    host       = hostname,
                    service    = info["service"],
                    risk       = info["risk"],
                    category   = info["category"],
                    source     = "network",
                    sanctioned = sanctioned,
                )
                self.on_detection(event)
                break

    def scan_once(self) -> list:
        """Single scan — returns list of detected shadow AI connections."""
        events = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="tcp"):
                if not conn.raddr or not conn.raddr.ip:
                    continue
                try:
                    hostname = socket.gethostbyaddr(conn.raddr.ip)[0].lower()
                except Exception:
                    hostname = conn.raddr.ip
                for shadow_host, info in SHADOW_AI_HOSTS.items():
                    if shadow_host in hostname:
                        events.append(ShadowAIEvent(
                            timestamp = datetime.now(timezone.utc).isoformat(),
                            host      = hostname,
                            service   = info["service"],
                            risk      = info["risk"],
                            category  = info["category"],
                            source    = "network",
                        ))
                        break
        except ImportError:
            pass
        return events


# ── Request inspector ─────────────────────────────────────────────────────────

class RequestInspector:
    """
    Inspects HTTP request/response content for AI API patterns.
    Used in proxy mode or when requests can be intercepted.
    """

    def inspect_request(self, host: str, path: str,
                        headers: dict, body: bytes) -> Optional[ShadowAIEvent]:
        host_lower = host.lower()

        # Check host against shadow AI list
        for shadow_host, info in SHADOW_AI_HOSTS.items():
            if shadow_host in host_lower:
                # Check if it looks like an AI API call
                is_api = (
                    any(p.search(path) for p in AI_API_PATTERNS) or
                    any(p.search(body.decode("utf-8", errors="ignore"))
                        for p in AI_API_PATTERNS)
                )
                return ShadowAIEvent(
                    timestamp  = datetime.now(timezone.utc).isoformat(),
                    host       = host,
                    service    = info["service"],
                    risk       = "critical" if is_api else info["risk"],
                    category   = info["category"],
                    source     = "proxy",
                    url        = f"https://{host}{path}",
                    data_size  = len(body),
                )

        # Check body for API patterns even if host is not in our list
        body_str = body.decode("utf-8", errors="ignore")
        for pattern in AI_API_PATTERNS:
            if pattern.search(body_str):
                return ShadowAIEvent(
                    timestamp = datetime.now(timezone.utc).isoformat(),
                    host      = host,
                    service   = "Unknown AI Service",
                    risk      = "high",
                    category  = "unknown_ai",
                    source    = "proxy",
                    url       = f"https://{host}{path}",
                    data_size = len(body),
                )
        return None


# ── Shadow AI detector ────────────────────────────────────────────────────────

class VaultakShadowAI:
    """
    Main Shadow AI Detection engine.

    Usage:
        detector = VaultakShadowAI(api_key="vtk_...")
        detector.start()

        # Or scan once
        events = detector.scan()
        for event in events:
            print(f"Shadow AI detected: {event.service} ({event.risk})")
    """

    def __init__(
        self,
        api_key:           str = None,
        sanctioned_hosts:  set = None,
        on_detection:      callable = None,
        alert_on_risk:     str = "medium",
    ):
        self.api_key          = api_key
        self.sanctioned       = sanctioned_hosts or SANCTIONED_API_HOSTS
        self.on_detection     = on_detection or self._default_handler
        self.alert_on_risk    = alert_on_risk
        self.events:          list = []
        self._lock            = threading.Lock()
        self.net_monitor      = NetworkMonitor(
            on_detection    = self._handle_event,
            sanctioned_hosts = self.sanctioned,
        )

    def start(self):
        """Start continuous background monitoring."""
        self.net_monitor.start()
        logger.info(f"Vaultak Shadow AI Detection active")
        logger.info(f"Monitoring {len(SHADOW_AI_HOSTS)} known AI services")

    def stop(self):
        self.net_monitor.stop()

    def scan(self) -> list:
        """Single scan — returns detected shadow AI usage."""
        return self.net_monitor.scan_once()

    def _handle_event(self, event: ShadowAIEvent):
        with self._lock:
            self.events.append(event)
        self.on_detection(event)
        self._report_to_backend(event)

    def _default_handler(self, event: ShadowAIEvent):
        risk_map = {"critical": "\033[91m", "high": "\033[91m",
                    "medium": "\033[93m", "low": "\033[92m"}
        color = risk_map.get(event.risk, "\033[97m")
        print(f"\n  {color}[SHADOW AI DETECTED]{'\033[0m'}")
        print(f"  Service:  {event.service}")
        print(f"  Host:     {event.host}")
        print(f"  Risk:     {event.risk.upper()}")
        print(f"  Category: {event.category}")
        print(f"  Source:   {event.source}")
        if not event.sanctioned:
            print(f"  Status:   UNSANCTIONED")

    def _report_to_backend(self, event: ShadowAIEvent):
        if not self.api_key:
            return
        try:
            import requests
            requests.post(
                "https://vaultak.com/api/actions",
                headers={"x-api-key": self.api_key},
                json={
                    "agent_id":    "shadow-ai-monitor",
                    "action_type": "shadow_ai_detected",
                    "resource":    event.host,
                    "risk_score":  {"critical": 0.95, "high": 0.80,
                                    "medium": 0.60, "low": 0.35}.get(event.risk, 0.5),
                    "metadata":    event.to_dict(),
                    "flagged":     not event.sanctioned,
                },
                timeout=3,
            )
        except Exception:
            pass

    def get_report(self) -> dict:
        with self._lock:
            events = list(self.events)
        by_risk     = {}
        by_service  = {}
        by_category = {}
        for e in events:
            by_risk[e.risk]          = by_risk.get(e.risk, 0) + 1
            by_service[e.service]    = by_service.get(e.service, 0) + 1
            by_category[e.category]  = by_category.get(e.category, 0) + 1
        return {
            "total_detections": len(events),
            "unsanctioned":     sum(1 for e in events if not e.sanctioned),
            "by_risk":          by_risk,
            "by_service":       by_service,
            "by_category":      by_category,
            "events":           [e.to_dict() for e in events[-50:]],
        }

    @classmethod
    def list_monitored_services(cls) -> list:
        return [
            {
                "host":     host,
                "service":  info["service"],
                "risk":     info["risk"],
                "category": info["category"],
            }
            for host, info in sorted(
                SHADOW_AI_HOSTS.items(), key=lambda x: x[1]["risk"])
        ]


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="vaultak-shadow-ai",
        description="Vaultak Shadow AI Detection"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="One-time scan for shadow AI connections")
    p_scan.add_argument("--api-key", default=None)
    p_scan.add_argument("--json", action="store_true")

    p_watch = sub.add_parser("watch", help="Continuous monitoring")
    p_watch.add_argument("--api-key", default=None)

    p_list = sub.add_parser("list", help="List all monitored AI services")
    p_list.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.cmd == "list":
        services = VaultakShadowAI.list_monitored_services()
        if hasattr(args, "json") and args.json:
            print(json.dumps(services, indent=2))
        else:
            print(f"\nVaultak Shadow AI — {len(services)} monitored services\n")
            for s in services:
                risk_color = "\033[91m" if s["risk"] in ("high","critical") else "\033[93m"
                print(f"  {risk_color}[{s['risk'].upper():<8}]\033[0m  "
                      f"{s['service']:<25}  {s['host']}")
            print()
        return

    detector = VaultakShadowAI(api_key=getattr(args, "api_key", None))

    if args.cmd == "scan":
        print("Scanning for shadow AI connections...")
        events = detector.scan()
        if not events:
            print("No shadow AI connections detected.")
        else:
            for e in events:
                print(f"\n[{e.risk.upper()}] {e.service} — {e.host}")
        return

    if args.cmd == "watch":
        print(f"Vaultak Shadow AI Detection — watching {len(SHADOW_AI_HOSTS)} services")
        print("Press Ctrl+C to stop.\n")
        detector.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            detector.stop()
            report = detector.get_report()
            print(f"\nDetections: {report['total_detections']}")
            print(f"Unsanctioned: {report['unsanctioned']}")


if __name__ == "__main__":
    main()
