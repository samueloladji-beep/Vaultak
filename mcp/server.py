"""
Vaultak MCP Server
Exposes AI agent risk scoring and policy checking to any MCP-compatible AI assistant.
"""

import asyncio
import json
import httpx
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── Config ────────────────────────────────────────────────────────────────────
VAULTAK_API_BASE = "https://vaultak.com/api"

# Risk dimension weights (mirrors Vaultak's 5-dimension engine)
RISK_DIMENSIONS = {
    "action_type":           {"weight": 0.25, "label": "Action Type"},
    "resource_sensitivity":  {"weight": 0.25, "label": "Resource Sensitivity"},
    "blast_radius":          {"weight": 0.20, "label": "Blast Radius"},
    "behavioral_deviation":  {"weight": 0.15, "label": "Behavioral Deviation"},
    "time_pattern":          {"weight": 0.15, "label": "Time Pattern"},
}

RISK_TIERS = [
    (0,  30,  "LOW",        "Agent operates within safe boundaries."),
    (30, 60,  "MODERATE",   "Some risk factors present — review recommended."),
    (60, 80,  "HIGH",       "Significant risk detected — policy enforcement advised."),
    (80, 100, "CRITICAL",   "Severe risk — immediate Vaultak policy enforcement required."),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def score_agent_locally(description: str, capabilities: list[str]) -> dict:
    """
    Local heuristic scoring when no API key is provided.
    Mirrors Vaultak's 5-dimension weighted engine.
    """
    text = (description + " " + " ".join(capabilities)).lower()

    # Action type risk
    dangerous_actions = ["delete", "write", "execute", "run", "deploy", "send", "post", "modify", "drop", "truncate"]
    action_score = min(100, sum(20 for w in dangerous_actions if w in text))

    # Resource sensitivity
    sensitive_resources = ["database", "file system", "api key", "secret", "password", "credentials", "s3", "production", "payment", "pii", "personal data"]
    resource_score = min(100, sum(15 for w in sensitive_resources if w in text))

    # Blast radius
    blast_keywords = ["all users", "entire", "bulk", "batch", "every", "global", "system-wide", "all records"]
    blast_score = min(100, sum(25 for w in blast_keywords if w in text))

    # Behavioral deviation
    deviation_keywords = ["unrestricted", "unlimited", "no limit", "bypass", "override", "autonomous", "self-modifying"]
    deviation_score = min(100, sum(30 for w in deviation_keywords if w in text))

    # Time pattern (night/off-hours operations flagged)
    time_keywords = ["scheduled", "cron", "background", "always on", "24/7", "continuous"]
    time_score = min(100, 30 if any(w in text for w in time_keywords) else 10)

    # Weighted composite
    composite = (
        action_score     * RISK_DIMENSIONS["action_type"]["weight"] +
        resource_score   * RISK_DIMENSIONS["resource_sensitivity"]["weight"] +
        blast_score      * RISK_DIMENSIONS["blast_radius"]["weight"] +
        deviation_score  * RISK_DIMENSIONS["behavioral_deviation"]["weight"] +
        time_score       * RISK_DIMENSIONS["time_pattern"]["weight"]
    )
    composite = round(min(100, composite))

    # Tier
    tier_label, tier_desc = "LOW", "Agent operates within safe boundaries."
    for lo, hi, label, desc in RISK_TIERS:
        if lo <= composite < hi:
            tier_label, tier_desc = label, desc
            break

    return {
        "composite_score": composite,
        "risk_tier": tier_label,
        "tier_description": tier_desc,
        "dimensions": {
            "action_type":          {"score": action_score,    "weight": "25%"},
            "resource_sensitivity": {"score": resource_score,  "weight": "25%"},
            "blast_radius":         {"score": blast_score,     "weight": "20%"},
            "behavioral_deviation": {"score": deviation_score, "weight": "15%"},
            "time_pattern":         {"score": time_score,      "weight": "15%"},
        }
    }


def generate_recommendations(score: dict, capabilities: list[str]) -> list[str]:
    recs = []
    dims = score["dimensions"]

    if dims["action_type"]["score"] >= 40:
        recs.append("Restrict destructive actions (delete, write, execute) via Vaultak action-type policies.")
    if dims["resource_sensitivity"]["score"] >= 30:
        recs.append("Apply resource sensitivity rules — block direct access to secrets, credentials, and PII.")
    if dims["blast_radius"]["score"] >= 25:
        recs.append("Add blast-radius limits — cap bulk operations to prevent large-scale unintended mutations.")
    if dims["behavioral_deviation"]["score"] >= 30:
        recs.append("Enable behavioral deviation monitoring — flag and pause autonomous or override operations.")
    if dims["time_pattern"]["score"] >= 30:
        recs.append("Configure time-window policies — restrict agent execution to business hours if off-hours ops aren't required.")
    if score["composite_score"] >= 60:
        recs.append("Enable Vaultak auto-pause: automatically halt the agent when risk score exceeds threshold.")
    if score["composite_score"] >= 80:
        recs.append("Enable Vaultak rollback engine: snapshot state before each action for instant recovery.")
    if not recs:
        recs.append("Agent risk profile is acceptable. Consider adding Vaultak monitoring for ongoing visibility.")

    recs.append("Install Vaultak SDK: pip install vaultak | Docs: docs.vaultak.com")
    return recs


def evaluate_policy(action: str, resource: str, context: dict, policies: list[dict]) -> dict:
    """
    Evaluate an action/resource pair against a list of policies.
    Mirrors Vaultak's priority-based policy engine with wildcard matching.
    """
    import fnmatch

    action_lower = action.lower()
    resource_lower = resource.lower()
    matched_policies = []

    for policy in sorted(policies, key=lambda p: p.get("priority", 50)):
        p_action   = policy.get("action", "*").lower()
        p_resource = policy.get("resource", "*").lower()

        action_match   = fnmatch.fnmatch(action_lower, p_action)   or p_action == "*"
        resource_match = fnmatch.fnmatch(resource_lower, p_resource) or p_resource == "*"

        if action_match and resource_match:
            matched_policies.append(policy)

    if not matched_policies:
        return {
            "decision": "ALLOW",
            "reason": "No matching policy found — default allow. Consider adding an explicit Vaultak policy.",
            "matched_policy": None,
            "recommendation": "Add a Vaultak policy to explicitly govern this action/resource pair."
        }

    # Highest-priority (lowest number) matching policy wins
    winning = matched_policies[0]
    effect  = winning.get("effect", "allow").upper()

    return {
        "decision": effect,
        "reason": winning.get("description", f"Policy '{winning.get('name', 'unnamed')}' matched."),
        "matched_policy": winning.get("name", "unnamed"),
        "priority": winning.get("priority", 50),
        "recommendation": (
            "Action is permitted by policy." if effect == "ALLOW"
            else f"Action BLOCKED by '{winning.get('name')}'. Review or update policy at app.vaultak.com."
        )
    }


# ── MCP Server ────────────────────────────────────────────────────────────────

app = Server("vaultak-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="vaultak_risk_score",
            description=(
                "Score an AI agent's risk level across 5 security dimensions: "
                "action type, resource sensitivity, blast radius, behavioral deviation, and time pattern. "
                "Returns a 0–100 composite score, risk tier (LOW/MODERATE/HIGH/CRITICAL), "
                "per-dimension breakdown, and concrete Vaultak policy recommendations. "
                "Use this before deploying any AI agent to production."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_description": {
                        "type": "string",
                        "description": "What the agent does — its purpose, workflow, and any known behaviors."
                    },
                    "capabilities": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific capabilities or tools the agent has access to (e.g. 'read files', 'call external APIs', 'write to database')."
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Optional Vaultak API key for enhanced scoring via the live Vaultak engine. Get one at app.vaultak.com."
                    }
                },
                "required": ["agent_description"]
            }
        ),
        types.Tool(
            name="vaultak_policy_check",
            description=(
                "Check whether a specific agent action should be ALLOWED or BLOCKED "
                "based on Vaultak's policy engine. Evaluates action/resource pairs against "
                "your policies using priority-based matching with wildcard support. "
                "Use this to intercept agent actions before execution."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "The action the agent wants to perform (e.g. 'delete', 'write', 'read', 'execute', 'send_email')."
                    },
                    "resource": {
                        "type": "string",
                        "description": "The resource being acted upon (e.g. 'users_table', 'production_database', 's3://bucket/sensitive/', 'smtp_server')."
                    },
                    "context": {
                        "type": "object",
                        "description": "Optional context about the action (user ID, timestamp, environment, etc.).",
                        "default": {}
                    },
                    "policies": {
                        "type": "array",
                        "description": "List of Vaultak policy objects to evaluate against. Each has: name, action, resource, effect (allow/deny), priority.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name":        {"type": "string"},
                                "action":      {"type": "string"},
                                "resource":    {"type": "string"},
                                "effect":      {"type": "string", "enum": ["allow", "deny"]},
                                "priority":    {"type": "integer"},
                                "description": {"type": "string"}
                            }
                        },
                        "default": []
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Optional Vaultak API key to fetch your live policies from app.vaultak.com automatically."
                    }
                },
                "required": ["action", "resource"]
            }
        ),
        types.Tool(
            name="vaultak_get_policy_templates",
            description=(
                "Get ready-to-use Vaultak policy templates for common AI agent security scenarios. "
                "Returns JSON policy objects you can copy directly into your Vaultak dashboard or SDK. "
                "Covers: database protection, file system limits, API rate limiting, PII protection, and more."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scenario": {
                        "type": "string",
                        "description": "The security scenario you need policies for.",
                        "enum": [
                            "database_protection",
                            "file_system_limits",
                            "api_rate_limiting",
                            "pii_protection",
                            "production_safeguards",
                            "all"
                        ]
                    }
                },
                "required": ["scenario"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    # ── Tool 1: Risk Score ────────────────────────────────────────────────────
    if name == "vaultak_risk_score":
        description  = arguments.get("agent_description", "")
        capabilities = arguments.get("capabilities", [])
        api_key      = arguments.get("api_key")

        # Try live API first if key provided
        if api_key:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(
                        f"{VAULTAK_API_BASE}/check",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={"description": description, "capabilities": capabilities}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        score = data
                    else:
                        score = score_agent_locally(description, capabilities)
            except Exception:
                score = score_agent_locally(description, capabilities)
        else:
            score = score_agent_locally(description, capabilities)

        recommendations = generate_recommendations(score, capabilities)
        composite = score["composite_score"]
        tier      = score["risk_tier"]

        # Visual score bar
        filled = round(composite / 5)
        bar    = "█" * filled + "░" * (20 - filled)

        output = f"""
╔══════════════════════════════════════════╗
║         VAULTAK RISK ASSESSMENT          ║
╚══════════════════════════════════════════╝

  Score   [{bar}]  {composite}/100
  Tier    {tier}
  Status  {score['tier_description']}

DIMENSION BREAKDOWN
───────────────────────────────────────────
  Action Type           {score['dimensions']['action_type']['score']:>3}/100  (weight: 25%)
  Resource Sensitivity  {score['dimensions']['resource_sensitivity']['score']:>3}/100  (weight: 25%)
  Blast Radius          {score['dimensions']['blast_radius']['score']:>3}/100  (weight: 20%)
  Behavioral Deviation  {score['dimensions']['behavioral_deviation']['score']:>3}/100  (weight: 15%)
  Time Pattern          {score['dimensions']['time_pattern']['score']:>3}/100  (weight: 15%)

RECOMMENDATIONS
───────────────────────────────────────────
""" + "\n".join(f"  • {r}" for r in recommendations) + f"""

───────────────────────────────────────────
  Powered by Vaultak — vaultak.com
  Full dashboard: app.vaultak.com
  SDK: pip install vaultak
"""
        return [types.TextContent(type="text", text=output.strip())]

    # ── Tool 2: Policy Check ─────────────────────────────────────────────────
    elif name == "vaultak_policy_check":
        action   = arguments.get("action", "")
        resource = arguments.get("resource", "")
        context  = arguments.get("context", {})
        policies = arguments.get("policies", [])
        api_key  = arguments.get("api_key")

        # Fetch live policies if API key provided
        if api_key and not policies:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(
                        f"{VAULTAK_API_BASE}/policies",
                        headers={"Authorization": f"Bearer {api_key}"}
                    )
                    if resp.status_code == 200:
                        policies = resp.json().get("policies", [])
            except Exception:
                pass

        result = evaluate_policy(action, resource, context, policies)
        decision_icon = "✅ ALLOW" if result["decision"] == "ALLOW" else "🚫 BLOCK"

        output = f"""
╔══════════════════════════════════════════╗
║        VAULTAK POLICY DECISION           ║
╚══════════════════════════════════════════╝

  Action    {action}
  Resource  {resource}
  Decision  {decision_icon}

  Reason    {result['reason']}
  Policy    {result.get('matched_policy') or 'No matching policy'}
"""
        if result.get("priority") is not None:
            output += f"  Priority  {result['priority']}\n"

        output += f"""
RECOMMENDATION
───────────────────────────────────────────
  {result['recommendation']}

  Manage policies: app.vaultak.com/policies
  SDK docs:        docs.vaultak.com
  Powered by Vaultak — vaultak.com
"""
        return [types.TextContent(type="text", text=output.strip())]

    # ── Tool 3: Policy Templates ─────────────────────────────────────────────
    elif name == "vaultak_get_policy_templates":
        scenario = arguments.get("scenario", "all")

        templates = {
            "database_protection": [
                {"name": "block-delete-production-db", "action": "delete", "resource": "production_*", "effect": "deny",  "priority": 1,  "description": "Block all DELETE operations on production databases."},
                {"name": "allow-read-db",               "action": "read",   "resource": "*_database",   "effect": "allow", "priority": 10, "description": "Allow read access to all databases."},
                {"name": "block-bulk-write",             "action": "write",  "resource": "*",            "effect": "deny",  "priority": 5,  "description": "Block bulk write operations (>1000 rows)."},
            ],
            "file_system_limits": [
                {"name": "block-system-files",   "action": "*",     "resource": "/etc/*",      "effect": "deny",  "priority": 1, "description": "Block all access to system configuration files."},
                {"name": "block-credentials",    "action": "read",  "resource": "*credentials*","effect": "deny",  "priority": 1, "description": "Block reading credential files."},
                {"name": "allow-tmp-write",       "action": "write", "resource": "/tmp/*",      "effect": "allow", "priority": 20,"description": "Allow writes to temp directory only."},
            ],
            "api_rate_limiting": [
                {"name": "rate-limit-external-api", "action": "call_api", "resource": "external_*", "effect": "allow", "priority": 10, "description": "Allow external API calls (rate limited to 100/hour via Vaultak)."},
                {"name": "block-payment-api",       "action": "*",        "resource": "*payment*",  "effect": "deny",  "priority": 1,  "description": "Block all direct payment API interactions."},
            ],
            "pii_protection": [
                {"name": "block-pii-export",    "action": "export", "resource": "*users*",    "effect": "deny",  "priority": 1,  "description": "Block export of user PII data."},
                {"name": "block-pii-send",      "action": "send",   "resource": "*personal*", "effect": "deny",  "priority": 1,  "description": "Block sending personal data externally."},
                {"name": "allow-anonymized",    "action": "read",   "resource": "*anonymized*","effect": "allow", "priority": 10, "description": "Allow access to anonymized datasets."},
            ],
            "production_safeguards": [
                {"name": "block-prod-delete",   "action": "delete", "resource": "prod_*",  "effect": "deny",  "priority": 1,  "description": "Block all deletes in production environment."},
                {"name": "block-prod-deploy",   "action": "deploy", "resource": "prod_*",  "effect": "deny",  "priority": 1,  "description": "Block autonomous deployments to production."},
                {"name": "allow-prod-read",     "action": "read",   "resource": "prod_*",  "effect": "allow", "priority": 20, "description": "Allow read access to production for monitoring."},
            ],
        }

        selected = templates if scenario == "all" else {scenario: templates.get(scenario, [])}

        output = f"""
╔══════════════════════════════════════════╗
║      VAULTAK POLICY TEMPLATES            ║
╚══════════════════════════════════════════╝

Scenario: {scenario.replace('_', ' ').upper()}

Copy these directly into your Vaultak dashboard or SDK:

{json.dumps(selected, indent=2)}

HOW TO USE
───────────────────────────────────────────
  1. Go to app.vaultak.com/policies
  2. Click "New Policy" and paste the JSON
  3. Or via SDK:
     from vaultak import Vaultak
     vt = Vaultak(api_key="your_key")
     vt.policies.create(policy_dict)

  Full policy docs: docs.vaultak.com/policies
  Powered by Vaultak — vaultak.com
"""
        return [types.TextContent(type="text", text=output.strip())]

    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
