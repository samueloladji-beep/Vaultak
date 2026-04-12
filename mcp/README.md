# Vaultak MCP Server

> AI agent runtime security — directly inside Claude, Cursor, and any MCP-compatible assistant.

## What it does

The Vaultak MCP server gives any AI assistant three security superpowers:

| Tool | What it does |
|------|-------------|
| `vaultak_risk_score` | Score any AI agent 0–100 across 5 security dimensions |
| `vaultak_policy_check` | Check if an action should be ALLOWED or BLOCKED |
| `vaultak_get_policy_templates` | Get ready-to-use security policy templates |

## Install

```bash
pip install vaultak-mcp
```

Or run directly:

```bash
uvx vaultak-mcp
```

## Connect to Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vaultak": {
      "command": "uvx",
      "args": ["vaultak-mcp"],
      "env": {
        "VAULTAK_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

Get your API key at [app.vaultak.com](https://app.vaultak.com).

## Connect to Cursor

In Cursor Settings → MCP → Add Server:

```json
{
  "name": "vaultak",
  "command": "uvx vaultak-mcp"
}
```

## Example usage

Once connected, ask your AI assistant:

> "Score the risk level of my agent that has access to the production database and can send emails"

> "Should my agent be allowed to delete records from the users table?"

> "Give me policy templates for protecting PII in my AI agent"

## Tools reference

### `vaultak_risk_score`

```
agent_description  (required)  What the agent does
capabilities       (optional)  List of tools/capabilities
api_key            (optional)  Vaultak API key for live scoring
```

Returns composite score (0–100), risk tier, per-dimension breakdown, and recommendations.

### `vaultak_policy_check`

```
action    (required)  The action being attempted (delete, write, execute...)
resource  (required)  The resource being acted on (production_db, /etc/secrets...)
policies  (optional)  Policy list to evaluate against
api_key   (optional)  Fetch your live policies automatically
```

Returns ALLOW or BLOCK decision with matched policy and recommendation.

### `vaultak_get_policy_templates`

```
scenario  (required)  One of: database_protection | file_system_limits |
                               api_rate_limiting | pii_protection |
                               production_safeguards | all
```

Returns ready-to-use policy JSON for your Vaultak dashboard.

## Links

- Dashboard: [app.vaultak.com](https://app.vaultak.com)
- Docs: [docs.vaultak.com](https://docs.vaultak.com)
- SDK: `pip install vaultak`
- Site: [vaultak.com](https://vaultak.com)
