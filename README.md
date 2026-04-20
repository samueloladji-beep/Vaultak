# Vaultak

[![PyPI version](https://badge.fury.io/py/vaultak.svg)](https://pypi.org/project/vaultak)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Downloads](https://static.pepy.tech/badge/vaultak)](https://pepy.tech/project/vaultak)

**Runtime security and behavioral monitoring for AI agents.**

Vaultak is the control layer for AI agents in production. Monitor every action, enforce permission boundaries, score risk in real time, and automatically pause or roll back agents before damage is done.

No agent should touch your production systems without it.

---

## The Problem

AI agents are being deployed into production at scale — writing to databases, sending emails, executing code, processing payments. But there is no standard layer that monitors what they are doing, enforces policy, or stops them when something goes wrong.

A misconfigured agent today can cause real damage: deleted records, leaked PII, unauthorized transactions. Vaultak closes that gap.

---

## Products

| | Vaultak Core | Vaultak Sentry |
|---|---|---|
| **Type** | Python SDK | Desktop App |
| **Integration** | 2 lines of code | Zero code changes |
| **Language support** | Python | Any language |
| **Best for** | Developers | Security teams |
| **Install** | `pip install vaultak` | [Download](https://vaultak.com/download) |

---

## Install

```bash
pip install vaultak
```

Requires Python 3.8 or higher.

---

## Quick Start

```python
from vaultak import Vaultak

vt = Vaultak(api_key="vtk_...")

with vt.monitor("my-agent"):
    # your agent code here
    pass
```

That is all. Vaultak wraps your agent, monitors every action, scores behavioral risk in real time, and blocks or rolls back if a threshold is breached.

---

## Core Features

### Behavioral Risk Scoring
Every agent action is scored 0–10 in real time across five dimensions: action type, resource sensitivity, blast radius, frequency, and context deviation. Scores above your configured threshold trigger automatic intervention.

### Policy Enforcement
Define what your agent is and is not allowed to do. Block specific action types, restrict access to sensitive resources, or require human approval before high-risk operations execute.

```python
vt = Vaultak(
    api_key="vtk_...",
    policy={
        "block": ["delete", "drop_table", "send_external_email"],
        "require_approval": ["write_production_db"],
        "max_risk_score": 7.0
    }
)
```

### Automatic Rollback
When an agent breaches a risk threshold, Vaultak does not just alert — it rolls back. Actions are logged with full state context so recovery is clean and auditable.

### PII Masking
Sensitive data passing through your agent pipeline is automatically detected and masked before it reaches external services or logs.

```python
from vaultak import mask_pii

safe_output = mask_pii(agent_output)
# SSNs, emails, credit cards, phone numbers masked automatically
```

### MCP Gateway Scanning
All Model Context Protocol (MCP) tool calls are intercepted and scanned before execution. Malicious or out-of-policy tool use is blocked at the gateway level.

### SIEM Integrations
Push behavioral events and risk alerts directly to your existing security stack.

```python
vt = Vaultak(
    api_key="vtk_...",
    siem={
        "provider": "splunk",  # splunk | datadog | sentinel | slack | pagerduty
        "endpoint": "https://your-splunk-endpoint",
        "token": "your-token"
    }
)
```

---

## Red Team Testing

Vaultak ships with a built-in red team simulation engine covering 22 attack vectors — prompt injection, jailbreaks, data exfiltration attempts, privilege escalation, and more. Run it against your agent pipeline before deploying to production.

```python
from vaultak import RedTeam

rt = RedTeam(api_key="vtk_...")
results = rt.run(target_agent=my_agent, vectors="all")
print(results.summary())
```

---

## On-Premises Deployment

For teams that cannot send data to external services, Vaultak ships a fully self-contained Docker deployment.

```bash
git clone https://github.com/samueloladji-beep/Vaultak
cd onprem
docker-compose up
```

All monitoring, risk scoring, and policy enforcement runs locally. No data leaves your infrastructure.

---

## Vaultak Sentry

Sentry is a zero-code desktop daemon that monitors agent activity at the system level — no SDK integration required. Install it, connect it to your Vaultak dashboard, and get full behavioral visibility across every agent running on the machine.

**Download:** [vaultak.com/download](https://vaultak.com/download)

Supports macOS, Windows, and Linux.

---

## Dashboard

Every agent event, risk score, policy trigger, and rollback is visible in your Vaultak dashboard at [vaultak.com](https://vaultak.com). Real-time feed, historical audit log, and team-level access controls.

---

## Pricing

| Plan | Price | Best for |
|---|---|---|
| Starter | Free | Individual developers |
| Pro | $49/mo | Small teams |
| Team | $99/mo | Engineering teams |
| Business | $299/mo | Growing engineering orgs |
| Enterprise | Custom from $999/mo | Large-scale deployments |

[Start free](https://vaultak.com) — no credit card required.

---

## Documentation

Full documentation at [docs.vaultak.com](https://docs.vaultak.com)

- [Quickstart](https://docs.vaultak.com/quickstart)
- [SDK Reference](https://docs.vaultak.com/sdk)
- [Sentry Guide](https://docs.vaultak.com/sentry)
- [Policy Configuration](https://docs.vaultak.com/policies)
- [SIEM Integrations](https://docs.vaultak.com/integrations)

---

## Links

- Website: [vaultak.com](https://vaultak.com)
- Docs: [docs.vaultak.com](https://docs.vaultak.com)
- PyPI: [pypi.org/project/vaultak](https://pypi.org/project/vaultak)
- White Paper: [vaultak.com/whitepaper](https://vaultak.com/whitepaper)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
