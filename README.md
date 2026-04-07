# DingDawg Governance SDK — Universal governance layer for AI agents

[![npm version](https://img.shields.io/npm/v/dingdawg-governance)](https://www.npmjs.com/package/dingdawg-governance)
[![PyPI version](https://img.shields.io/pypi/v/dingdawg-loop)](https://pypi.org/project/dingdawg-loop/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Any agent. Any framework. Governed by default.**

---

## What it does

Every AI agent action — writing files, calling APIs, sending emails, modifying data — executes without a receipt. You don't know what ran, what was blocked, or why.

DingDawg Governance adds a pre-execution gate that:

- **Blocks policy violations before they execute** — fail-closed, not fail-open
- **Generates LNN causal traces** — interpretable reasoning chain for every decision
- **Issues IPFS audit proofs** — tamper-evident receipts pinned to distributed storage
- **Supports rollback** — every governed action carries enough context to reverse it
- **Assigns @handle identities** — agents get a governed identity (`@billing-agent`, `@hr-screener`) with a full action history tied to that handle

---

## Regulated niches

Built for frameworks where AI agent decisions carry legal weight:

| Industry | Regulation |
|----------|-----------|
| Healthcare | HIPAA — PHI access, treatment decision logging |
| Insurance / Fintech | State regulations, adverse action documentation |
| Employment | CO SB 205, EEOC — automated hiring decision audit |
| Legal | Chain-of-custody, privileged data access controls |
| Edtech | FERPA — student data access receipts |

---

## Install

```bash
npm install dingdawg-governance
```

```bash
pip install dingdawg-loop
```

---

## Quick start — Claude Code (MCP config)

Add to `~/.claude/mcp.json` or project-level `.mcp.json`:

```json
{
  "mcpServers": {
    "dingdawg-governance": {
      "command": "npx",
      "args": ["dingdawg-governance"],
      "env": {
        "DINGDAWG_API_KEY": "your-api-key"
      }
    }
  }
}
```

Without an API key, all tools work locally. Receipts stored at `~/.dingdawg/governance/receipts/`.

---

## Quick start — Python (scheduled governed agents)

```python
from dingdawg_loop import schedule_governed

@schedule_governed(
    agent_id="@data-sync-agent",
    cron="0 * * * *",
    risk_tier="medium"
)
def sync_records():
    # Your agent logic here
    pass
```

Two lines. Every execution is pre-checked, receipted, and fail-closed. If governance denies, the function does not run.

---

## MCP tools (6)

| Tool | What it does |
|------|-------------|
| `govern_action` | Pre-execution gate — evaluates risk, issues receipt, blocks on violation |
| `audit_trail` | Retrieve receipts by agent handle, time range, or receipt ID |
| `compliance_check` | Score against EU AI Act, CO SB 205, NIST AI RMF, ISO 42001 |
| `rollback_action` | Reverse a governed action using its receipt context |
| `register_agent` | Assign a governed @handle identity to an agent |
| `ipfs_proof` | Retrieve or pin IPFS audit proof for a receipt |

---

## Open-core model

| Layer | License | Where |
|-------|---------|-------|
| SDK core (govern, audit, compliance) | Apache 2.0 | This repo |
| LNN causal trace engine | Cloud only | [dingdawg.com/harness](https://dingdawg.com/harness) |
| IPFS proof pinning | Cloud only | [dingdawg.com/harness](https://dingdawg.com/harness) |
| Team audit trail + cross-agent history | Cloud only | [dingdawg.com](https://dingdawg.com) |
| Compliance report PDFs (certified) | Paid tier | [dingdawg.com/compliance](https://dingdawg.com/compliance) |

The core gate runs fully offline. Cloud unlocks team visibility, IPFS pinning, and certified compliance reports.

---

## Links

- [dingdawg.com](https://dingdawg.com) — platform, pricing, API keys
- [dingdawg.com/docs/integrations](https://dingdawg.com/docs/integrations) — CrewAI, LangGraph, Cursor, Claude Code
- [dingdawg.com/harness](https://dingdawg.com/harness) — LNN engine, IPFS proofs, advanced governance
- [dingdawg.com/compliance](https://dingdawg.com/compliance) — CO SB 205 gap report ($199)
