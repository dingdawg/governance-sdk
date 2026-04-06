# dingdawg-governance

**AI governance for Claude Code, Cursor, and any MCP-compatible agent.** Govern actions. Audit trails. Compliance checks. One command to install.

```bash
npx dingdawg-governance
```

```bash
# Claude Code
claude mcp add dingdawg-governance npx dingdawg-governance

# Cursor / any MCP client
# Add to your MCP config:
# { "command": "npx", "args": ["dingdawg-governance"] }
```

---

## What it does

Every AI agent action — sending emails, modifying data, making API calls — runs without a receipt. You don't know what was approved, what was blocked, or why.

`dingdawg-governance` adds a governance layer that:

- **Governs actions** before they execute — evaluates risk, detects policy violations, generates a signed receipt
- **Audits everything** — searchable trail of every governed action by agent, time range, or receipt ID
- **Checks compliance** — scores your AI system against EU AI Act, Colorado SB 205, NIST AI RMF, and ISO 42001

Works **locally with no API key** for all three tools. Add an API key for cloud storage, team audit trails, and unlimited compliance checks.

---

## Install

```bash
npm install -g dingdawg-governance
```

Or run directly without installing:

```bash
npx dingdawg-governance
```

Requires Node.js 18+.

---

## Add to Claude Code

```bash
claude mcp add dingdawg-governance npx dingdawg-governance
```

Verify it loaded:

```bash
claude mcp list
```

---

## Add to Cursor

Add to your `~/.cursor/mcp.json` (or project-level `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "dingdawg-governance": {
      "command": "npx",
      "args": ["dingdawg-governance"]
    }
  }
}
```

With an API key:

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

---

## Tools

### `govern_action`

Govern any agent action before it executes. Returns a receipt.

```
govern_action(
  agent_id: "my-agent",
  action_type: "send_email",
  action_description: "Sending weekly report to 500 subscribers",
  target_resource: "email_server",
  risk_tier: "medium"
)
```

**Returns:**
```json
{
  "receipt_id": "gov_1x2y3z_ab12cd34",
  "decision": "allow",
  "risk_score": 10,
  "policy_violations": [],
  "recommended_controls": ["Validate message content before sending externally"],
  "governed": true
}
```

**Decisions:**
| Score | Decision | Meaning |
|-------|----------|---------|
| 0–39 | `allow` | Proceed — policy checks passed |
| 40–69 | `review` | Pause for human review |
| 70–100 | `deny` | Block — critical policy violation |

**Risk tiers:** `low` · `medium` · `high` · `critical`

**Policy checks run automatically:**
- Sensitive data access (PII, credentials, health records, payment data)
- Destructive operations (delete, drop, truncate, purge)
- Bulk/broadcast operations
- External communications
- High-stakes actions requiring human-in-the-loop

Receipts are stored locally at `~/.dingdawg/governance/receipts/`. With an API key, receipts sync to the cloud.

---

### `audit_trail`

Retrieve governance receipts.

```
# All receipts from the last 24 hours
audit_trail(time_range: "24h")

# All receipts for a specific agent
audit_trail(agent_id: "my-agent", time_range: "7d")

# Look up a specific receipt
audit_trail(receipt_id: "gov_1x2y3z_ab12cd34")
```

**Time ranges:** `1h` · `24h` · `7d` · `30d`

---

### `compliance_check`

Check your AI system against major governance frameworks. **Free: 10 checks per day** (no API key needed).

```
compliance_check(
  system_description: "A hiring recommendation system that screens resumes 
    and ranks candidates for employment decisions. Uses ML to score 
    applicants against job requirements. Includes human review for 
    final decisions and appeal mechanism for rejected candidates.",
  framework: "colorado_ai_act",
  deployment_stage: "production"
)
```

**Returns:**
```json
{
  "overall_compliance": 65,
  "compliance_level": "PARTIAL",
  "frameworks": [
    {
      "name": "Colorado AI Act (SB24-205)",
      "score": 65,
      "status": "PARTIAL",
      "requirements_met": [
        "Consequential decision identification (SB24-205 Sec. 3)",
        "Right to appeal/opt-out (SB24-205 Sec. 6)"
      ],
      "requirements_missing": [
        "Impact assessment required (SB24-205 Sec. 4)",
        "Consumer disclosure required (SB24-205 Sec. 5)"
      ]
    }
  ],
  "critical_gaps": ["Colorado: No impact assessment documented"],
  "checks_remaining": 9
}
```

**Frameworks supported:**
| Framework | Coverage |
|-----------|----------|
| `eu_ai_act` | Art. 6, 10, 11, 12, 13, 14 — risk classification, human oversight, transparency, data governance, logging |
| `colorado_ai_act` | SB24-205 Sec. 3–6 — consequential decisions, impact assessment, disclosure, appeal rights |
| `nist_ai_rmf` | GOVERN, MAP, MEASURE, MANAGE functions |
| `iso_42001` | Clauses 5–10 — policy, risk assessment, operations, performance, improvement |
| `all` | All four frameworks simultaneously |

Free tier: 10 checks/day. Resets every 24 hours. Unlimited with API key.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DINGDAWG_API_KEY` | *(none)* | API key for cloud storage + unlimited checks |
| `DINGDAWG_API_URL` | `https://api.dingdawg.com/v1` | Override API endpoint |

**Without an API key:** All three tools work locally. Receipts stored at `~/.dingdawg/governance/receipts/`. Compliance checks limited to 10/day.

**With an API key:** Receipts sync to the cloud. Audit trail searchable across team members. Unlimited compliance checks. Get a key at [dingdawg.com/developers](https://dingdawg.com/developers).

---

## Example: Govern a full agent workflow

```javascript
// In your agent — before any consequential action:

// 1. Govern the action
const receipt = await mcp.call("govern_action", {
  agent_id: "billing-agent",
  action_type: "make_purchase",
  action_description: "Purchasing $450 cloud credits for monthly infrastructure renewal",
  target_resource: "payment_api",
  risk_tier: "high"
});

// 2. Check the decision
if (receipt.decision === "deny") {
  throw new Error(`Action blocked: ${receipt.policy_violations[0].description}`);
}

if (receipt.decision === "review") {
  await notifyHuman(receipt.receipt_id);
  return;
}

// 3. Execute with receipt attached
await executePurchase({ receipt_id: receipt.receipt_id });
```

---

## Local storage

Receipts are stored at:
```
~/.dingdawg/governance/receipts/<receipt_id>.json
```

Each receipt is a complete JSON record:
```json
{
  "receipt_id": "gov_1x2y3z_ab12cd34",
  "timestamp": "2026-04-06T14:23:01Z",
  "agent_id": "billing-agent",
  "action_type": "make_purchase",
  "action_description": "...",
  "target_resource": "payment_api",
  "risk_tier": "high",
  "decision": "allow",
  "risk_score": 30,
  "policy_violations": [],
  "recommended_controls": [],
  "context": {}
}
```

---

## CO SB 205 compliance scanner

Also available — separate tool for Colorado AI Act self-assessment:

```bash
pip install dingdawg-compliance
python3 -m dingdawg_compliance scan
```

→ [github.com/dingdawg/dingdawg-compliance](https://github.com/dingdawg/dingdawg-compliance)

---

## License

MIT — free to use, fork, and contribute.

## Links

- [dingdawg.com/developers](https://dingdawg.com/developers) — API keys, cloud audit trail
- [dingdawg.com/compliance](https://dingdawg.com/compliance) — CO SB 205 gap report ($199)
- [npm: dingdawg-governance](https://www.npmjs.com/package/dingdawg-governance)
