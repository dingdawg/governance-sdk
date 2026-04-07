/**
 * 01-basic-governance.js
 *
 * Shows: spawn dingdawg-governance as an MCP subprocess, send a govern_action
 * JSON-RPC call over stdin, and print the governance receipt.
 *
 * Regulated use case: FINTECH — governing a payment-transfer action before
 * it executes. The receipt is proof the action was reviewed by policy before
 * any money moved.
 *
 * Run:
 *   node examples/01-basic-governance.js
 *
 * No API key required — local policy engine runs offline.
 * Set DINGDAWG_API_KEY for cloud-tier policy evaluation.
 */

const { spawn } = require("child_process");

// ---------------------------------------------------------------------------
// Spawn the MCP server as a subprocess (same way Claude Code does it)
// ---------------------------------------------------------------------------

const server = spawn("npx", ["dingdawg-governance"], {
  stdio: ["pipe", "pipe", "pipe"],
  env: {
    ...process.env,
    // Optional: set DINGDAWG_API_KEY here for cloud-tier evaluation
    // DINGDAWG_API_KEY: "dg_live_...",
  },
});

let buffer = "";

server.stdout.on("data", (chunk) => {
  buffer += chunk.toString();

  // MCP responses are newline-delimited JSON
  const lines = buffer.split("\n");
  buffer = lines.pop(); // keep incomplete line

  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const msg = JSON.parse(line);

      // Response to our tools/call — print the receipt
      if (msg.id === 1 && msg.result) {
        const receipt = JSON.parse(msg.result.content[0].text);
        console.log("\n=== Governance Receipt ===");
        console.log(JSON.stringify(receipt, null, 2));

        console.log("\n=== Summary ===");
        console.log(`Decision : ${receipt.decision.toUpperCase()}`);
        console.log(`Risk Score: ${receipt.risk_score}/100`);
        console.log(`Receipt ID: ${receipt.receipt_id}`);
        console.log(`Violations: ${receipt.policy_violations.length}`);

        if (receipt.policy_violations.length > 0) {
          console.log("\nViolations flagged:");
          receipt.policy_violations.forEach((v) => {
            console.log(`  [${v.severity.toUpperCase()}] ${v.policy}: ${v.description}`);
          });
        }

        if (receipt.recommended_controls.length > 0) {
          console.log("\nRecommended controls:");
          receipt.recommended_controls.forEach((c) => console.log(`  • ${c}`));
        }

        server.kill();
        process.exit(0);
      }
    } catch {
      // Non-JSON line (e.g. server startup noise) — ignore
    }
  }
});

server.stderr.on("data", (chunk) => {
  // Server logs to stderr — suppress unless debugging
  if (process.env.DEBUG) process.stderr.write(chunk);
});

server.on("error", (err) => {
  console.error("Failed to start dingdawg-governance server:", err.message);
  console.error("Make sure it is installed: npm install dingdawg-governance");
  process.exit(1);
});

// ---------------------------------------------------------------------------
// Wait briefly for the server to initialise, then send a govern_action call
// ---------------------------------------------------------------------------

setTimeout(() => {
  // MCP JSON-RPC 2.0 tools/call request
  const request = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "govern_action",
      arguments: {
        agent_id: "@payment-agent",
        action_type: "transfer_funds",
        action_description:
          "Transfer $4,200 from checking account 0042 to external account 9917 " +
          "for invoice INV-2024-0891. Initiated by automated billing workflow.",
        target_resource: "payment_api",
        risk_tier: "high",
        context: {
          invoice_id: "INV-2024-0891",
          amount_usd: "4200",
          initiated_by: "billing-workflow-v2",
          environment: "production",
        },
      },
    },
  };

  server.stdin.write(JSON.stringify(request) + "\n");
}, 800);

// Timeout safety — kill if server never responds
setTimeout(() => {
  console.error("Timeout: server did not respond within 10s");
  server.kill();
  process.exit(1);
}, 10000);

/*
 * Expected output:
 *
 * === Governance Receipt ===
 * {
 *   "success": true,
 *   "receipt_id": "gov_m3x9a2b1_f4e8c3d2",
 *   "timestamp": "2026-04-06T14:23:11.042Z",
 *   "agent_id": "@payment-agent",
 *   "action_type": "transfer_funds",
 *   "target_resource": "payment_api",
 *   "risk_tier": "high",
 *   "decision": "review",           // <-- did not allow, did not hard-deny
 *   "risk_score": 55,
 *   "policy_violations": [
 *     {
 *       "policy": "data_access_control",
 *       "severity": "high",
 *       "description": "Action targets sensitive resource containing \"payment\" — requires elevated access controls"
 *     },
 *     {
 *       "policy": "human_in_the_loop",
 *       "severity": "critical",
 *       "description": "High-stakes action \"transfer_funds\" at high risk requires human approval"
 *     }
 *   ],
 *   "recommended_controls": [
 *     "Enforce role-based access control for payment resources",
 *     "Require explicit human approval before execution",
 *     "Log the approver identity and timestamp"
 *   ],
 *   "governed": true,
 *   "mode": "local"
 * }
 *
 * === Summary ===
 * Decision : REVIEW
 * Risk Score: 55/100
 * Receipt ID: gov_m3x9a2b1_f4e8c3d2
 * Violations: 2
 *
 * The "review" decision means: the agent must NOT execute autonomously.
 * A human approver must confirm before the transfer proceeds.
 * This receipt is saved at ~/.dingdawg/governance/receipts/ as proof.
 */
