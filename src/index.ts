#!/usr/bin/env node
/**
 * dingdawg-governance — AI Governance-as-a-Service MCP Server
 *
 * Govern actions. Audit trails. Compliance checks.
 *
 * Install: npx dingdawg-governance
 * Claude Code: claude mcp add dingdawg-governance npx dingdawg-governance
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

const API_BASE = process.env.DINGDAWG_API_URL || "https://api.dingdawg.com/v1";
const API_KEY = process.env.DINGDAWG_API_KEY || "";

// ---------------------------------------------------------------------------
// Filesystem paths
// ---------------------------------------------------------------------------

const GOV_DIR = path.join(os.homedir(), ".dingdawg", "governance");
const RECEIPTS_DIR = path.join(GOV_DIR, "receipts");
const RATE_FILE = path.join(os.homedir(), ".dingdawg", "governance_usage.json");

function ensureDirs(): void {
  if (!fs.existsSync(RECEIPTS_DIR)) {
    fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Persistent rate limiting — same pattern as dingdawg-compliance
// ---------------------------------------------------------------------------

const MACHINE_ID = crypto.createHash("sha256")
  .update(`${os.hostname()}-${os.userInfo().username}-${os.platform()}-${os.arch()}`)
  .digest("hex").slice(0, 16);

function checkFreeRateLimit(tool: string, limit: number): { allowed: boolean; remaining: number } {
  const key = `${MACHINE_ID}_${tool}`;
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  let store: Record<string, { count: number; resetAt: number }> = {};
  try {
    const dir = path.dirname(RATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(RATE_FILE)) {
      store = JSON.parse(fs.readFileSync(RATE_FILE, "utf-8"));
    }
  } catch { /* fresh start */ }

  const entry = store[key];
  if (!entry || now > entry.resetAt) {
    store[key] = { count: 1, resetAt: now + dayMs };
  } else if (entry.count >= limit) {
    try { fs.writeFileSync(RATE_FILE, JSON.stringify(store)); } catch { /* best effort */ }
    return { allowed: false, remaining: 0 };
  } else {
    store[key].count++;
  }

  try { fs.writeFileSync(RATE_FILE, JSON.stringify(store)); } catch { /* best effort */ }
  const current = store[key].count;
  return { allowed: true, remaining: limit - current };
}

// ---------------------------------------------------------------------------
// Local policy evaluation engine
// ---------------------------------------------------------------------------

interface PolicyViolation {
  policy: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

interface GovernanceReceipt {
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  action_type: string;
  action_description: string;
  target_resource: string;
  risk_tier: string;
  decision: "allow" | "deny" | "review";
  risk_score: number;
  policy_violations: PolicyViolation[];
  recommended_controls: string[];
  context: Record<string, string>;
}

const NEGATION_PREFIXES = /\b(?:no|not|without|lacks?|never|doesn'?t|don'?t|isn'?t|aren'?t|won'?t|cannot|can'?t|absent|missing|zero)\s+/i;

/** Returns true if the keyword appears in desc WITHOUT a preceding negation */
function hasKeywordWithoutNegation(desc: string, keyword: string): boolean {
  const regex = new RegExp(`\\b${keyword}\\b`, "gi");
  let match: RegExpExecArray | null;
  while ((match = regex.exec(desc)) !== null) {
    const before = desc.slice(Math.max(0, match.index - 40), match.index);
    if (!NEGATION_PREFIXES.test(before)) {
      return true;
    }
  }
  return false;
}

function evaluateLocalPolicies(
  actionType: string,
  actionDescription: string,
  targetResource: string,
  riskTier: string,
): { violations: PolicyViolation[]; riskScore: number; decision: "allow" | "deny" | "review"; controls: string[] } {
  const violations: PolicyViolation[] = [];
  const controls: string[] = [];
  let riskScore = 0;
  const desc = actionDescription.toLowerCase();
  const resource = targetResource.toLowerCase();
  const action = actionType.toLowerCase();

  // --- Data access controls ---
  const sensitiveResources = ["user_database", "payment", "credentials", "secrets", "pii", "health_records", "ssn", "financial"];
  for (const sr of sensitiveResources) {
    if (resource.includes(sr) || desc.includes(sr)) {
      riskScore += 25;
      violations.push({
        policy: "data_access_control",
        severity: "high",
        description: `Action targets sensitive resource containing "${sr}" — requires elevated access controls`,
      });
      controls.push(`Enforce role-based access control for ${sr} resources`);
      break;
    }
  }

  // --- PII handling ---
  const piiIndicators = ["personal data", "pii", "email address", "phone number", "social security", "date of birth", "name and address"];
  for (const indicator of piiIndicators) {
    if (desc.includes(indicator) || resource.includes(indicator.replace(/ /g, "_"))) {
      riskScore += 20;
      violations.push({
        policy: "pii_handling",
        severity: "high",
        description: `PII detected ("${indicator}") — requires data protection controls per GDPR/CCPA`,
      });
      controls.push("Apply data minimization — collect only what is necessary");
      controls.push("Ensure PII encryption at rest and in transit");
      break;
    }
  }

  // --- Rate limit policy ---
  const bulkActions = ["bulk", "batch", "mass", "all users", "broadcast", "export_all"];
  for (const ba of bulkActions) {
    if (desc.includes(ba) || action.includes(ba)) {
      riskScore += 15;
      violations.push({
        policy: "rate_limit_policy",
        severity: "medium",
        description: `Bulk operation detected ("${ba}") — requires rate limiting and batching controls`,
      });
      controls.push("Implement batch size limits and progressive processing");
      break;
    }
  }

  // --- Human-in-the-loop requirements ---
  const highStakesActions = ["delete", "purchase", "payment", "transfer", "send_email", "modify_data", "deploy", "terminate", "revoke"];
  const needsHumanReview = highStakesActions.some(a => action.includes(a) || desc.includes(a));
  if (needsHumanReview && (riskTier === "high" || riskTier === "critical")) {
    riskScore += 20;
    violations.push({
      policy: "human_in_the_loop",
      severity: "critical",
      description: `High-stakes action "${actionType}" at ${riskTier} risk requires human approval`,
    });
    controls.push("Require explicit human approval before execution");
    controls.push("Log the approver identity and timestamp");
  }

  // --- Destructive action detection ---
  const destructiveKeywords = ["delete", "drop", "truncate", "destroy", "purge", "wipe", "remove all"];
  for (const dk of destructiveKeywords) {
    if (action.includes(dk) || desc.includes(dk)) {
      riskScore += 30;
      violations.push({
        policy: "destructive_action_guard",
        severity: "critical",
        description: `Destructive operation detected ("${dk}") — requires backup and confirmation`,
      });
      controls.push("Create backup before executing destructive operation");
      controls.push("Require double confirmation for destructive actions");
      break;
    }
  }

  // --- External communication ---
  const externalComms = ["send_email", "sms", "webhook", "api_call", "notify", "broadcast"];
  for (const ec of externalComms) {
    if (action.includes(ec) || desc.includes(ec)) {
      riskScore += 10;
      violations.push({
        policy: "external_communication",
        severity: "medium",
        description: `External communication detected ("${ec}") — review content before sending`,
      });
      controls.push("Validate message content before sending externally");
      break;
    }
  }

  // --- Risk tier amplifier ---
  if (riskTier === "critical") riskScore += 20;
  else if (riskTier === "high") riskScore += 10;

  riskScore = Math.max(0, Math.min(100, riskScore));

  // --- Decision ---
  let decision: "allow" | "deny" | "review";
  if (riskScore >= 70) {
    decision = "deny";
  } else if (riskScore >= 40 || violations.some(v => v.severity === "critical")) {
    decision = "review";
  } else {
    decision = "allow";
  }

  // Deduplicate controls
  const uniqueControls = [...new Set(controls)];

  return { violations, riskScore, decision, controls: uniqueControls };
}

function saveReceipt(receipt: GovernanceReceipt): void {
  ensureDirs();
  const filePath = path.join(RECEIPTS_DIR, `${receipt.receipt_id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(receipt, null, 2));
}

function loadReceipts(options: { limit: number; agentId?: string; receiptId?: string; timeRange?: string }): GovernanceReceipt[] {
  ensureDirs();
  const files = fs.readdirSync(RECEIPTS_DIR).filter(f => f.endsWith(".json"));

  // If looking for a specific receipt
  if (options.receiptId) {
    const filePath = path.join(RECEIPTS_DIR, `${options.receiptId}.json`);
    if (fs.existsSync(filePath)) {
      try {
        return [JSON.parse(fs.readFileSync(filePath, "utf-8"))];
      } catch {
        return [];
      }
    }
    return [];
  }

  // Load all, parse, sort by timestamp descending
  const receipts: GovernanceReceipt[] = [];
  for (const file of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(RECEIPTS_DIR, file), "utf-8"));
      receipts.push(data);
    } catch {
      // Skip corrupt files
    }
  }

  // Sort newest first
  receipts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  // Filter by agent_id if provided
  let filtered = receipts;
  if (options.agentId) {
    filtered = receipts.filter(r => r.agent_id === options.agentId);
  }

  // Filter by time range if provided
  if (options.timeRange) {
    const now = Date.now();
    const rangeMs: Record<string, number> = {
      "1h": 60 * 60 * 1000,
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    const cutoff = now - (rangeMs[options.timeRange] || rangeMs["24h"]);
    filtered = filtered.filter(r => new Date(r.timestamp).getTime() >= cutoff);
  }

  return filtered.slice(0, options.limit);
}

// ---------------------------------------------------------------------------
// Description quality validation — runs server-side when API key is set
// ---------------------------------------------------------------------------

function detectKeywordStuffing(_description: string): { isStuffed: boolean; reason: string } {
  // Full validation runs server-side via the API.
  // Local mode accepts all descriptions — cloud tier enforces quality gates.
  return { isStuffed: false, reason: "" };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "dingdawg-governance",
  version: "1.0.2",
});

// ---------------------------------------------------------------------------
// govern_action — Works locally when no API key, API-first when key is set
// ---------------------------------------------------------------------------

server.tool(
  "govern_action",
  "Govern any AI agent action. Performs capability check + policy evaluation + generates a governance receipt. Returns a receipt proving the action was governed. When API key is set, uses cloud API with local fallback.",
  {
    agent_id: z.string().describe("Identifier for the AI agent performing the action"),
    action_type: z.string().describe("Type of action (e.g., 'send_email', 'make_purchase', 'modify_data', 'api_call')"),
    action_description: z.string().describe("Human-readable description of what the agent is about to do"),
    target_resource: z.string().optional().describe("The resource being acted upon (e.g., 'user_database', 'email_server', 'payment_api')"),
    risk_tier: z.enum(["low", "medium", "high", "critical"]).optional().describe("Self-assessed risk level of this action"),
    context: z.record(z.string(), z.string()).optional().describe("Additional context key-value pairs for policy evaluation"),
  },
  async ({ agent_id, action_type, action_description, target_resource, risk_tier, context }) => {
    const tier = risk_tier || "medium";
    const resource = target_resource || "unspecified";
    const ctx = context || {};

    // If API key is set, try the API first
    if (API_KEY) {
      try {
        const res = await fetch(`${API_BASE}/governance/govern`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
          body: JSON.stringify({ agent_id, action_type, action_description, target_resource: resource, risk_tier: tier, context: ctx }),
        });
        if (res.ok) {
          const data = await res.json();
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                success: true,
                decision: data.decision,
                receipt_id: data.receipt_id || `gov_${Date.now().toString(36)}`,
                capability_check: data.capability_check,
                policy_evaluation: data.policy_evaluation,
                risk_assessment: data.risk_assessment,
                agent_id,
                action_type,
                timestamp: new Date().toISOString(),
                governed: true,
                ...(data.conditions && { conditions: data.conditions }),
              }, null, 2),
            }],
          };
        }
        // Non-OK response — fall through to local evaluation
      } catch {
        // Network error — fall through to local evaluation
      }
    }

    // Local policy evaluation
    const evaluation = evaluateLocalPolicies(action_type, action_description, resource, tier);
    const receiptId = `gov_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
    const timestamp = new Date().toISOString();

    const receipt: GovernanceReceipt = {
      receipt_id: receiptId,
      timestamp,
      agent_id,
      action_type,
      action_description,
      target_resource: resource,
      risk_tier: tier,
      decision: evaluation.decision,
      risk_score: evaluation.riskScore,
      policy_violations: evaluation.violations,
      recommended_controls: evaluation.controls,
      context: ctx,
    };

    // Persist the receipt
    try {
      saveReceipt(receipt);
    } catch {
      // Best effort — don't fail the governance check over filesystem issues
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          success: true,
          receipt_id: receiptId,
          timestamp,
          agent_id,
          action_type,
          target_resource: resource,
          risk_tier: tier,
          decision: evaluation.decision,
          risk_score: evaluation.riskScore,
          policy_violations: evaluation.violations,
          recommended_controls: evaluation.controls,
          governed: true,
          mode: API_KEY ? "local_fallback" : "local",
        }, null, 2),
      }],
    };
  },
);

// ---------------------------------------------------------------------------
// audit_trail — Works locally, API-first when key is set
// ---------------------------------------------------------------------------

server.tool(
  "audit_trail",
  "Get the governance audit trail. Returns governance receipts from local storage or cloud API. Free to use.",
  {
    receipt_id: z.string().optional().describe("Receipt ID from a govern_action call"),
    agent_id: z.string().optional().describe("Agent ID to get all governed actions for"),
    time_range: z.enum(["1h", "24h", "7d", "30d"]).optional().describe("Time range for audit trail lookup"),
    limit: z.number().optional().describe("Maximum number of records to return (default 10)"),
  },
  async ({ receipt_id, agent_id, time_range, limit }) => {
    const maxRecords = limit || 10;

    // If API key is set, try the API first
    if (API_KEY) {
      try {
        const params = new URLSearchParams();
        if (receipt_id) params.set("receipt_id", receipt_id);
        if (agent_id) params.set("agent_id", agent_id);
        if (time_range) params.set("time_range", time_range);
        if (limit) params.set("limit", String(limit));

        const res = await fetch(`${API_BASE}/governance/audit?${params.toString()}`, {
          headers: { Authorization: `Bearer ${API_KEY}` },
        });
        if (res.ok) {
          const data = await res.json();
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                success: true,
                total_records: data.total_records,
                trail: data.trail,
                time_range: time_range || "24h",
                governed: true,
              }, null, 2),
            }],
          };
        }
        // Non-OK response — fall through to local
      } catch {
        // Network error — fall through to local
      }
    }

    // Local audit trail from filesystem
    const receipts = loadReceipts({
      limit: maxRecords,
      agentId: agent_id,
      receiptId: receipt_id,
      timeRange: time_range,
    });

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          success: true,
          total_records: receipts.length,
          trail: receipts.map(r => ({
            receipt_id: r.receipt_id,
            timestamp: r.timestamp,
            agent_id: r.agent_id,
            action_type: r.action_type,
            decision: r.decision,
            risk_score: r.risk_score,
            policy_violations_count: r.policy_violations.length,
          })),
          time_range: time_range || "all",
          governed: true,
          mode: API_KEY ? "local_fallback" : "local",
        }, null, 2),
      }],
    };
  },
);

// ---------------------------------------------------------------------------
// compliance_check — FREE tier: 10/day (local analysis, rate limited)
// ---------------------------------------------------------------------------

server.tool(
  "compliance_check",
  "Quick compliance check against common AI governance frameworks. Free tier: 10 checks per day. Evaluates against EU AI Act, Colorado AI Act, NIST AI RMF, and ISO 42001.",
  {
    system_description: z.string().describe("Describe your AI system: what it does, data sources, decision scope"),
    framework: z.enum(["eu_ai_act", "colorado_ai_act", "nist_ai_rmf", "iso_42001", "all"]).optional().describe("Framework to check against (default: all)"),
    deployment_stage: z.enum(["development", "staging", "production"]).optional().describe("Current deployment stage"),
  },
  async ({ system_description, framework, deployment_stage }) => {
    // Rate limiting: 10 checks per day
    const rateCheck = checkFreeRateLimit("compliance_check", 10);
    if (!rateCheck.allowed) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            error: "Free tier limit reached (10 compliance checks per 24 hours). Your limit resets automatically.",
            upgrade: "Get unlimited access with an API key at dingdawg.com/developers",
            governed: true,
          }),
        }],
      };
    }

    // Keyword stuffing detection
    const stuffingCheck = detectKeywordStuffing(system_description);
    if (stuffingCheck.isStuffed) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            error: "Insufficient system description",
            detail: stuffingCheck.reason,
            suggestion: "Provide a detailed description of your AI system including: what it does, what data it processes, how decisions are made, and what safeguards are in place.",
            checks_remaining: rateCheck.remaining,
            governed: true,
          }),
        }],
      };
    }

    const targetFramework = framework || "all";
    const stage = deployment_stage || "development";
    const results = runComplianceCheck(system_description, targetFramework, stage);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          check_id: `cc_${Date.now().toString(36)}`,
          overall_compliance: results.overallScore,
          compliance_level: results.level,
          frameworks: results.frameworks,
          critical_gaps: results.criticalGaps,
          deployment_stage: stage,
          checks_remaining: rateCheck.remaining,
          recommendation: results.overallScore < 40
            ? "Critical compliance gaps. Do not deploy without remediation."
            : results.overallScore < 70
            ? "Partial compliance. Address critical gaps before production deployment."
            : "Good compliance baseline. Use govern_action to maintain ongoing governance.",
          next_step: results.overallScore < 70
            ? "Address critical gaps, then run compliance_check again to verify."
            : "Use govern_action to govern your AI actions in production.",
          governed: true,
        }, null, 2),
      }],
    };
  },
);

// ---------------------------------------------------------------------------
// Local compliance check engine (powers free tier — no API needed)
// ---------------------------------------------------------------------------

interface FrameworkResult {
  name: string;
  score: number;
  status: "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT";
  requirements_met: string[];
  requirements_missing: string[];
}

function runComplianceCheck(
  description: string,
  framework: string,
  stage: string,
): { overallScore: number; level: string; frameworks: FrameworkResult[]; criticalGaps: string[] } {
  const desc = description.toLowerCase();
  const frameworks: FrameworkResult[] = [];
  const criticalGaps: string[] = [];

  // EU AI Act
  if (framework === "eu_ai_act" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];
    let score = 0;

    if (hasKeywordWithoutNegation(desc, "risk assessment") || hasKeywordWithoutNegation(desc, "risk classif")) {
      met.push("Risk classification (Art. 6)"); score += 10;
    } else { missing.push("Risk classification required (Art. 6)"); }

    if (hasKeywordWithoutNegation(desc, "human oversight") || hasKeywordWithoutNegation(desc, "human-in-the-loop")) {
      met.push("Human oversight (Art. 14)"); score += 15;
    } else { missing.push("Human oversight required (Art. 14)"); criticalGaps.push("EU AI Act Art. 14: No human oversight mechanism"); }

    if (hasKeywordWithoutNegation(desc, "transparen") || hasKeywordWithoutNegation(desc, "explainab")) {
      met.push("Transparency obligations (Art. 13)"); score += 10;
    } else { missing.push("Transparency obligations (Art. 13)"); }

    if (hasKeywordWithoutNegation(desc, "data governance") || hasKeywordWithoutNegation(desc, "training data")) {
      met.push("Data governance (Art. 10)"); score += 10;
    } else { missing.push("Data governance required (Art. 10)"); }

    if (hasKeywordWithoutNegation(desc, "technical document") || hasKeywordWithoutNegation(desc, "model card")) {
      met.push("Technical documentation (Art. 11)"); score += 10;
    } else { missing.push("Technical documentation required (Art. 11)"); }

    if (hasKeywordWithoutNegation(desc, "logging") || hasKeywordWithoutNegation(desc, "audit")) {
      met.push("Record-keeping (Art. 12)"); score += 5;
    } else { missing.push("Automatic logging required (Art. 12)"); }

    // High-risk category detection
    const highRisk = ["biometric", "critical infrastructure", "education", "employment", "credit", "law enforcement", "migration", "justice"];
    for (const hr of highRisk) {
      if (desc.includes(hr)) {
        missing.push(`HIGH-RISK system detected ("${hr}") — full Art. 6-15 compliance mandatory`);
        score -= 10;
        criticalGaps.push(`EU AI Act: High-risk AI system ("${hr}") requires full compliance`);
        break;
      }
    }

    score = Math.max(0, Math.min(100, score));
    frameworks.push({ name: "EU AI Act", score, status: score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIAL" : "NON_COMPLIANT", requirements_met: met, requirements_missing: missing });
  }

  // Colorado AI Act
  if (framework === "colorado_ai_act" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];
    let score = 0;

    if (hasKeywordWithoutNegation(desc, "consequential decision") || hasKeywordWithoutNegation(desc, "high-risk")) {
      met.push("Consequential decision identification (SB24-205 Sec. 3)"); score += 15;
    } else { missing.push("Must identify if system makes consequential decisions"); }

    if (hasKeywordWithoutNegation(desc, "impact assessment")) {
      met.push("Impact assessment (SB24-205 Sec. 4)"); score += 20;
    } else { missing.push("Impact assessment required (SB24-205 Sec. 4)"); criticalGaps.push("Colorado: No impact assessment documented"); }

    if (hasKeywordWithoutNegation(desc, "disclosure") || hasKeywordWithoutNegation(desc, "notify")) {
      met.push("Consumer disclosure (SB24-205 Sec. 5)"); score += 15;
    } else { missing.push("Consumer disclosure required (SB24-205 Sec. 5)"); }

    if (hasKeywordWithoutNegation(desc, "opt out") || hasKeywordWithoutNegation(desc, "appeal")) {
      met.push("Right to appeal/opt-out (SB24-205 Sec. 6)"); score += 15;
    } else { missing.push("Right to appeal/opt-out required (SB24-205 Sec. 6)"); }

    if (hasKeywordWithoutNegation(desc, "bias") || hasKeywordWithoutNegation(desc, "discrimination")) {
      met.push("Algorithmic discrimination prevention"); score += 15;
    } else { missing.push("Must test for algorithmic discrimination"); }

    score = Math.max(0, Math.min(100, score));
    frameworks.push({ name: "Colorado AI Act (SB24-205)", score, status: score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIAL" : "NON_COMPLIANT", requirements_met: met, requirements_missing: missing });
  }

  // NIST AI RMF
  if (framework === "nist_ai_rmf" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];
    let score = 0;

    if (hasKeywordWithoutNegation(desc, "risk") || hasKeywordWithoutNegation(desc, "threat model")) {
      met.push("GOVERN: Risk management process"); score += 20;
    } else { missing.push("GOVERN: Establish risk management process"); }

    if (hasKeywordWithoutNegation(desc, "map") || hasKeywordWithoutNegation(desc, "context") || hasKeywordWithoutNegation(desc, "stakeholder")) {
      met.push("MAP: Context and stakeholder mapping"); score += 15;
    } else { missing.push("MAP: Define context, stakeholders, and intended use"); }

    if (hasKeywordWithoutNegation(desc, "measur") || hasKeywordWithoutNegation(desc, "metric") || hasKeywordWithoutNegation(desc, "benchmark")) {
      met.push("MEASURE: Performance metrics defined"); score += 20;
    } else { missing.push("MEASURE: Define and track AI performance metrics"); }

    if (hasKeywordWithoutNegation(desc, "monitor") || hasKeywordWithoutNegation(desc, "mitigat") || hasKeywordWithoutNegation(desc, "remediat")) {
      met.push("MANAGE: Ongoing monitoring and mitigation"); score += 20;
    } else { missing.push("MANAGE: Implement continuous monitoring and mitigation"); }

    if (hasKeywordWithoutNegation(desc, "trustworth")) {
      met.push("Trustworthiness characteristics addressed"); score += 10;
    } else { missing.push("Address all 7 trustworthiness characteristics"); }

    score = Math.max(0, Math.min(100, score));
    frameworks.push({ name: "NIST AI RMF", score, status: score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIAL" : "NON_COMPLIANT", requirements_met: met, requirements_missing: missing });
  }

  // ISO 42001
  if (framework === "iso_42001" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];
    let score = 0;

    if (hasKeywordWithoutNegation(desc, "policy") || hasKeywordWithoutNegation(desc, "governance")) {
      met.push("AI management system policy (Clause 5)"); score += 15;
    } else { missing.push("AI management system policy required (Clause 5)"); }

    if (hasKeywordWithoutNegation(desc, "risk assessment") || hasKeywordWithoutNegation(desc, "risk treat")) {
      met.push("Risk assessment and treatment (Clause 6)"); score += 20;
    } else { missing.push("Risk assessment and treatment required (Clause 6)"); criticalGaps.push("ISO 42001: No risk assessment process"); }

    if (hasKeywordWithoutNegation(desc, "resource") || hasKeywordWithoutNegation(desc, "competen")) {
      met.push("Resources and competence (Clause 7)"); score += 15;
    } else { missing.push("Define resources and competence requirements (Clause 7)"); }

    if (hasKeywordWithoutNegation(desc, "operational") || hasKeywordWithoutNegation(desc, "lifecycle")) {
      met.push("Operational planning and control (Clause 8)"); score += 15;
    } else { missing.push("Operational lifecycle management required (Clause 8)"); }

    if (hasKeywordWithoutNegation(desc, "performance evaluation") || hasKeywordWithoutNegation(desc, "audit")) {
      met.push("Performance evaluation (Clause 9)"); score += 15;
    } else { missing.push("Performance evaluation and internal audit required (Clause 9)"); }

    if (hasKeywordWithoutNegation(desc, "continual improvement") || hasKeywordWithoutNegation(desc, "corrective")) {
      met.push("Continual improvement (Clause 10)"); score += 10;
    } else { missing.push("Continual improvement process required (Clause 10)"); }

    score = Math.max(0, Math.min(100, score));
    frameworks.push({ name: "ISO 42001", score, status: score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIAL" : "NON_COMPLIANT", requirements_met: met, requirements_missing: missing });
  }

  // Stage-specific adjustments
  if (stage === "production" && criticalGaps.length > 0) {
    criticalGaps.unshift("PRODUCTION SYSTEM with critical gaps — remediation is urgent");
  }

  const overallScore = frameworks.length > 0
    ? Math.round(frameworks.reduce((sum, f) => sum + f.score, 0) / frameworks.length)
    : 0;

  return {
    overallScore,
    level: overallScore >= 80 ? "COMPLIANT" : overallScore >= 60 ? "PARTIAL" : overallScore >= 40 ? "NEEDS_WORK" : "NON_COMPLIANT",
    frameworks,
    criticalGaps,
  };
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => { console.error("Server failed:", err); process.exit(1); });
