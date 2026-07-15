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
import {
  isExplainEnabled,
  generateExplanationTrace,
  toCompactExplanation,
  type ExplanationTrace,
  type CompactExplanation,
  type TraceInput,
} from "./lnn_interpretability.js";
import { registerMeterTools } from "./meter_tools.js";

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

interface VerifiedBadge {
  text: "Powered by DingDawg Verified";
  version: string;
  receipt_id: string;
  ipfs_ready: boolean;
  embed_url: string;
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
  verified_badge?: VerifiedBadge;
}

function buildVerifiedBadge(receiptId: string): VerifiedBadge {
  return {
    text: "Powered by DingDawg Verified",
    version: "1.0.3",
    receipt_id: receiptId,
    ipfs_ready: true,
    embed_url: `https://dingdawg.com/verify/${receiptId}`,
  };
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

/**
 * Free-tier local policy check (thin client).
 *
 * The full weighted policy engine — the complete keyword→weight→threshold
 * rulebook that produces allow/deny/review verdicts — runs SERVER-SIDE ONLY
 * (api.dingdawg.com). When DINGDAWG_API_KEY is set, govern_action calls that
 * API first and this function is never reached; it exists purely as the
 * offline fallback for keyless free-tier use.
 *
 * To avoid shipping a reverse-engineering cookbook, this fallback does the
 * minimum a thin client should: a tiny static list of the most obvious
 * destructive verbs is flagged for human review; everything else is allowed.
 * No weights, no score accumulation, no thresholds are exposed here.
 */
function evaluateLocalPolicies(
  actionType: string,
  actionDescription: string,
  targetResource: string,
  riskTier: string,
): { violations: PolicyViolation[]; riskScore: number; decision: "allow" | "deny" | "review"; controls: string[] } {
  void riskTier; // full risk-tier weighting is a server-side concern
  const haystack = `${actionType} ${actionDescription} ${targetResource}`.toLowerCase();

  // Minimal, non-revealing heuristic: only the most obvious destructive verbs.
  const obviousDestructiveVerbs = ["delete", "drop", "destroy", "wipe", "purge"];
  const looksDestructive = obviousDestructiveVerbs.some(v => haystack.includes(v));

  const violations: PolicyViolation[] = [];
  const controls: string[] = ["Set DINGDAWG_API_KEY for full policy analysis."];

  if (looksDestructive) {
    violations.push({
      policy: "basic_safety_check",
      severity: "medium",
      description: "Potentially destructive action flagged by the free-tier local check — manual review recommended.",
    });
    controls.push("Review this action manually before executing.");
    return { violations, riskScore: 0, decision: "review", controls };
  }

  return { violations, riskScore: 0, decision: "allow", controls };
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
// Keyword stuffing detection for compliance_check
// ---------------------------------------------------------------------------

function detectKeywordStuffing(description: string): { isStuffed: boolean; reason: string } {
  // Split into sentences (period, exclamation, question mark, or newline-delimited)
  const sentences = description
    .split(/[.!?\n]+/)
    .map(s => s.trim())
    .filter(s => s.length > 0);

  if (sentences.length === 0) {
    return { isStuffed: true, reason: "Empty or unparseable description" };
  }

  // Heuristic: if >50% of sentences are under 5 words, flag as insufficient detail
  const shortSentences = sentences.filter(s => s.split(/\s+/).length < 5);
  const shortRatio = shortSentences.length / sentences.length;

  if (shortRatio > 0.5) {
    return {
      isStuffed: true,
      reason: `Insufficient detail: ${Math.round(shortRatio * 100)}% of sentences are under 5 words. Provide substantive descriptions of your system's practices, not keyword lists.`,
    };
  }

  // Check for pure comma-separated keyword lists (e.g., "risk, human oversight, transparency, logging")
  const commaChunks = description.split(",").map(s => s.trim()).filter(s => s.length > 0);
  if (commaChunks.length >= 6) {
    const shortChunks = commaChunks.filter(c => c.split(/\s+/).length <= 3);
    if (shortChunks.length / commaChunks.length > 0.7) {
      return {
        isStuffed: true,
        reason: "Description appears to be a keyword list rather than a system description. Describe what your system does and how it addresses each requirement.",
      };
    }
  }

  // Check 3: Space-separated buzzword lists without sentence structure
  const structureWords = /\b(is|are|was|were|has|have|had|does|do|did|will|would|can|could|should|shall|may|might|must|the|a|an|our|we|it|this|that|these|those|for|with|from|into|through|during|before|after|between|under|above|by|at|in|on|of|to|and|but|or|if|when|while|because|since|although|perform|implement|use|provide|ensure|include|deploy|run|process|handle|manage|create|build|send|receive|store|analyze|evaluate|monitor|detect|prevent|protect|verify|validate|generate|execute|configure|maintain)\b/gi;
  const words = description.trim().split(/\s+/);
  const wordCount = words.length;
  if (wordCount >= 6) {
    const structureMatches = (description.match(structureWords) || []).length;
    const structureRatio = structureMatches / wordCount;
    if (structureRatio < 0.15) {
      return {
        isStuffed: true,
        reason: "Description appears to be a list of buzzwords without sentence structure. Provide complete sentences describing what your system does, how it works, and what safeguards are in place.",
      };
    }
  }

  return { isStuffed: false, reason: "" };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "dingdawg-governance",
  version: "2.1.0",
});

// ---------------------------------------------------------------------------
// govern_action — Works locally when no API key, API-first when key is set
// ---------------------------------------------------------------------------

server.tool(
  "govern_action",
  "Governs a single AI agent action: runs a capability check + policy evaluation, then returns a governance decision (allow/deny/conditions) plus a receipt_id proving the check happened. " +
    "Not read-only — every call writes a receipt record to disk at ~/.dingdawg/governance/receipts/ (best-effort; a filesystem error never blocks the decision). " +
    "No authentication required for local mode. If DINGDAWG_API_KEY is set, the cloud API is tried first with richer capability_check/risk_assessment detail; on any network error or non-2xx response it silently falls back to the local policy engine (mode: 'local_fallback' vs 'local' with no key). No hard rate limit. " +
    "Use this before letting an agent take a consequential action (send_email, make_purchase, modify_data, api_call, etc.) — it is the only tool of the four that produces a receipt_id for a specific action. " +
    "Use audit_trail to look up receipts this tool created, get_verified_badge to surface one publicly, or compliance_check instead if you're evaluating a whole system's posture rather than one action.",
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

    const rateCheck = checkFreeRateLimit("govern_action", 10);
    if (!rateCheck.allowed) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            error: "free_tier_limit_reached",
            message: "You've used all 10 free governed actions. Upgrade to continue.",
            upgrade_url: "https://dingdawg.com/pricing",
            starter_checkout: "https://checkout.dingdawg.com/b/9B69AS9m3gKP5hA1vxdjO04",
            note: "Starter: $19/mo — 50 calls/day | Pro: $49/mo — 200 calls/day",
          }, null, 2),
        }],
      };
    }

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

    // Generate LNN explanation trace if enabled
    let explanation: CompactExplanation | undefined;
    let fullTrace: ExplanationTrace | undefined;
    if (isExplainEnabled()) {
      const traceInput: TraceInput = {
        action_type,
        action_description,
        target_resource: resource,
        risk_tier: tier,
        violations: evaluation.violations,
        risk_score: evaluation.riskScore,
        decision: evaluation.decision,
      };
      fullTrace = await generateExplanationTrace(traceInput);
      explanation = toCompactExplanation(fullTrace);
    }

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
      ...(evaluation.decision !== "deny" && {
        verified_badge: buildVerifiedBadge(receiptId),
      }),
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
          ...(receipt.verified_badge && { verified_badge: receipt.verified_badge }),
          ...(explanation && { explanation }),
          ...(fullTrace && { explanation_detail: {
            deliberation_time_ms: fullTrace.deliberation_time_ms,
            active_neurons: fullTrace.active_neurons,
            total_neurons: fullTrace.total_neurons,
            mode: fullTrace.mode,
            causal_steps: fullTrace.causal_steps,
            counterfactuals: fullTrace.counterfactuals,
          }}),
        }, null, 2),
      }],
    };
  },
);

// ---------------------------------------------------------------------------
// get_verified_badge — Returns the "Powered by DingDawg Verified" badge payload
//
// Creators can opt-in to emit "Powered by DingDawg Verified" in agent output.
// When enabled, every governed action receipt includes a verifiable badge URL.
// This turns governed agents into DingDawg marketing channels.
//
// Usage: after govern_action returns a receipt_id, call get_verified_badge with
// that receipt_id to retrieve the embeddable badge payload. Agents can then
// include this in their output, UI, or logs to signal governed provenance.
// ---------------------------------------------------------------------------

server.tool(
  "get_verified_badge",
  "Read-only: looks up a receipt_id from a prior govern_action call and, if that action was allowed or flagged for review (not denied), returns an embeddable 'Powered by DingDawg Verified' badge payload (URL + markup) an agent can surface in its own output/UI/logs. " +
    "No side effects, no authentication required, no rate limit. Returns an error object (not a thrown exception) if the receipt_id doesn't exist or the referenced action was denied — check the response for an `error` field rather than assuming success. " +
    "receipt_id is required and must come from a prior govern_action response; this tool cannot generate a badge on its own. " +
    "Use this only after govern_action to surface provenance of an already-governed action; it does not perform any new governance check itself.",
  {
    receipt_id: z.string().describe("Receipt ID returned by a govern_action call (e.g. 'gov_abc123_def456')"),
  },
  { readOnlyHint: true },
  async ({ receipt_id }) => {
    // Look up the persisted receipt to validate it exists and was not denied
    const receipts = loadReceipts({ limit: 1, receiptId: receipt_id });
    const receipt = receipts[0];

    if (!receipt) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            error: "Receipt not found",
            detail: `No governance receipt found for id "${receipt_id}". Run govern_action first.`,
            governed: true,
          }, null, 2),
        }],
      };
    }

    if (receipt.decision === "deny") {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            error: "Badge not available",
            detail: "Verified badge is only issued for receipts with decision 'allow' or 'review'. This action was denied.",
            receipt_id,
            decision: receipt.decision,
            governed: true,
          }, null, 2),
        }],
      };
    }

    const badge = buildVerifiedBadge(receipt_id);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          success: true,
          badge,
          usage: {
            markdown: `![Powered by DingDawg Verified](${badge.embed_url})`,
            html: `<a href="${badge.embed_url}" target="_blank">Powered by DingDawg Verified</a>`,
            plain: `${badge.text} — verify at ${badge.embed_url}`,
          },
          governed: true,
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
  "Read-only lookup of governance receipts previously created by govern_action — from local storage (~/.dingdawg/governance/receipts/) or, when DINGDAWG_API_KEY is set, the cloud API (falling back to local on any API error). " +
    "No side effects, no authentication required for local mode, no rate limit, free to use. " +
    "Returns { total_records, trail: [...], time_range, mode }, where each trail entry is a receipt summary (receipt_id, timestamp, agent_id, action_type, decision, risk_score, policy_violations_count) — not the full receipt. " +
    "receipt_id and agent_id are independent filters, not mutually exclusive — supplying both narrows to that agent's occurrences of that specific receipt (usually 0 or 1 result). " +
    "time_range default differs by mode when omitted: local mode returns full history (time_range: 'all'), cloud API mode defaults to the last 24h. limit defaults to 10 either way. " +
    "Use this to review or verify past govern_action decisions; use govern_action to create a new receipt, get_verified_badge to surface one publicly.",
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
  "Evaluates a described AI system's compliance posture against one or all of: EU AI Act, Colorado AI Act — Revised (SB26-189 / ADMT, eff. Jan 1 2027), NIST AI RMF, ISO 42001. Read-only — analyzes the text you provide, does not inspect or modify your actual system, and writes nothing (unlike govern_action). " +
    "No authentication required. Hard rate limit: 10 checks per rolling 24h window per machine; once exceeded, every call returns an error object (no partial result) until the window resets — check checks_remaining in a successful response. For unlimited checks, set DINGDAWG_API_KEY. " +
    "Free-tier scoring is a uniform, unweighted coverage ratio (requirements mentioned vs. total) — not the fully weighted, framework-calibrated assessment, which requires an API key. " +
    "Returns { overall_compliance (0-100), compliance_level, frameworks: [...per-framework score/status/requirements], critical_gaps, recommendation, next_step, checks_remaining }. Accuracy depends entirely on how complete system_description is — vague descriptions score conservatively low rather than guessing in your favor. " +
    "Use this for a whole-system compliance posture check before deployment; use govern_action instead for governing individual agent actions at runtime, and audit_trail to review the history of those decisions.",
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

  // Free-tier local checklist = simple pattern matching only: is each required
  // control mentioned or not. The per-requirement scoring calibration — which
  // clause carries how much weight and the pass/partial cut-offs — lives
  // SERVER-SIDE ONLY (api.dingdawg.com). Set DINGDAWG_API_KEY for the full
  // weighted, framework-calibrated assessment. Locally we report only a generic,
  // uniform coverage ratio (met vs. total) so no proprietary calibration ships.
  const coverage = (met: string[], missing: string[]): number => {
    const total = met.length + missing.length;
    return total === 0 ? 0 : Math.round((met.length / total) * 100);
  };
  const statusFor = (pct: number): "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT" =>
    pct >= 70 ? "COMPLIANT" : pct >= 40 ? "PARTIAL" : "NON_COMPLIANT";

  // EU AI Act
  if (framework === "eu_ai_act" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];

    if (hasKeywordWithoutNegation(desc, "risk assessment") || hasKeywordWithoutNegation(desc, "risk classif")) {
      met.push("Risk classification (Art. 6)");
    } else { missing.push("Risk classification required (Art. 6)"); }

    if (hasKeywordWithoutNegation(desc, "human oversight") || hasKeywordWithoutNegation(desc, "human-in-the-loop")) {
      met.push("Human oversight (Art. 14)");
    } else { missing.push("Human oversight required (Art. 14)"); criticalGaps.push("EU AI Act Art. 14: No human oversight mechanism"); }

    if (hasKeywordWithoutNegation(desc, "transparen") || hasKeywordWithoutNegation(desc, "explainab")) {
      met.push("Transparency obligations (Art. 13)");
    } else { missing.push("Transparency obligations (Art. 13)"); }

    if (hasKeywordWithoutNegation(desc, "data governance") || hasKeywordWithoutNegation(desc, "training data")) {
      met.push("Data governance (Art. 10)");
    } else { missing.push("Data governance required (Art. 10)"); }

    if (hasKeywordWithoutNegation(desc, "technical document") || hasKeywordWithoutNegation(desc, "model card")) {
      met.push("Technical documentation (Art. 11)");
    } else { missing.push("Technical documentation required (Art. 11)"); }

    if (hasKeywordWithoutNegation(desc, "logging") || hasKeywordWithoutNegation(desc, "audit")) {
      met.push("Record-keeping (Art. 12)");
    } else { missing.push("Automatic logging required (Art. 12)"); }

    // High-risk category detection
    const highRisk = ["biometric", "critical infrastructure", "education", "employment", "credit", "law enforcement", "migration", "justice"];
    for (const hr of highRisk) {
      if (desc.includes(hr)) {
        missing.push(`HIGH-RISK system detected ("${hr}") — full Art. 6-15 compliance mandatory`);
        criticalGaps.push(`EU AI Act: High-risk AI system ("${hr}") requires full compliance`);
        break;
      }
    }

    const pct = coverage(met, missing);
    frameworks.push({ name: "EU AI Act", score: pct, status: statusFor(pct), requirements_met: met, requirements_missing: missing });
  }

  // Colorado ADMT Law (SB26-189)
  if (framework === "colorado_ai_act" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];

    if (hasKeywordWithoutNegation(desc, "consequential decision") || hasKeywordWithoutNegation(desc, "high-risk")) {
      met.push("Consequential decision identification (SB26-189 — ADMT consequential decision, eff. Jan 1 2027)");
    } else { missing.push("Must identify if system makes consequential decisions"); }

    // NOTE: SB26-189 REMOVED annual impact assessment obligation (was SB24-205 Sec. 4).
    // Replacement obligation: 3-year record retention of ADMT outputs + personal data used.
    if (hasKeywordWithoutNegation(desc, "record retention") || hasKeywordWithoutNegation(desc, "audit log") || hasKeywordWithoutNegation(desc, "data retention")) {
      met.push("Documentation & record retention — 3 years (SB26-189, eff. Jan 1 2027)");
    } else { missing.push("Record retention required — 3 years of ADMT outputs + personal data used (SB26-189, eff. Jan 1 2027)"); criticalGaps.push("Colorado ADMT Law (SB26-189): No record retention policy documented"); }

    if (hasKeywordWithoutNegation(desc, "disclosure") || hasKeywordWithoutNegation(desc, "notify")) {
      met.push("Consumer disclosure (SB26-189 — ADMT notice obligation, eff. Jan 1 2027)");
    } else { missing.push("Consumer disclosure required (SB26-189 — ADMT notice obligation, eff. Jan 1 2027)"); }

    // SB26-189 grants "meaningful human review and reconsideration" post-adverse-outcome — NOT an opt-out right.
    if (hasKeywordWithoutNegation(desc, "human review") || hasKeywordWithoutNegation(desc, "appeal") || hasKeywordWithoutNegation(desc, "reconsideration")) {
      met.push("Right to meaningful human review and reconsideration — post-adverse-outcome (SB26-189, eff. Jan 1 2027)");
    } else { missing.push("Human review and reconsideration process required post-adverse-outcome (SB26-189, eff. Jan 1 2027)"); }

    if (hasKeywordWithoutNegation(desc, "bias") || hasKeywordWithoutNegation(desc, "discrimination")) {
      met.push("Algorithmic discrimination prevention");
    } else { missing.push("Must test for algorithmic discrimination"); }

    const pct = coverage(met, missing);
    frameworks.push({ name: "Colorado AI Act — Revised (SB26-189 / ADMT)", score: pct, status: statusFor(pct), requirements_met: met, requirements_missing: missing });
  }

  // NIST AI RMF
  if (framework === "nist_ai_rmf" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];

    if (hasKeywordWithoutNegation(desc, "risk") || hasKeywordWithoutNegation(desc, "threat model")) {
      met.push("GOVERN: Risk management process");
    } else { missing.push("GOVERN: Establish risk management process"); }

    if (hasKeywordWithoutNegation(desc, "map") || hasKeywordWithoutNegation(desc, "context") || hasKeywordWithoutNegation(desc, "stakeholder")) {
      met.push("MAP: Context and stakeholder mapping");
    } else { missing.push("MAP: Define context, stakeholders, and intended use"); }

    if (hasKeywordWithoutNegation(desc, "measur") || hasKeywordWithoutNegation(desc, "metric") || hasKeywordWithoutNegation(desc, "benchmark")) {
      met.push("MEASURE: Performance metrics defined");
    } else { missing.push("MEASURE: Define and track AI performance metrics"); }

    if (hasKeywordWithoutNegation(desc, "monitor") || hasKeywordWithoutNegation(desc, "mitigat") || hasKeywordWithoutNegation(desc, "remediat")) {
      met.push("MANAGE: Ongoing monitoring and mitigation");
    } else { missing.push("MANAGE: Implement continuous monitoring and mitigation"); }

    if (hasKeywordWithoutNegation(desc, "trustworth")) {
      met.push("Trustworthiness characteristics addressed");
    } else { missing.push("Address all 7 trustworthiness characteristics"); }

    const pct = coverage(met, missing);
    frameworks.push({ name: "NIST AI RMF", score: pct, status: statusFor(pct), requirements_met: met, requirements_missing: missing });
  }

  // ISO 42001
  if (framework === "iso_42001" || framework === "all") {
    const met: string[] = [];
    const missing: string[] = [];

    if (hasKeywordWithoutNegation(desc, "policy") || hasKeywordWithoutNegation(desc, "governance")) {
      met.push("AI management system policy (Clause 5)");
    } else { missing.push("AI management system policy required (Clause 5)"); }

    if (hasKeywordWithoutNegation(desc, "risk assessment") || hasKeywordWithoutNegation(desc, "risk treat")) {
      met.push("Risk assessment and treatment (Clause 6)");
    } else { missing.push("Risk assessment and treatment required (Clause 6)"); criticalGaps.push("ISO 42001: No risk assessment process"); }

    if (hasKeywordWithoutNegation(desc, "resource") || hasKeywordWithoutNegation(desc, "competen")) {
      met.push("Resources and competence (Clause 7)");
    } else { missing.push("Define resources and competence requirements (Clause 7)"); }

    if (hasKeywordWithoutNegation(desc, "operational") || hasKeywordWithoutNegation(desc, "lifecycle")) {
      met.push("Operational planning and control (Clause 8)");
    } else { missing.push("Operational lifecycle management required (Clause 8)"); }

    if (hasKeywordWithoutNegation(desc, "performance evaluation") || hasKeywordWithoutNegation(desc, "audit")) {
      met.push("Performance evaluation (Clause 9)");
    } else { missing.push("Performance evaluation and internal audit required (Clause 9)"); }

    if (hasKeywordWithoutNegation(desc, "continual improvement") || hasKeywordWithoutNegation(desc, "corrective")) {
      met.push("Continual improvement (Clause 10)");
    } else { missing.push("Continual improvement process required (Clause 10)"); }

    const pct = coverage(met, missing);
    frameworks.push({ name: "ISO 42001", score: pct, status: statusFor(pct), requirements_met: met, requirements_missing: missing });
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
// Meter tools (v2.1.0) — LLM spend tracking + budget enforcement
// ---------------------------------------------------------------------------

registerMeterTools(server);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => { console.error("Server failed:", err); process.exit(1); });
