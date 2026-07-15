/**
 * lnn_interpretability.ts — Governance decision explanation (thin client)
 *
 * FREE tier: generic local summary (decision + score only, no rule detail).
 * PAID tier: full causal explanation + counterfactuals via DingDawg API.
 *
 * The actual policy weights, keyword rules, and scoring thresholds live
 * server-side only — never in this package. See dingdawg-compliance's
 * index.ts for the reference pattern this file now follows.
 */

const API_ENDPOINT = "https://api.dingdawg.com/v1/govern/explain";
const API_KEY = process.env.DINGDAWG_API_KEY || "";

// ---------------------------------------------------------------------------
// Types — public contract only, no scoring logic
// ---------------------------------------------------------------------------

export interface PolicyViolation {
  policy: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export interface CausalStep {
  description: string;
  score_delta: number;
  running_total: number;
  neuron: string;
  tau: number;
  activation: number;
}

export interface Counterfactual {
  description: string;
  changed_input: string;
  from: string;
  to: string;
  resulting_decision: "allow" | "deny" | "review";
  resulting_score: number;
}

export interface ExplanationTrace {
  primary_trigger: string;
  causal_chain: string[];
  causal_steps: CausalStep[];
  confidence: number;
  counterfactual: string;
  counterfactuals: Counterfactual[];
  deliberation_time_ms: number;
  active_neurons: number;
  total_neurons: number;
  mode: "local_basic" | "api_explained";
}

export interface TraceInput {
  action_type: string;
  action_description: string;
  target_resource: string;
  risk_tier: string;
  violations: PolicyViolation[];
  risk_score: number;
  decision: "allow" | "deny" | "review";
}

// ---------------------------------------------------------------------------
// Feature gating
// ---------------------------------------------------------------------------

export function isExplainEnabled(): boolean {
  const explainEnv = process.env.DINGDAWG_EXPLAIN;
  if (explainEnv === "true" || explainEnv === "1") return true;
  return API_KEY.length > 0;
}

// ---------------------------------------------------------------------------
// Core: Generate explanation trace
// ---------------------------------------------------------------------------

/**
 * FREE tier: a generic, non-revealing summary — reports the decision that
 * was already made by the API, no local rule evaluation happens here.
 * PAID tier: calls the API for the full causal trace + counterfactuals.
 */
export async function generateExplanationTrace(input: TraceInput): Promise<ExplanationTrace> {
  const startTime = Date.now();

  if (API_KEY) {
    try {
      const res = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${API_KEY}`,
        },
        body: JSON.stringify(input),
      });
      if (res.ok) {
        const data = await res.json() as ExplanationTrace;
        return data;
      }
    } catch {
      // fall through to local summary on any API error
    }
  }

  return localSummary(input, Date.now() - startTime);
}

/**
 * Generic local summary — reports WHAT the decision was, not WHY.
 * No policy weights, keywords, or thresholds are evaluated or exposed here.
 */
function localSummary(input: TraceInput, elapsedMs: number): ExplanationTrace {
  const primaryPolicy = input.violations[0]?.policy || "none";
  const chain = [
    `decision: ${input.decision} (score ${input.risk_score})`,
    input.violations.length > 0
      ? `${input.violations.length} policy signal(s) detected`
      : "no policy signals detected",
  ];

  return {
    primary_trigger: primaryPolicy,
    causal_chain: chain,
    causal_steps: [],
    confidence: 0.5,
    counterfactual: "Set DINGDAWG_API_KEY for a detailed causal explanation and counterfactual analysis.",
    counterfactuals: [],
    deliberation_time_ms: elapsedMs,
    active_neurons: input.violations.length,
    total_neurons: 0,
    mode: "local_basic",
  };
}

// ---------------------------------------------------------------------------
// Compact explanation (for receipts — drops verbose fields)
// ---------------------------------------------------------------------------

export interface CompactExplanation {
  primary_trigger: string;
  causal_chain: string[];
  confidence: number;
  counterfactual: string;
}

export function toCompactExplanation(trace: ExplanationTrace): CompactExplanation {
  return {
    primary_trigger: trace.primary_trigger,
    causal_chain: trace.causal_chain,
    confidence: trace.confidence,
    counterfactual: trace.counterfactual,
  };
}
