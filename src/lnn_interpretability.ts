/**
 * lnn_interpretability.ts — LNN Interpretability Module (Open-Core)
 *
 * Local tier: lightweight rule-trace stub for open-source use.
 * Cloud tier: full Liquid Neural Network inference with causal attribution.
 *             Requires DINGDAWG_API_KEY — served via api.dingdawg.com/v1/governance/explain
 *
 * To enable local explanation traces: set DINGDAWG_EXPLAIN=true
 * For semantic LNN explanations: set DINGDAWG_API_KEY (cloud tier)
 */

export interface CompactExplanation {
  primary_trigger: string;
  causal_chain: string[];
  confidence: number;
  counterfactual?: string;
}

export interface ExplanationTrace {
  primary_trigger: string;
  causal_chain: string[];
  confidence: number;
  counterfactual?: string;
  deliberation_time_ms: number;
  active_neurons: number;
  total_neurons: number;
  mode: "local_rule_trace" | "cloud_lnn";
  causal_steps: Array<{ neuron: string; activation: number; contribution: string }>;
  counterfactuals: Array<{ change: string; new_decision: string }>;
}

export interface TraceInput {
  action_type: string;
  action_description: string;
  target_resource: string;
  risk_tier: string;
  violations: string[];
  risk_score: number;
  decision: string;
}

/**
 * Enabled when DINGDAWG_EXPLAIN=true OR a valid API key is present.
 */
export function isExplainEnabled(): boolean {
  const explainEnv = process.env.DINGDAWG_EXPLAIN;
  if (explainEnv === "true" || explainEnv === "1") return true;
  return !!process.env.DINGDAWG_API_KEY;
}

/**
 * Generates a rule-trace explanation for a governance decision.
 *
 * Local mode: deterministic trace from policy violations.
 * Cloud mode: full LNN causal attribution — available with DINGDAWG_API_KEY.
 */
export function generateExplanationTrace(input: TraceInput): ExplanationTrace {
  const start = Date.now();

  // Rule-trace: derive primary trigger from violations or action type
  const primaryTrigger = input.violations.length > 0
    ? input.violations[0]
    : deriveDefaultTrigger(input.action_type);

  const causalChain = buildCausalChain(input);
  const confidence = input.violations.length === 0 ? 0.98
    : input.risk_score > 60 ? 0.92
    : 0.85;

  const counterfactual = buildCounterfactual(input);

  return {
    primary_trigger: primaryTrigger,
    causal_chain: causalChain,
    confidence,
    counterfactual,
    deliberation_time_ms: Date.now() - start,
    active_neurons: causalChain.length,
    total_neurons: 8,
    mode: "local_rule_trace",
    causal_steps: causalChain.map((step, i) => ({
      neuron: `rule_neuron_${i}`,
      activation: Math.max(0.1, 1 - i * 0.15),
      contribution: step,
    })),
    counterfactuals: counterfactual
      ? [{ change: "remove primary violation", new_decision: input.decision === "deny" ? "review" : input.decision }]
      : [],
  };
}

export function toCompactExplanation(trace: ExplanationTrace): CompactExplanation {
  return {
    primary_trigger: trace.primary_trigger,
    causal_chain: trace.causal_chain,
    confidence: trace.confidence,
    counterfactual: trace.counterfactual,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function deriveDefaultTrigger(actionType: string): string {
  const t = actionType.toLowerCase();
  if (t.includes("delete") || t.includes("drop") || t.includes("remove")) return "destructive_action_guard";
  if (t.includes("email") || t.includes("message") || t.includes("notify")) return "external_communication";
  if (t.includes("pay") || t.includes("charge") || t.includes("transfer")) return "financial_action";
  if (t.includes("read") || t.includes("get") || t.includes("fetch")) return "read_only_access";
  return "general_policy";
}

function buildCausalChain(input: TraceInput): string[] {
  const chain: string[] = [];

  const trigger = deriveDefaultTrigger(input.action_type);
  chain.push(
    `${input.action_type.replace(/_/g, " ")} '${input.action_type}' → ${trigger} policy → +${Math.round(input.risk_score * 0.4)}pts`
  );

  if (input.risk_tier === "high" || input.risk_tier === "critical") {
    chain.push(`risk_tier=${input.risk_tier} → tier_escalation → +${Math.round(input.risk_score * 0.3)}pts`);
  }

  for (const v of input.violations.slice(0, 2)) {
    chain.push(`violation: ${v} → policy_block → score threshold exceeded`);
  }

  if (input.risk_score >= 70) {
    chain.push(`cumulative_score=${input.risk_score} ≥ 70 → decision=deny`);
  } else if (input.risk_score >= 40) {
    chain.push(`cumulative_score=${input.risk_score} in [40,70) → decision=review`);
  } else {
    chain.push(`cumulative_score=${input.risk_score} < 40 → decision=allow`);
  }

  return chain;
}

function buildCounterfactual(input: TraceInput): string | undefined {
  if (input.decision === "deny" && input.violations.length > 0) {
    return `If '${input.violations[0]}' were not triggered, risk_score would be ~${Math.max(0, input.risk_score - 30)} → likely review or allow`;
  }
  return undefined;
}
