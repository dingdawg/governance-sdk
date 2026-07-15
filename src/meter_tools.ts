/**
 * meter_tools.ts — LLM spend metering + budget enforcement for dingdawg-governance v2.1.0
 *
 * Tools: meter_llm_call | set_llm_budget | get_spend_report
 *
 * Data contract:
 *   meter_llm_call: { agent_id, provider, model, prompt_tokens, completion_tokens, task_id? }
 *     → { cost_usd, cumulative_spend_usd, budget_status, budget_limit_usd, receipt_id, timestamp }
 *
 *   set_llm_budget: { agent_id, limit_usd, period, warning_threshold? }
 *     → { agent_id, limit_usd, period, warning_threshold, set_at }
 *
 *   get_spend_report: { agent_id?, from_date?, to_date? }
 *     → { total_cost_usd, call_count, by_model, by_agent, receipts[] }
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const METER_DIR = path.join(os.homedir(), ".dingdawg", "meter");
const SPEND_DIR = path.join(METER_DIR, "spend");
const BUDGET_FILE = path.join(METER_DIR, "budgets.json");

function ensureMeterDirs(): void {
  if (!fs.existsSync(SPEND_DIR)) fs.mkdirSync(SPEND_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// LLM price table (per 1M tokens, USD — snapshot 2026-04-25)
// input = prompt tokens, output = completion tokens
// ---------------------------------------------------------------------------

const PRICE_TABLE: Record<string, Record<string, { input: number; output: number }>> = {
  openai: {
    "gpt-4o":                   { input: 5.00,  output: 15.00  },
    "gpt-4o-mini":              { input: 0.15,  output: 0.60   },
    "gpt-4-turbo":              { input: 10.00, output: 30.00  },
    "gpt-4":                    { input: 30.00, output: 60.00  },
    "gpt-3.5-turbo":            { input: 0.50,  output: 1.50   },
    "o1":                       { input: 15.00, output: 60.00  },
    "o1-mini":                  { input: 3.00,  output: 12.00  },
    "o3":                       { input: 10.00, output: 40.00  },
    "o3-mini":                  { input: 1.10,  output: 4.40   },
  },
  anthropic: {
    "claude-opus-4-7":                  { input: 15.00, output: 75.00  },
    "claude-sonnet-4-6":                { input: 3.00,  output: 15.00  },
    "claude-haiku-4-5":                 { input: 0.80,  output: 4.00   },
    "claude-haiku-4-5-20251001":        { input: 0.80,  output: 4.00   },
    "claude-3-opus-20240229":           { input: 15.00, output: 75.00  },
    "claude-3-5-sonnet-20241022":       { input: 3.00,  output: 15.00  },
    "claude-3-5-haiku-20241022":        { input: 0.80,  output: 4.00   },
    "claude-3-haiku-20240307":          { input: 0.25,  output: 1.25   },
  },
  google: {
    "gemini-2.0-flash":         { input: 0.10,  output: 0.40   },
    "gemini-2.0-flash-lite":    { input: 0.075, output: 0.30   },
    "gemini-1.5-pro":           { input: 3.50,  output: 10.50  },
    "gemini-1.5-flash":         { input: 0.075, output: 0.30   },
    "gemini-1.0-pro":           { input: 0.50,  output: 1.50   },
  },
  groq: {
    "llama-3.3-70b-versatile":  { input: 0.59,  output: 0.79   },
    "llama-3.1-8b-instant":     { input: 0.05,  output: 0.08   },
    "mixtral-8x7b-32768":       { input: 0.24,  output: 0.24   },
    "gemma2-9b-it":             { input: 0.20,  output: 0.20   },
  },
  mistral: {
    "mistral-large-latest":     { input: 2.00,  output: 6.00   },
    "mistral-small-latest":     { input: 0.20,  output: 0.60   },
    "codestral-latest":         { input: 0.20,  output: 0.60   },
    "open-mixtral-8x22b":       { input: 2.00,  output: 6.00   },
  },
  cohere: {
    "command-r-plus":           { input: 2.50,  output: 10.00  },
    "command-r":                { input: 0.15,  output: 0.60   },
    "command":                  { input: 1.00,  output: 2.00   },
  },
  deepseek: {
    "deepseek-chat":            { input: 0.27,  output: 1.10   },
    "deepseek-reasoner":        { input: 0.55,  output: 2.19   },
  },
};

/** Calculate cost in USD for a model call */
function calcCost(provider: string, model: string, promptTokens: number, completionTokens: number): number {
  const providerPrices = PRICE_TABLE[provider.toLowerCase()];
  if (!providerPrices) return 0;

  // Exact match first, then prefix match (e.g. "gpt-4o-2024-11-20" → "gpt-4o")
  const prices = providerPrices[model] ?? Object.entries(providerPrices).find(([k]) => model.startsWith(k))?.[1];
  if (!prices) return 0;

  const inputCost  = (promptTokens     / 1_000_000) * prices.input;
  const outputCost = (completionTokens / 1_000_000) * prices.output;
  return Math.round((inputCost + outputCost) * 1_000_000) / 1_000_000; // 6 decimal places
}

// ---------------------------------------------------------------------------
// Budget storage (filesystem)
// ---------------------------------------------------------------------------

interface BudgetRecord {
  agent_id: string;
  limit_usd: number;
  period: "daily" | "monthly";
  warning_threshold: number;
  set_at: string;
}

function loadBudgets(): Record<string, BudgetRecord> {
  try {
    ensureMeterDirs();
    if (fs.existsSync(BUDGET_FILE)) {
      return JSON.parse(fs.readFileSync(BUDGET_FILE, "utf-8"));
    }
  } catch { /* fresh start */ }
  return {};
}

function saveBudgets(budgets: Record<string, BudgetRecord>): void {
  try {
    ensureMeterDirs();
    fs.writeFileSync(BUDGET_FILE, JSON.stringify(budgets, null, 2));
  } catch { /* best effort */ }
}

// ---------------------------------------------------------------------------
// Spend records (one JSON file per call, same pattern as governance receipts)
// ---------------------------------------------------------------------------

interface SpendRecord {
  receipt_id: string;
  agent_id: string;
  provider: string;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  cost_usd: number;
  task_id: string;
  timestamp: string;
}

function saveSpendRecord(record: SpendRecord): void {
  ensureMeterDirs();
  const file = path.join(SPEND_DIR, `${record.receipt_id}.json`);
  fs.writeFileSync(file, JSON.stringify(record, null, 2));
}

function loadSpendRecords(opts: {
  agentId?: string;
  fromDate?: string;
  toDate?: string;
  periodStart?: Date;  // for cumulative budget calc
}): SpendRecord[] {
  try {
    ensureMeterDirs();
    const files = fs.readdirSync(SPEND_DIR).filter(f => f.endsWith(".json"));
    const records: SpendRecord[] = [];
    for (const f of files) {
      try {
        records.push(JSON.parse(fs.readFileSync(path.join(SPEND_DIR, f), "utf-8")));
      } catch { /* skip corrupt */ }
    }
    let filtered = records;
    if (opts.agentId) filtered = filtered.filter(r => r.agent_id === opts.agentId);
    if (opts.fromDate) filtered = filtered.filter(r => r.timestamp >= opts.fromDate!);
    if (opts.toDate)   filtered = filtered.filter(r => r.timestamp <= opts.toDate!);
    if (opts.periodStart) {
      const cutoff = opts.periodStart.toISOString();
      filtered = filtered.filter(r => r.timestamp >= cutoff);
    }
    return filtered.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  } catch {
    return [];
  }
}

function getPeriodStart(period: "daily" | "monthly"): Date {
  const now = new Date();
  if (period === "daily") {
    return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  }
  return new Date(now.getFullYear(), now.getMonth(), 1);
}

// ---------------------------------------------------------------------------
// Register meter tools onto the MCP server
// ---------------------------------------------------------------------------

export function registerMeterTools(server: McpServer): void {

  // ── meter_llm_call ──────────────────────────────────────────────────────

  server.tool(
    "meter_llm_call",
    "Track the cost of an LLM API call and enforce budget limits. Call this after every LLM API response. Returns real-time cost, cumulative spend, and budget status. Free to use — no API key required.",
    {
      agent_id:          z.string().describe("Unique identifier for the agent making the LLM call"),
      provider:          z.enum(["openai","anthropic","google","groq","mistral","cohere","deepseek","other"]).describe("LLM provider"),
      model:             z.string().describe("Model name (e.g. 'gpt-4o', 'claude-sonnet-4-6', 'gemini-2.0-flash')"),
      prompt_tokens:     z.number().int().min(0).describe("Number of input/prompt tokens used"),
      completion_tokens: z.number().int().min(0).describe("Number of output/completion tokens generated"),
      task_id:           z.string().optional().describe("Optional task identifier for grouping related calls"),
    },
    async ({ agent_id, provider, model, prompt_tokens, completion_tokens, task_id }) => {
      const cost_usd = calcCost(provider, model, prompt_tokens, completion_tokens);
      const timestamp = new Date().toISOString();
      const receipt_id = `mtr_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;

      const record: SpendRecord = {
        receipt_id,
        agent_id,
        provider,
        model,
        prompt_tokens,
        completion_tokens,
        cost_usd,
        task_id: task_id || "",
        timestamp,
      };

      try { saveSpendRecord(record); } catch { /* best effort */ }

      // Cumulative spend + budget check
      const budgets = loadBudgets();
      const budget = budgets[agent_id];

      let cumulative_spend_usd = cost_usd;
      let budget_status: "ok" | "warning" | "exceeded" = "ok";
      let budget_limit_usd = 0;

      if (budget) {
        const periodStart = getPeriodStart(budget.period);
        const periodRecords = loadSpendRecords({ agentId: agent_id, periodStart });
        cumulative_spend_usd = periodRecords.reduce((s, r) => s + r.cost_usd, 0);
        budget_limit_usd = budget.limit_usd;

        const ratio = cumulative_spend_usd / budget.limit_usd;
        if (ratio >= 1.0) {
          budget_status = "exceeded";
        } else if (ratio >= budget.warning_threshold) {
          budget_status = "warning";
        }
      } else {
        // No budget set — calculate cumulative for info only
        const today = getPeriodStart("daily");
        const todayRecords = loadSpendRecords({ agentId: agent_id, periodStart: today });
        cumulative_spend_usd = todayRecords.reduce((s, r) => s + r.cost_usd, 0);
      }

      const unknownModel = provider !== "other" && cost_usd === 0;

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            receipt_id,
            agent_id,
            provider,
            model,
            prompt_tokens,
            completion_tokens,
            cost_usd,
            cumulative_spend_usd: Math.round(cumulative_spend_usd * 1_000_000) / 1_000_000,
            budget_status,
            ...(budget_limit_usd > 0 && { budget_limit_usd, budget_period: budget?.period }),
            timestamp,
            ...(unknownModel && {
              note: `Model "${model}" not in price table — cost shown as $0. Submit a PR or use provider "other".`,
            }),
            governed: true,
          }, null, 2),
        }],
      };
    },
  );

  // ── set_llm_budget ──────────────────────────────────────────────────────

  server.tool(
    "set_llm_budget",
    "Set a USD spend limit for an agent. The meter will return budget_status: 'warning' at the threshold and 'exceeded' when the limit is hit. Limits reset daily or monthly.",
    {
      agent_id:           z.string().describe("Agent ID to set budget for"),
      limit_usd:          z.number().positive().describe("Maximum USD spend allowed in the period (e.g. 10.00 for $10/day)"),
      period:             z.enum(["daily","monthly"]).describe("Reset cadence"),
      warning_threshold:  z.number().min(0.1).max(0.99).optional().describe("Fraction of limit that triggers 'warning' status (default: 0.8 = 80%)"),
    },
    async ({ agent_id, limit_usd, period, warning_threshold }) => {
      const threshold = warning_threshold ?? 0.8;
      const set_at = new Date().toISOString();

      const budgets = loadBudgets();
      budgets[agent_id] = { agent_id, limit_usd, period, warning_threshold: threshold, set_at };
      saveBudgets(budgets);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            success: true,
            agent_id,
            limit_usd,
            period,
            warning_threshold: threshold,
            warning_at_usd: Math.round(limit_usd * threshold * 100) / 100,
            set_at,
            message: `Budget set: ${agent_id} is limited to $${limit_usd} per ${period}. Warning fires at $${Math.round(limit_usd * threshold * 100) / 100}.`,
            governed: true,
          }, null, 2),
        }],
      };
    },
  );

  // ── get_spend_report ────────────────────────────────────────────────────

  server.tool(
    "get_spend_report",
    "Get LLM spend breakdown by agent, model, and provider. Filter by agent and date range. Returns total cost, call count, and per-model breakdown.",
    {
      agent_id:  z.string().optional().describe("Filter by agent ID (omit for all agents)"),
      from_date: z.string().optional().describe("ISO 8601 start date (e.g. '2026-04-01T00:00:00Z')"),
      to_date:   z.string().optional().describe("ISO 8601 end date (e.g. '2026-04-30T23:59:59Z')"),
    },
    { readOnlyHint: true },
    async ({ agent_id, from_date, to_date }) => {
      const records = loadSpendRecords({ agentId: agent_id, fromDate: from_date, toDate: to_date });

      const total_cost_usd = records.reduce((s, r) => s + r.cost_usd, 0);

      const by_model: Record<string, { calls: number; cost_usd: number }> = {};
      const by_agent: Record<string, { calls: number; cost_usd: number }> = {};

      for (const r of records) {
        const mk = `${r.provider}/${r.model}`;
        by_model[mk] = by_model[mk] ?? { calls: 0, cost_usd: 0 };
        by_model[mk].calls++;
        by_model[mk].cost_usd = Math.round((by_model[mk].cost_usd + r.cost_usd) * 1_000_000) / 1_000_000;

        by_agent[r.agent_id] = by_agent[r.agent_id] ?? { calls: 0, cost_usd: 0 };
        by_agent[r.agent_id].calls++;
        by_agent[r.agent_id].cost_usd = Math.round((by_agent[r.agent_id].cost_usd + r.cost_usd) * 1_000_000) / 1_000_000;
      }

      // Sort by_model by cost descending
      const by_model_sorted = Object.fromEntries(
        Object.entries(by_model).sort((a, b) => b[1].cost_usd - a[1].cost_usd)
      );

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            total_cost_usd: Math.round(total_cost_usd * 1_000_000) / 1_000_000,
            call_count: records.length,
            filters: { agent_id: agent_id || "all", from_date: from_date || "all", to_date: to_date || "all" },
            by_model: by_model_sorted,
            by_agent,
            receipts: records.slice(0, 50).map(r => ({
              receipt_id:        r.receipt_id,
              agent_id:          r.agent_id,
              provider:          r.provider,
              model:             r.model,
              prompt_tokens:     r.prompt_tokens,
              completion_tokens: r.completion_tokens,
              cost_usd:          r.cost_usd,
              task_id:           r.task_id || undefined,
              timestamp:         r.timestamp,
            })),
            governed: true,
          }, null, 2),
        }],
      };
    },
  );
}
