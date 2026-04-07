"""
03-crewai-integration.py

Shows: a CrewAI Agent wrapped with DingDawg governance so every task
the agent executes is pre-checked by the policy engine.

Regulated use case: EMPLOYMENT / HR — an AI agent screening resumes
and scoring candidates. Under Colorado SB 205 and EEOC guidelines,
automated hiring decisions require an audit trail and human review.

Install:
    pip install crewai dingdawg-loop

Run:
    python examples/03-crewai-integration.py

How governance wraps CrewAI:
  1. Before each task executes, govern_action is called with the task
     description and risk context.
  2. If decision == "deny" → task is blocked, GovernanceError raised,
     crew execution halts. Receipt is saved as proof of the block.
  3. If decision == "review" → task runs but a human-review webhook
     fires (cloud tier) or a local receipt flags it for manual QA.
  4. If decision == "allow" → task executes normally. Receipt saved.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

try:
    from crewai import Agent, Task, Crew, Process
except ImportError:
    raise ImportError(
        "CrewAI is not installed.\n"
        "Install it with: pip install crewai"
    )

try:
    from dingdawg_loop import GovernedCrewWrapper, GovernanceError
except ImportError:
    raise ImportError(
        "dingdawg-loop is not installed.\n"
        "Install it with: pip install dingdawg-loop"
    )

import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step 1: Define CrewAI agents as normal
# ---------------------------------------------------------------------------

resume_screener = Agent(
    role="Resume Screener",
    goal="Screen candidate resumes against job requirements objectively",
    backstory=(
        "You are an impartial resume evaluator. You assess candidates purely "
        "on job-relevant qualifications. You do not consider age, gender, "
        "race, or any protected characteristics."
    ),
    verbose=True,
)

hiring_coordinator = Agent(
    role="Hiring Coordinator",
    goal="Compile screening results and prepare shortlist for human review",
    backstory=(
        "You compile objective screening scores into a structured shortlist "
        "report. You never make final hiring decisions — you prepare data "
        "for human reviewers."
    ),
    verbose=True,
)


# ---------------------------------------------------------------------------
# Step 2: Wrap each agent with DingDawg governance
#
# GovernedCrewWrapper intercepts .execute_task() and fires govern_action
# before the LLM call happens. The agent object still works normally.
# ---------------------------------------------------------------------------

governed_screener = GovernedCrewWrapper(
    agent=resume_screener,
    agent_id="@resume-screener-v2",     # governed @handle — full history tracked
    risk_tier="high",                    # hiring decisions are high-stakes
    context={
        "regulation": "CO_SB_205",
        "framework": "EEOC",
        "action_category": "employment_screening",
        "requires_human_review": "true",
    },
)

governed_coordinator = GovernedCrewWrapper(
    agent=hiring_coordinator,
    agent_id="@hiring-coordinator-v1",
    risk_tier="medium",
    context={
        "regulation": "CO_SB_205",
        "action_category": "report_compilation",
    },
)


# ---------------------------------------------------------------------------
# Step 3: Define tasks — governance checks fire when these execute
# ---------------------------------------------------------------------------

screen_task = Task(
    description=(
        "Screen the following candidate resume against the Senior Engineer role.\n\n"
        "Candidate: Jamie Rivera\n"
        "Experience: 7 years Python, 4 years Kubernetes, led 3-person team\n"
        "Education: BS Computer Science, State University 2017\n\n"
        "Job Requirements: 5+ years Python, Kubernetes experience, leadership.\n\n"
        "Output: JSON with fields: qualified (bool), score (0-100), "
        "qualifying_factors (list), disqualifying_factors (list). "
        "Do NOT reference any protected characteristics."
    ),
    agent=governed_screener,          # uses the governed wrapper
    expected_output="JSON screening result with score and qualifying factors",
)

compile_task = Task(
    description=(
        "Take the screening result and compile a one-paragraph human-review brief. "
        "Include: candidate name, score, top 3 qualifying factors, any concerns. "
        "End with: 'Recommend for human review: YES/NO'"
    ),
    agent=governed_coordinator,
    expected_output="Human-review brief paragraph",
    context=[screen_task],
)


# ---------------------------------------------------------------------------
# Step 4: Run the crew — governance fires automatically
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting governed hiring crew...\n")
    print("Governance will pre-check each task before LLM execution.\n")

    crew = Crew(
        agents=[governed_screener, governed_coordinator],
        tasks=[screen_task, compile_task],
        process=Process.sequential,
        verbose=True,
    )

    try:
        result = crew.kickoff()
        print("\n=== Crew Result ===")
        print(result)

        # Retrieve receipts to show auditor
        receipts = governed_screener.get_receipts() + governed_coordinator.get_receipts()
        print(f"\n=== Governance Receipts ({len(receipts)} total) ===")
        for r in receipts:
            print(f"  {r['receipt_id']} | {r['agent_id']} | decision={r['decision']} | score={r['risk_score']}")

    except GovernanceError as e:
        # Task was blocked by governance — this IS compliance working correctly
        print(f"\n[GOVERNANCE BLOCK] Task denied before execution.")
        print(f"Agent      : {e.agent_id}")
        print(f"Receipt ID : {e.receipt_id}")
        print(f"Risk Score : {e.risk_score}")
        print(f"Violations :")
        for v in e.violations:
            print(f"  [{v['severity'].upper()}] {v['policy']}: {v['description']}")
        print(f"\nThe LLM was never called. No biased output was generated.")
        print(f"This receipt is your CO SB 205 compliance artifact.")


"""
Expected governance receipts (one per task):

Receipt 1 — resume_screener task:
{
  "receipt_id": "gov_p2k7n9_c1a4e6b3",
  "timestamp": "2026-04-06T14:30:22.118Z",
  "agent_id": "@resume-screener-v2",
  "action_type": "task_execution",
  "action_description": "Screen candidate resume for Senior Engineer role",
  "target_resource": "hiring_pipeline",
  "risk_tier": "high",
  "decision": "review",        // <-- high-risk employment decision always triggers review
  "risk_score": 30,
  "policy_violations": [
    {
      "policy": "human_in_the_loop",
      "severity": "critical",
      "description": "High-stakes action at high risk requires human approval"
    }
  ],
  "recommended_controls": [
    "Require explicit human approval before execution",
    "Log the approver identity and timestamp"
  ],
  "context": {
    "regulation": "CO_SB_205",
    "framework": "EEOC",
    "action_category": "employment_screening",
    "requires_human_review": "true"
  },
  "governed": true
}

Receipt 2 — hiring_coordinator task:
{
  "receipt_id": "gov_q3l8o0_d2b5f7c4",
  "decision": "allow",
  "risk_score": 10,
  "policy_violations": [],
  "governed": true
}

What regulated buyers see:
  - Every hiring AI decision has a timestamped receipt
  - CO SB 205 requires impact assessments + human oversight — these receipts are the audit artifacts
  - EEOC: if a candidate disputes a screening, you have a tamper-evident log
    showing the AI was governed and human review was required
  - Receipts saved at: ~/.dingdawg/governance/receipts/
  - Cloud tier: IPFS-pinned receipts + certified PDF compliance reports
"""
