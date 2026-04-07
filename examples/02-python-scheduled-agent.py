"""
02-python-scheduled-agent.py

Shows: a Python agent scheduled with dingdawg-loop using @schedule_governed.
Every execution is pre-checked by the governance engine. If policy denies,
the function does not run and a receipt is generated proving the block.

Regulated use case: HEALTHCARE — a nightly agent syncing patient records.
PHI access requires an audit trail per HIPAA §164.312(b).

Install:
    pip install dingdawg-loop

Run:
    python examples/02-python-scheduled-agent.py

No API key required for local mode.
Set DINGDAWG_API_KEY env var for cloud-tier policy + certified receipts.
"""

# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

try:
    from dingdawg_loop import schedule_governed, GovernanceError
except ImportError:
    raise ImportError(
        "dingdawg-loop is not installed.\n"
        "Install it with: pip install dingdawg-loop"
    )

import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Governed scheduled agent — HIPAA PHI sync
# ---------------------------------------------------------------------------

@schedule_governed(
    agent_id="@ehr-sync-agent",      # governed identity — every action is tied to this handle
    cron="0 2 * * *",               # 2 AM nightly
    risk_tier="high",               # PHI access is always high risk
    context={
        "regulation": "HIPAA",
        "data_classification": "PHI",
        "environment": "production",
        "owner": "clinical-data-team",
    },
)
def sync_patient_records():
    """
    Sync updated patient records from EHR to analytics warehouse.

    This function only runs if governance allows it.
    Every invocation — allowed or denied — produces a receipt.
    """
    log.info("PHI sync started — governance cleared")

    # Your real sync logic here:
    # records = ehr_client.fetch_updated(since=last_sync_timestamp())
    # warehouse.upsert(records)
    # update_sync_cursor(records[-1].updated_at)

    return {"synced_records": 142, "duration_ms": 890}


# ---------------------------------------------------------------------------
# Second example: lower-risk scheduled agent (fintech reconciliation)
# ---------------------------------------------------------------------------

@schedule_governed(
    agent_id="@ledger-reconciler",
    cron="*/15 * * * *",            # every 15 minutes
    risk_tier="medium",
    context={
        "regulation": "SOX",
        "data_classification": "financial",
        "environment": "production",
    },
)
def reconcile_ledger():
    """
    Reconcile internal ledger against payment processor statements.
    Medium risk — read-only financial data, no mutations.
    """
    log.info("Ledger reconciliation started")

    # Your reconciliation logic here:
    # discrepancies = ledger.find_discrepancies(window_minutes=15)
    # if discrepancies:
    #     alert_finance_team(discrepancies)

    return {"checked_entries": 58, "discrepancies": 0}


# ---------------------------------------------------------------------------
# Manual invocation demo (for testing without waiting for cron)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Running governed agents manually (bypasses cron schedule)...\n")

    # Call the governed functions directly — governance still fires
    try:
        result = sync_patient_records()
        print(f"EHR sync result: {json.dumps(result, indent=2)}")
    except GovernanceError as e:
        # GovernanceError is raised when decision == "deny"
        print(f"[BLOCKED] EHR sync was denied by governance.")
        print(f"Receipt ID : {e.receipt_id}")
        print(f"Risk Score : {e.risk_score}")
        print(f"Reason     : {e.primary_violation}")
        print(f"\nThis block is proof of compliance — the agent did not run.")

    print()

    try:
        result = reconcile_ledger()
        print(f"Ledger reconciliation result: {json.dumps(result, indent=2)}")
    except GovernanceError as e:
        print(f"[BLOCKED] Ledger reconciliation denied. Receipt: {e.receipt_id}")


"""
Expected output (local mode, no API key):

Running governed agents manually (bypasses cron schedule)...

[GOVERNANCE] @ehr-sync-agent → sync_patient_records
  Action     : function_execution
  Risk Tier  : high
  Decision   : review
  Risk Score : 35
  Receipt ID : gov_m7z2p1_a3f9e8c4
  Saved to   : ~/.dingdawg/governance/receipts/gov_m7z2p1_a3f9e8c4.json

EHR sync result: {
  "synced_records": 142,
  "duration_ms": 890
}

[GOVERNANCE] @ledger-reconciler → reconcile_ledger
  Action     : function_execution
  Risk Tier  : medium
  Decision   : allow
  Risk Score : 10
  Receipt ID : gov_n8q3r2_b5d1f7a0
  Saved to   : ~/.dingdawg/governance/receipts/gov_n8q3r2_b5d1f7a0.json

Ledger reconciliation result: {
  "checked_entries": 58,
  "discrepancies": 0
}

What "review" means for @ehr-sync-agent:
  The governance engine flagged PHI access + high risk tier.
  In local mode, review = the function runs with a warning receipt.
  In cloud mode (with DINGDAWG_API_KEY), review triggers a human-approval
  webhook before the function is permitted to execute.

Receipts for auditors:
  Every run — allowed, reviewed, or denied — is saved as a JSON file.
  Your HIPAA auditor can request these files as access logs.
  Cloud tier pins receipts to IPFS for tamper-evident audit proofs.
"""
