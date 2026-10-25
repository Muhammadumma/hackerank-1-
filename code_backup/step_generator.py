"""
step_generator.py - Canonical Step Ordering and Schema Serialization Engine
HackerRank Orchestrate: Ghost Data Still Exists
"""

import json
import logging
from typing import Any, Dict, List

from rule_engine import EvaluationResult

logger = logging.getLogger("step_generator")

PHASE_RANK = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

OPERATION_RANK = {
    # FINDING
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # REMEDIATION
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    # VERIFICATION
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


def determine_status(evaluations: List[EvaluationResult], is_deletion_authorized: bool = True) -> str:
    """
    Determines case deletion_status strictly per contract:
    - NOT_APPLICABLE: Request does not authorize deletion (e.g. data export or opt-out).
    - COMPLETE: Deletion authorized, and all audited resources are compliant.
    - INCOMPLETE: Deletion authorized, but at least one resource is non-compliant.
    """
    if not is_deletion_authorized:
        return "NOT_APPLICABLE"

    if not evaluations:
        return "COMPLETE"

    if any(not ev.is_compliant for ev in evaluations):
        return "INCOMPLETE"

    return "COMPLETE"


def generate_steps(evaluations: List[EvaluationResult], is_deletion_authorized: bool = True) -> List[Dict[str, Any]]:
    """
    Generates canonical steps_json array:
    - NOT_APPLICABLE -> []
    - COMPLETE -> only VERIFICATION steps proving current compliant state, citing evidence_id.
    - INCOMPLETE -> FINDING steps (citing evidence_id),
                    REMEDIATION steps (empty evidence_id=""),
                    VERIFICATION steps (empty evidence_id="").
    """
    status = determine_status(evaluations, is_deletion_authorized)
    if status == "NOT_APPLICABLE":
        return []

    is_complete_case = (status == "COMPLETE")
    raw_steps: List[Dict[str, Any]] = []

    if not is_complete_case:
        for ev in evaluations:
            if not ev.is_compliant:
                # 1. Finding step
                if ev.finding_op and ev.finding_state:
                    raw_steps.append({
                        "phase": "FINDING",
                        "system_id": ev.system_id,
                        "resource_id": ev.resource_id,
                        "operation": ev.finding_op,
                        "state": ev.finding_state,
                        "evidence_id": ev.evidence_id,
                    })
                # 2. Remediation step (must cite empty evidence_id)
                if ev.remediation_op and ev.remediation_state:
                    raw_steps.append({
                        "phase": "REMEDIATION",
                        "system_id": ev.system_id,
                        "resource_id": ev.resource_id,
                        "operation": ev.remediation_op,
                        "state": ev.remediation_state,
                        "evidence_id": "",
                    })

    # 3. Verification steps
    for ev in evaluations:
        if ev.verification_op and ev.verification_state:
            raw_steps.append({
                "phase": "VERIFICATION",
                "system_id": ev.system_id,
                "resource_id": ev.resource_id,
                "operation": ev.verification_op,
                "state": ev.verification_state,
                # COMPLETE cites evidence_id; INCOMPLETE uses empty string ""
                "evidence_id": ev.evidence_id if is_complete_case else "",
            })

    # Sort strictly: phase -> operation rank -> system_id (asc) -> resource_id (asc)
    def sort_key(s: Dict[str, Any]):
        return (
            PHASE_RANK.get(s["phase"], 99),
            OPERATION_RANK.get(s["operation"], 99),
            s["system_id"].lower(),
            s["resource_id"].lower(),
        )

    sorted_steps = sorted(raw_steps, key=sort_key)

    # Assign 1-indexed consecutive step numbers
    final_steps: List[Dict[str, Any]] = []
    for idx, s in enumerate(sorted_steps, start=1):
        final_steps.append({
            "step_no": idx,
            "phase": s["phase"],
            "system_id": s["system_id"],
            "resource_id": s["resource_id"],
            "operation": s["operation"],
            "state": s["state"],
            "evidence_id": s["evidence_id"],
        })

    return final_steps


def serialize_steps_json(steps: List[Dict[str, Any]]) -> str:
    """Serializes steps list to minified JSON string."""
    return json.dumps(steps, separators=(",", ":"))
