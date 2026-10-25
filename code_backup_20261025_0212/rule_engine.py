"""
rule_engine.py - Policy Rule Evaluation and Action Mapping Engine
HackerRank Orchestrate: Ghost Data Still Exists
"""

import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("rule_engine")


@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # 'DELETE', 'REDACT', 'ANONYMIZE', 'RETAIN'


@dataclass
class EvaluationResult:
    rule_id: str
    system_id: str
    resource_id: str
    is_compliant: bool
    current_state: str
    finding_op: Optional[str] = None
    finding_state: Optional[str] = None
    remediation_op: Optional[str] = None
    remediation_state: Optional[str] = None
    verification_op: Optional[str] = None
    verification_state: Optional[str] = None
    evidence_id: str = ""


DEFAULT_RULES = {
    "rule_01": DeletionRule("rule_01", "USER_PROFILE", "Always", "DELETE"),
    "rule_02": DeletionRule("rule_02", "SECONDARY_IDENTIFIER", "Always", "DELETE"),
    "rule_03": DeletionRule("rule_03", "SEARCH_INDEX_ENTRY", "Always", "DELETE"),
    "rule_04": DeletionRule("rule_04", "CACHE_ENTRY", "Always", "DELETE"),
    "rule_05": DeletionRule("rule_05", "SUPPORT_MESSAGE", "Shared context retained", "REDACT"),
    "rule_06": DeletionRule("rule_06", "SUPPORT_ATTACHMENT", "Subject only", "DELETE"),
    "rule_07": DeletionRule("rule_07", "ANALYTICS_PROFILE", "Attributable to user", "ANONYMIZE"),
    "rule_08": DeletionRule("rule_08", "PRODUCT_TELEMETRY", "Attributable to user", "ANONYMIZE"),
    "rule_09": DeletionRule("rule_09", "USER_EXPORT", "Always", "DELETE"),
    "rule_10": DeletionRule("rule_10", "MARKETING_PROFILE", "Always", "DELETE"),
    "rule_11": DeletionRule("rule_11", "EMAIL_DELIVERY_LOG", "Contains user email", "REDACT"),
    "rule_12": DeletionRule("rule_12", "SECURITY_AUDIT_LOG", "Within retention period", "RETAIN"),
    "rule_13": DeletionRule("rule_13", "LEGAL_HOLD_RECORD", "Active legal hold", "RETAIN"),
    "rule_14": DeletionRule("rule_14", "BACKUP_ARCHIVE", "Restore access blocked", "RETAIN"),
    "rule_15": DeletionRule("rule_15", "ACCOUNT_TOMBSTONE", "Tombstone internal user_id only", "REDACT"),
}


class RuleEngine:
    def __init__(self, repo_root: Union[str, Path] = "."):
        self.repo_root = Path(repo_root)
        self.rules_path = self.repo_root / "dataset" / "deletion_rules.csv"
        self.rules: Dict[str, DeletionRule] = {}
        self.category_to_rule: Dict[str, DeletionRule] = {}
        self.load_rules()

    def load_rules(self) -> None:
        # Fallback to hardcoded DEFAULT_RULES only if deletion_rules.csv is not present (M067)
        if not self.rules_path.exists():
            self.rules = dict(DEFAULT_RULES)
            for r in self.rules.values():
                self.category_to_rule[r.data_category] = r
            return

        with open(self.rules_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                r_id = row.get("rule_id", "").strip()
                cat = row.get("data_category", "").strip()
                cond = row.get("condition", "").strip()
                act = row.get("required_action", "").strip().upper()
                if r_id:
                    rule = DeletionRule(r_id, cat, cond, act)
                    self.rules[r_id] = rule
                    if cat in self.category_to_rule:
                        logger.warning(f"Duplicate data_category '{cat}' found; overwriting {self.category_to_rule[cat].rule_id} with {r_id} (M068)")
                    self.category_to_rule[cat] = rule

    def evaluate_record(
        self,
        rule: Optional[DeletionRule],
        system_id: str,
        resource_id: str,
        evidence_item: Dict[str, Any],
    ) -> EvaluationResult:
        evidence_id = evidence_item.get("evidence_id", "")
        is_active_flow = evidence_item.get("is_active_flow", False)
        is_restore_risk = evidence_item.get("is_restore_risk", False)
        exists = evidence_item.get("exists", True)
        has_exposed_pii = bool(evidence_item.get("has_exposed_pii") or evidence_item.get("has_pii"))
        is_anonymized = evidence_item.get("is_anonymized", False)

        rule_id = rule.rule_id if rule else "rule_01"
        action = rule.required_action if rule else "DELETE"

        # 1. Integration Service / Data Flows
        if is_active_flow or system_id == "integration_service" or "data_flow" in resource_id:
            is_comp = not is_active_flow
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=is_comp,
                current_state="ACTIVE" if is_active_flow else "DISABLED",
                finding_op="REPORT_ACTIVE_DATA_FLOW" if not is_comp else None,
                finding_state="ACTIVE" if not is_comp else None,
                remediation_op="DISABLE_DATA_FLOW" if not is_comp else None,
                remediation_state="DISABLED" if not is_comp else None,
                verification_op="VERIFY_DATA_FLOW_DISABLED",
                verification_state="DISABLED",
                evidence_id=evidence_id,
            )

        # 2. Backup Service / Restore Risk (redundant subsumed condition eliminated, M070)
        if is_restore_risk:
            is_comp = not is_restore_risk
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=is_comp,
                current_state="ACTIVE" if is_restore_risk else "BLOCKED",
                finding_op="REPORT_RESTORE_RISK" if not is_comp else None,
                finding_state="ACTIVE" if not is_comp else None,
                remediation_op="BLOCK_RESTORE" if not is_comp else None,
                remediation_state="BLOCKED" if not is_comp else None,
                verification_op="VERIFY_RESTORE_BLOCKED",
                verification_state="BLOCKED",
                evidence_id=evidence_id,
            )

        # 3. Action DELETE
        if action == "DELETE":
            is_comp = not exists
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=is_comp,
                current_state="PRESENT" if exists else "ABSENT",
                finding_op="REPORT_REMAINING_RECORD" if not is_comp else None,
                finding_state="PRESENT" if not is_comp else None,
                remediation_op="DELETE_RECORD" if not is_comp else None,
                remediation_state="ABSENT" if not is_comp else None,
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
                evidence_id=evidence_id,
            )

        # 4. Action REDACT
        elif action == "REDACT":
            is_comp = not has_exposed_pii
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=is_comp,
                current_state="PRESENT" if has_exposed_pii else "REDACTED",
                finding_op="REPORT_EXPOSED_PII" if not is_comp else None,
                finding_state="PRESENT" if not is_comp else None,
                remediation_op="REDACT_RECORD" if not is_comp else None,
                remediation_state="REDACTED" if not is_comp else None,
                verification_op="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
                evidence_id=evidence_id,
            )

        # 5. Action ANONYMIZE
        elif action == "ANONYMIZE":
            is_comp = is_anonymized and not has_exposed_pii
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=is_comp,
                current_state="PRESENT" if not is_comp else "ANONYMIZED",
                finding_op="REPORT_EXPOSED_PII" if not is_comp else None,
                finding_state="PRESENT" if not is_comp else None,
                remediation_op="ANONYMIZE_RECORD" if not is_comp else None,
                remediation_state="ANONYMIZED" if not is_comp else None,
                verification_op="VERIFY_RECORD_ANONYMIZED",
                verification_state="ANONYMIZED",
                evidence_id=evidence_id,
            )

        # 6. Action RETAIN
        elif action == "RETAIN":
            return EvaluationResult(
                rule_id=rule_id,
                system_id=system_id,
                resource_id=resource_id,
                is_compliant=True,
                current_state="PRESENT",
                verification_op="VERIFY_RECORD_PRESENT",
                verification_state="PRESENT",
                evidence_id=evidence_id,
            )

        return EvaluationResult(
            rule_id=rule_id,
            system_id=system_id,
            resource_id=resource_id,
            is_compliant=(not exists),
            current_state="PRESENT" if exists else "ABSENT",
            finding_op="REPORT_REMAINING_RECORD" if exists else None,
            finding_state="PRESENT" if exists else None,
            remediation_op="DELETE_RECORD" if exists else None,
            remediation_state="ABSENT" if exists else None,
            verification_op="VERIFY_RECORD_ABSENT",
            verification_state="ABSENT",
            evidence_id=evidence_id,
        )

    def evaluate_resource(
        self,
        category: str,
        system_id: str,
        resource_id: str,
        observed_state: str,
        contains_prohibited_pii: bool = False,
        evidence_id: str = "",
        is_active_flow: bool = False,
        is_restore_risk: bool = False,
    ) -> EvaluationResult:
        rule = self.category_to_rule.get(category)
        return self.evaluate_record(
            rule=rule,
            system_id=system_id,
            resource_id=resource_id,
            evidence_item={
                "evidence_id": evidence_id,
                "exists": (observed_state != "ABSENT"),
                "has_pii": contains_prohibited_pii,
                "is_anonymized": (observed_state == "ANONYMIZED"),
                "is_active_flow": is_active_flow,
                "is_restore_risk": is_restore_risk,
            },
        )
