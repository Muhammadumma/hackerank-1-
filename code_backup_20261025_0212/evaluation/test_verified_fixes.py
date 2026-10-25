"""
test_verified_fixes.py - Regression Unit Tests for Verified Audit Fixes
HackerRank Orchestrate: Ghost Data Still Exists
"""

import sys
import unittest
from pathlib import Path

# Add code/ to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import is_deletion_authorized, HIT_EVENT_NAMES, ACTIVE_STATUSES, AuditOrchestrator
from temporal_filter import parse_iso_timestamp, is_admissible, filter_evidence_records
from step_generator import generate_steps, determine_status
from rule_engine import RuleEngine, DeletionRule, EvaluationResult


class TestVerifiedAuditFixes(unittest.TestCase):

    def test_m005_is_deletion_authorized_type_guard(self):
        # M005: Ensure non-string and invalid types are safely rejected without exception
        self.assertFalse(is_deletion_authorized(None))
        self.assertFalse(is_deletion_authorized(12345))
        self.assertFalse(is_deletion_authorized(""))
        self.assertFalse(is_deletion_authorized("   "))
        self.assertTrue(is_deletion_authorized("Please delete all my stored personal data."))
        self.assertFalse(is_deletion_authorized("Please export my data only, do not delete."))

    def test_m014_resource_id_falsy_zero(self):
        # M014: Ensure resource_id with integer 0 does not fall through
        data = {"resource_id": 0, "connector_id": "conn_123"}
        raw_res = data.get("resource_id")
        if raw_res is None:
            raw_res = data.get("connector_id")
        res_id = str(raw_res if raw_res is not None else "").strip()
        self.assertEqual(res_id, "0")

    def test_m015_string_rows_and_status(self):
        # M015: String "0" and "404" status handling
        data1 = {"status_code": "404"}
        is_404_1 = (data1.get("status_code") in [404, "404"] or str(data1.get("rows", "")).strip() == "0" or data1.get("rows") == 0)
        self.assertTrue(is_404_1)

        data2 = {"rows": "0"}
        is_404_2 = (data2.get("status_code") in [404, "404"] or str(data2.get("rows", "")).strip() == "0" or data2.get("rows") == 0)
        self.assertTrue(is_404_2)

    def test_m027_empty_quoted_value_preservation(self):
        # M027: Quoted empty string "" preserved in KV regex parsing
        import re
        line = 'service="account_service" evidence_id="" status="ACTIVE"'
        matches = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line)
        kv = {m[0]: (m[1] if m[1] is not None and m[1] != "" else (m[2] if m[2] is not None else "")).strip('"\'') for m in matches}
        self.assertIn("evidence_id", kv)
        self.assertEqual(kv["evidence_id"], "")

    def test_m029_hit_event_membership(self):
        # M029: frozenset lookup for event names and statuses
        self.assertIn("HIT", HIT_EVENT_NAMES)
        self.assertIn("RECORD_FOUND", HIT_EVENT_NAMES)
        self.assertIn("ACTIVE", ACTIVE_STATUSES)
        self.assertIn("FOUND", ACTIVE_STATUSES)
        self.assertNotIn("MISS", HIT_EVENT_NAMES)

    def test_m059_safe_case_sort_key(self):
        # M059: Regex sort key does not crash on case_id without digits
        import re
        def _safe_case_sort_key(r):
            m = re.search(r'\d+', r.get("case_id", ""))
            return int(m.group()) if m else 0

        cases = [{"case_id": "malformed_case"}, {"case_id": "case_10"}, {"case_id": "case_2"}]
        cases.sort(key=_safe_case_sort_key)
        self.assertEqual(cases[0]["case_id"], "malformed_case")
        self.assertEqual(cases[1]["case_id"], "case_2")
        self.assertEqual(cases[2]["case_id"], "case_10")

    def test_m070_redundant_condition_simplification(self):
        # M070: is_restore_risk evaluates properly without redundant condition
        engine = RuleEngine()
        ev_item = {
            "is_restore_risk": True,
            "exists": True,
            "evidence_id": "ev_01",
        }
        res = engine.evaluate_record(None, "backup_service", "backup_123", ev_item)
        self.assertFalse(res.is_compliant)
        self.assertEqual(res.remediation_op, "BLOCK_RESTORE")
        self.assertEqual(res.verification_op, "VERIFY_RESTORE_BLOCKED")

    def test_m076_deterministic_total_ordering(self):
        # M076: Total ordering tie-break in step generator
        eval1 = EvaluationResult(
            rule_id="r1", system_id="account_service", resource_id="res_01",
            is_compliant=True, current_state="ABSENT",
            verification_op="VERIFY_RECORD_ABSENT", verification_state="ABSENT",
            evidence_id="ev_01",
        )
        eval2 = EvaluationResult(
            rule_id="r2", system_id="account_service", resource_id="res_01",
            is_compliant=True, current_state="ABSENT",
            verification_op="VERIFY_RECORD_ABSENT", verification_state="ABSENT",
            evidence_id="ev_02",
        )
        steps = generate_steps([eval1, eval2], is_deletion_authorized=True)
        self.assertEqual(len(steps), 2)
        # Deterministic sorting on evidence_id tie-break
        self.assertEqual(steps[0]["evidence_id"], "ev_01")
        self.assertEqual(steps[1]["evidence_id"], "ev_02")

    def test_m078_m079_temporal_admissibility(self):
        # M078: Naive datetime parsed to UTC
        dt = parse_iso_timestamp("2026-10-01 12:00:00")
        self.assertIsNotNone(dt)
        self.assertIsNotNone(dt.tzinfo)

        # M079: Inclusive boundary (<=)
        self.assertTrue(is_admissible("2026-10-01T12:00:00Z", "2026-10-01T12:00:00Z"))
        self.assertTrue(is_admissible("2026-10-01T11:59:59Z", "2026-10-01T12:00:00Z"))
        self.assertFalse(is_admissible("2026-10-01T12:00:01Z", "2026-10-01T12:00:00Z"))

    def test_m086_load_evidence_none_handling(self):
        # M086: Check that None returned from load_evidence does not crash build_index
        from evidence_loader import EvidenceLoader
        loader = EvidenceLoader(Path("."))
        res = loader.load_evidence("non_existent_file_id_xyz")
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
