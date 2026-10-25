"""
Debug: Understand every step mismatch in sample cases.
"""
import csv, json, sys
from pathlib import Path

sys.path.insert(0, str(Path("code").resolve()))
from main import AuditOrchestrator

def debug_mismatches():
    orchestrator = AuditOrchestrator(Path("."))
    
    with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
        sample_requests = list(csv.DictReader(f))
    with open("dataset/sample_output.csv", encoding="utf-8") as f:
        golden = {r["case_id"]: r for r in csv.DictReader(f)}

    for case in sample_requests:
        cid = case["case_id"]
        gold = golden[cid]
        pred = orchestrator.audit_case(case)
        pred_steps = json.loads(pred["steps_json"])
        gold_steps = json.loads(gold["steps_json"])
        
        if len(pred_steps) != len(gold_steps):
            print(f"\n{'='*60}")
            print(f"{cid}: Gold={gold['deletion_status']} ({len(gold_steps)} steps) | Pred={pred['deletion_status']} ({len(pred_steps)} steps)")
            print("GOLD STEPS:")
            for s in gold_steps:
                print(f"  {s['step_no']}. [{s['phase']}] {s['operation']} | {s['system_id']} | {s['resource_id']} | ev={s['evidence_id']}")
            print("PRED STEPS:")
            for s in pred_steps:
                print(f"  {s['step_no']}. [{s['phase']}] {s['operation']} | {s['system_id']} | {s['resource_id']} | ev={s['evidence_id']}")
            
            # Find what's missing
            gold_set = {(s['phase'], s['operation'], s['system_id'], s['resource_id']) for s in gold_steps}
            pred_set = {(s['phase'], s['operation'], s['system_id'], s['resource_id']) for s in pred_steps}
            missing = gold_set - pred_set
            extra = pred_set - gold_set
            if missing:
                print("MISSING from pred:", missing)
            if extra:
                print("EXTRA in pred:", extra)

if __name__ == "__main__":
    debug_mismatches()
