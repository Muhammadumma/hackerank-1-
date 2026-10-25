import sys
import csv
import json
from pathlib import Path

sys.path.insert(0, str(Path("code").resolve()))
from main import AuditOrchestrator

orchestrator = AuditOrchestrator(".")

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_requests = list(csv.DictReader(f))
with open("dataset/sample_output.csv", encoding="utf-8") as f:
    gold_map = {r["case_id"]: r for r in csv.DictReader(f)}

print(f"Total sample cases: {len(sample_requests)}")

discrepancies = []

for case in sample_requests:
    cid = case["case_id"]
    gold = gold_map[cid]
    pred = orchestrator.audit_case(case)
    
    pred_status = pred["deletion_status"]
    gold_status = gold["deletion_status"]
    pred_steps = json.loads(pred["steps_json"])
    gold_steps = json.loads(gold["steps_json"])
    
    status_match = (pred_status == gold_status)
    step_count_match = (len(pred_steps) == len(gold_steps))
    
    gold_tuples = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state"), s.get("evidence_id")) for s in gold_steps]
    pred_tuples = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state"), s.get("evidence_id")) for s in pred_steps]
    
    exact_match = (gold_tuples == pred_tuples) and status_match
    
    diff = {
        "case_id": cid,
        "email": case["email"],
        "status_match": status_match,
        "gold_status": gold_status,
        "pred_status": pred_status,
        "gold_len": len(gold_steps),
        "pred_len": len(pred_steps),
        "exact_match": exact_match,
        "missing_steps": [s for s in gold_tuples if s not in pred_tuples],
        "extra_steps": [s for s in pred_tuples if s not in gold_tuples],
    }
    discrepancies.append(diff)

perfect = sum(1 for d in discrepancies if d["exact_match"])
step_cnt_ok = sum(1 for d in discrepancies if d["gold_len"] == d["pred_len"])
status_ok = sum(1 for d in discrepancies if d["status_match"])

print(f"Status Match: {status_ok}/32 ({status_ok/32*100:.1f}%)")
print(f"Step Count Match: {step_cnt_ok}/32 ({step_cnt_ok/32*100:.1f}%)")
print(f"Exact Step Match: {perfect}/32 ({perfect/32*100:.1f}%)")
print("=" * 80)

for d in discrepancies:
    if not d["exact_match"]:
        print(f"=== {d['case_id']} | Gold: {d['gold_status']} ({d['gold_len']} steps) | Pred: {d['pred_status']} ({d['pred_len']} steps) ===")
        if d["missing_steps"]:
            print("  MISSING in Pred:")
            for s in d["missing_steps"]:
                print(f"    [-] Phase: {s[0]}, Op: {s[1]}, Sys: {s[2]}, Res: {s[3]}, State: {s[4]}, Ev: {s[5]}")
        if d["extra_steps"]:
            print("  EXTRA in Pred:")
            for s in d["extra_steps"]:
                print(f"    [+] Phase: {s[0]}, Op: {s[1]}, Sys: {s[2]}, Res: {s[3]}, State: {s[4]}, Ev: {s[5]}")
        print()
