import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path("code").resolve()))
from main import AuditOrchestrator

def evaluate_sample_cases():
    orchestrator = AuditOrchestrator(Path("."))
    
    with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
        sample_requests = list(csv.DictReader(f))
    with open("dataset/sample_output.csv", encoding="utf-8") as f:
        golden = {r["case_id"]: r for r in csv.DictReader(f)}

    status_matches = 0
    step_count_matches = 0
    total = len(sample_requests)

    print("=" * 70)
    print("SAMPLE EVALUATION RESULTS (Cases 1 - 32 against dataset/sample_output.csv)")
    print("=" * 70)

    for case in sample_requests:
        cid = case["case_id"]
        gold = golden[cid]
        pred = orchestrator.audit_case(case)
        pred_status = pred["deletion_status"]
        gold_status = gold["deletion_status"]
        
        is_match = (pred_status == gold_status)
        if is_match:
            status_matches += 1
            
        pred_steps = json.loads(pred["steps_json"])
        gold_steps = json.loads(gold["steps_json"])
        if len(pred_steps) == len(gold_steps):
            step_count_matches += 1
            
        print(f"{cid}: Predicted={pred_status:<12} | Gold={gold_status:<12} | Match={str(is_match):<5} | Steps Pred={len(pred_steps)} Gold={len(gold_steps)}")

    accuracy = (status_matches / total) * 100
    step_acc = (step_count_matches / total) * 100
    print("=" * 70)
    print(f"Sample Deletion-Status Accuracy: {status_matches}/{total} ({accuracy:.1f}%)")
    print(f"Sample Step-Count Alignment   : {step_count_matches}/{total} ({step_acc:.1f}%)")
    print("=" * 70)
    return status_matches, total, accuracy

if __name__ == "__main__":
    evaluate_sample_cases()
